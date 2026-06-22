#!/usr/bin/env python3
"""
dns-witness  --  verifiable, tamper-evident passive DNS (v1, single node).

Subcommands:
  keygen        generate an Ed25519 signing keypair
  collect       resolve configured domains and append signed observations
  verify        verify the observation log's hash chain and signatures
  check-canary  warn if a canary domain's latest observation drifted from expected

Integrity model
---------------
Every observation is appended to an append-only JSONL log. Entries are
hash-chained and signed:

    content      = the observation fields (incl. prev_hash)
    canonical    = deterministic JSON of content (sorted keys, no whitespace)
    entry_hash   = sha256(canonical)
    sig          = Ed25519_sign(canonical)

Because each entry's content includes the previous entry's hash, the log cannot
be reordered, truncated from the middle, or altered without breaking the chain;
and because each entry is signed, entries cannot be forged without the private
key. Anyone holding the public key can verify the whole log independently.

This is the Certificate-Transparency / Sigstore "append-only signed log" idea,
applied to your own passive-DNS observations. v1 is a single node; a network of
nodes that cross-verify each other is the roadmap (see README).
"""

import argparse
import base64
import hashlib
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import dns.edns
import dns.resolver
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# The exact set of fields that make up an entry's signed/hashed content.
# Build and verify MUST agree on this set. (Order doesn't matter: the canonical
# form sorts keys.)
CONTENT_FIELDS = [
    "seq",
    "observed_at",
    "domain",
    "record_type",
    "value",
    "asn",
    "as_org",
    "country",
    "source",
    "is_canary",
    "vantage",
    "prev_hash",
]

GENESIS = "genesis"  # prev_hash of the very first entry


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def canonical_json(content: dict) -> str:
    """Deterministic JSON so the hash/signature are reproducible."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _resolver(resolver_ip: str = None, ecs: str = None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = 5.0
    r.lifetime = 5.0
    if resolver_ip:
        r.nameservers = [resolver_ip]
    if ecs:
        # EDNS Client Subnet: ask "what would a client in <subnet> be told?"
        addr, _, prefix = ecs.partition("/")
        r.use_edns(0, 0, 1232, options=[dns.edns.ECSOption(addr, int(prefix or 24))])
    return r


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #
def cmd_keygen(cfg: dict, args) -> int:
    priv_path = Path(cfg["private_key_path"])
    pub_path = Path(cfg["public_key_path"])
    priv_path.parent.mkdir(parents=True, exist_ok=True)

    if priv_path.exists() and not args.force:
        print(f"refusing to overwrite existing key at {priv_path} (use --force)")
        return 1

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),  # v1: unencrypted. keep this file safe.
        )
    )
    pub_path.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"wrote private key -> {priv_path}  (KEEP SECRET, it is gitignored)")
    print(f"wrote public  key -> {pub_path}  (publish this)")
    return 0


def load_private_key(cfg: dict) -> ed25519.Ed25519PrivateKey:
    data = Path(cfg["private_key_path"]).read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(cfg: dict) -> ed25519.Ed25519PublicKey:
    data = Path(cfg["public_key_path"]).read_bytes()
    return serialization.load_pem_public_key(data)


# --------------------------------------------------------------------------- #
# DNS + ASN/geo enrichment
# --------------------------------------------------------------------------- #
def resolve(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> list[str]:
    """Return the textual values for one (domain, record_type), or [] on miss."""
    try:
        answer = resolver.resolve(domain, rtype)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    except Exception:
        return []
    out = []
    for rdata in answer:
        out.append(rdata.to_text().strip('"'))
    return out


def asn_lookup(ip: str) -> tuple:
    """
    Map an IPv4 address to (asn, as_org, country) using Team Cymru's public
    IP-to-ASN service over DNS. No API key, no database -- a DNS tool using DNS.
    IPv6 enrichment is deferred to a later version.
    """
    if ":" in ip:  # IPv6 -- deferred in v1
        return (None, None, None)
    try:
        rev = ".".join(reversed(ip.split(".")))
        r = _resolver()
        origin = r.resolve(f"{rev}.origin.asn.cymru.com", "TXT")[0].to_text().strip('"')
        # "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
        parts = [p.strip() for p in origin.split("|")]
        asn = int(parts[0].split()[0])          # first ASN if several
        country = parts[2] or None
        name = r.resolve(f"AS{asn}.asn.cymru.com", "TXT")[0].to_text().strip('"')
        # "15169 | US | arin | 2000-03-30 | GOOGLE, US"
        as_org = [p.strip() for p in name.split("|")][-1] or None
        return (asn, as_org, country)
    except Exception:
        return (None, None, None)


# --------------------------------------------------------------------------- #
# the signed, hash-chained log
# --------------------------------------------------------------------------- #
def log_tail(log_path: Path) -> tuple:
    """Return (prev_hash, next_seq) for appending; (GENESIS, 0) if empty."""
    if not log_path.exists():
        return (GENESIS, 0)
    prev_hash, next_seq = GENESIS, 0
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            prev_hash = entry["entry_hash"]
            next_seq = entry["seq"] + 1
    return (prev_hash, next_seq)


def make_signed_entry(content: dict, priv: ed25519.Ed25519PrivateKey) -> dict:
    canonical = canonical_json(content)
    entry = dict(content)
    entry["entry_hash"] = sha256_hex(canonical)
    entry["sig"] = base64.b64encode(priv.sign(canonical.encode("utf-8"))).decode()
    return entry


def cmd_collect(cfg: dict, args) -> int:
    priv = load_private_key(cfg)
    log_path = Path(cfg["log_path"])
    log_path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash, seq = log_tail(log_path)
    observed_at = utcnow_iso()
    record_types = cfg.get("record_types", ["A", "AAAA", "CNAME", "MX", "NS", "TXT"])
    # Each vantage is a viewpoint: an optional alternate resolver and/or an EDNS
    # Client Subnet to probe from. No vantages configured == one default view.
    vantages = cfg.get("vantages") or [{"name": "default"}]

    written = 0
    with open(log_path, "a", encoding="utf-8") as fh:
        for v in vantages:
            vname = v["name"]
            resolver = _resolver(v.get("resolver"), v.get("ecs"))
            for d in cfg["domains"]:
                domain = d["name"]
                is_canary = bool(d.get("canary", False))
                for rtype in record_types:
                    for value in resolve(resolver, domain, rtype):
                        asn = as_org = country = None
                        if rtype in ("A", "AAAA"):
                            asn, as_org, country = asn_lookup(value)
                        content = {
                            "seq": seq,
                            "observed_at": observed_at,
                            "domain": domain,
                            "record_type": rtype,
                            "value": value,
                            "asn": asn,
                            "as_org": as_org,
                            "country": country,
                            "source": "self-collected",
                            "is_canary": is_canary,
                            "vantage": vname,
                            "prev_hash": prev_hash,
                        }
                        entry = make_signed_entry(content, priv)
                        fh.write(json.dumps(entry) + "\n")
                        prev_hash = entry["entry_hash"]
                        seq += 1
                        written += 1

    print(f"appended {written} observations to {log_path} (now {seq} total)")
    return 0


def read_log(log_path: Path):
    """Yield entries from the JSONL log, in order."""
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def verify_entries(pub, log_path: Path) -> list:
    """
    Re-check the whole log. Returns [{"entry": <entry>, "issues": [str]}, ...].
    Empty issues == that entry is intact, in order, and authentically signed.
    Shared by `verify` and `report` so the two can never disagree.
    """
    results, prev_hash, expected_seq = [], GENESIS, 0
    for entry in read_log(log_path):
        issues = []
        # Sign/verify over every field except the signature envelope itself, so the
        # log can hold different record shapes (DNS, CT, ...) and still verify
        # uniformly. Backward compatible with the fixed-schema DNS entries.
        content = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
        canonical = canonical_json(content)
        if entry["seq"] != expected_seq:
            issues.append("seq out of order")
        if entry["prev_hash"] != prev_hash:
            issues.append("chain break")
        if sha256_hex(canonical) != entry["entry_hash"]:
            issues.append("hash mismatch")
        try:
            pub.verify(base64.b64decode(entry["sig"]), canonical.encode("utf-8"))
        except InvalidSignature:
            issues.append("bad signature")
        results.append({"entry": entry, "issues": issues})
        prev_hash = entry["entry_hash"]
        expected_seq += 1
    return results


def cmd_verify(cfg: dict, args) -> int:
    log_path = Path(getattr(args, "log", None) or cfg["log_path"])
    if not log_path.exists():
        print(f"no log at {log_path}")
        return 1
    pub = load_public_key(cfg)
    results = verify_entries(pub, log_path)
    problems = [(r["entry"]["seq"], i) for r in results for i in r["issues"]]
    if problems:
        print(f"FAILED: {len(problems)} problem(s) across {len(results)} entries:")
        for seq, issue in problems[:50]:
            print(f"  - seq {seq}: {issue}")
        return 1
    print(f"OK: {len(results)} entries verified -- chain intact, all signatures valid")
    return 0


def _render_html(results: list, pub) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    fp = hashlib.sha256(raw).hexdigest()[:16]
    n = len(results)
    n_bad = sum(1 for r in results if r["issues"])
    chain_ok = n_bad == 0
    status_txt = (
        "VALID — chain intact, all signatures authentic"
        if chain_ok
        else f"{n_bad} PROBLEM(S) — evidence may be altered"
    )
    status_cls = "ok" if chain_ok else "bad"

    rows = []
    for r in results:
        e = r["entry"]
        ok = not r["issues"]
        cc = e.get("country") or ""
        row_cls = "ok" if ok else "bad"
        foreign = " foreign" if cc and cc != "US" else ""
        canary = "★" if e.get("is_canary") else ""
        chain_cell = "✓" if ok else "✗ " + html.escape(", ".join(r["issues"]))
        cells = [
            str(e["seq"]),
            html.escape(e["observed_at"]),
            html.escape(e["domain"]),
            html.escape(e["record_type"]),
            html.escape(str(e["value"])),
            html.escape(str(e["asn"]) if e["asn"] is not None else ""),
            html.escape(e.get("as_org") or ""),
            html.escape(cc),
            canary,
            html.escape(e.get("vantage") or ""),
        ]
        tds = "".join(f"<td>{c}</td>" for c in cells)
        tds += f'<td class="chain {row_cls}">{chain_cell}</td>'
        rows.append(f'<tr class="{row_cls}{foreign}">{tds}</tr>')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dns-witness report</title>
<style>
 body{{font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:1.5rem;color:#1b1f23;background:#fff}}
 h1{{font-size:1.25rem;margin:0 0 .25rem}}
 .sub{{color:#666;margin:0 0 1rem;max-width:60rem}}
 .summary{{display:flex;flex-wrap:wrap;gap:.5rem 1.5rem;padding:.75rem 1rem;border:1px solid #ddd;border-radius:8px;margin-bottom:1rem}}
 .status{{font-weight:600}} .status.ok{{color:#137333}} .status.bad{{color:#b00020}}
 .mono{{font-family:ui-monospace,Consolas,monospace}}
 input#q{{width:100%;padding:.5rem .6rem;border:1px solid #ccc;border-radius:6px;margin-bottom:.75rem;font-size:14px;box-sizing:border-box}}
 table{{border-collapse:collapse;width:100%;font-size:13px}}
 th,td{{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #eee;vertical-align:top}}
 th{{position:sticky;top:0;background:#fafafa;border-bottom:1px solid #ccc}}
 td:nth-child(5){{font-family:ui-monospace,Consolas,monospace;word-break:break-all}}
 tr.bad{{background:#fff5f5}}
 tr.foreign td:nth-child(8){{font-weight:700;color:#b06000}}
 td.chain.ok{{color:#137333}} td.chain.bad{{color:#b00020;font-weight:600}}
 .hint{{color:#888;font-size:12px;margin-top:.75rem;max-width:60rem}}
</style></head><body>
<h1>dns-witness — verifiable passive DNS</h1>
<p class="sub">Tamper-evident DNS observations. Each row is signed and hash-chained; the chain state below was re-verified when this page was generated.</p>
<div class="summary">
 <div>Generated: <span class="mono">{utcnow_iso()}</span></div>
 <div>Observations: <b>{n}</b></div>
 <div class="status {status_cls}">Evidence chain: {status_txt}</div>
 <div>Signing key: <span class="mono">{fp}</span></div>
 <div>Anchoring: <span class="mono">none (v1)</span></div>
</div>
<input id="q" placeholder="search — domain, value, ASN, operator, country…" autofocus>
<table id="t">
<thead><tr><th>#</th><th>observed (UTC)</th><th>domain</th><th>type</th><th>value</th><th>ASN</th><th>operator</th><th>cc</th><th>canary</th><th>vantage</th><th>chain</th></tr></thead>
<tbody>
{chr(10).join(rows)}
</tbody></table>
<p class="hint">Non-US country codes are highlighted; ★ marks canary domains; rows failing verification are shaded. Don't trust this page — verify independently: <span class="mono">python3 dns_witness.py verify</span></p>
<script>
 const q=document.getElementById('q'), rows=[...document.querySelectorAll('#t tbody tr')];
 q.addEventListener('input',()=>{{const v=q.value.toLowerCase();for(const r of rows)r.style.display=r.textContent.toLowerCase().includes(v)?'':'none';}});
</script>
</body></html>"""


def cmd_report(cfg: dict, args) -> int:
    log_path = Path(cfg["log_path"])
    if not log_path.exists():
        print(f"no log at {log_path}")
        return 1
    pub = load_public_key(cfg)
    results = verify_entries(pub, log_path)
    out = Path(args.output)
    out.write_text(_render_html(results, pub), encoding="utf-8")
    n_bad = sum(1 for r in results if r["issues"])
    print(f"wrote {out}  ({len(results)} observations, {n_bad} with issues)")
    return 0


def cmd_check_canary(cfg: dict, args) -> int:
    """Compare each canary's most-recent observed values against `expected`."""
    log_path = Path(cfg["log_path"])
    canaries = {d["name"]: d.get("expected", {}) for d in cfg["domains"] if d.get("canary")}
    if not canaries:
        print("no canaries configured")
        return 0
    if not log_path.exists():
        print(f"no log at {log_path}")
        return 1

    # latest observed values per (canary domain, record_type)
    latest: dict = {}
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            if e["domain"] in canaries:
                latest.setdefault((e["domain"], e["record_type"]), set()).add(e["value"])

    drift = False
    for domain, expected in canaries.items():
        for rtype, exp_values in expected.items():
            seen = latest.get((domain, rtype), set())
            unexpected = seen - set(exp_values)
            missing = set(exp_values) - seen
            if unexpected or missing:
                drift = True
                print(f"CANARY DRIFT {domain} {rtype}:")
                if unexpected:
                    print(f"    unexpected: {sorted(unexpected)}")
                if missing:
                    print(f"    missing:    {sorted(missing)}")
    if not drift:
        print("canaries OK -- all observed values match expected")
        return 0
    print("\n^ drift usually means YOUR collection was tampered/poisoned. Investigate.")
    return 1


def detect_changes(log_path: Path) -> list:
    """
    Group observations by (domain, record_type, vantage) and walk collection runs
    in time order, emitting an event whenever the value set changes or a surviving
    value's ASN/country (jurisdiction) shifts between runs. Grouping by vantage
    keeps legitimate geo-variation from looking like a change. Reads the raw log;
    the forensic/temporal lens over the same data `verify` checks for integrity.
    """
    from collections import defaultdict

    timeline = defaultdict(dict)  # (domain, rtype, vantage) -> {observed_at: {value: (asn, country)}}
    for e in read_log(log_path):
        key = (e["domain"], e["record_type"], e.get("vantage", "default"))
        timeline[key].setdefault(e["observed_at"], {})[e["value"]] = (e.get("asn"), e.get("country"))

    changes = []
    for key, runs in sorted(timeline.items()):
        prev_ts = prev = None
        for ts in sorted(runs):
            cur = runs[ts]
            if prev is not None:
                added = sorted(set(cur) - set(prev))
                removed = sorted(set(prev) - set(cur))
                shifts = [
                    {"value": v, "from": prev[v], "to": cur[v]}
                    for v in sorted(set(cur) & set(prev))
                    if cur[v] != prev[v]
                ]
                if added or removed or shifts:
                    changes.append({
                        "domain": key[0],
                        "record_type": key[1],
                        "vantage": key[2],
                        "from_time": prev_ts,
                        "to_time": ts,
                        "added": [{"value": v, "asn": cur[v][0], "country": cur[v][1]} for v in added],
                        "removed": removed,
                        "shifts": shifts,
                    })
            prev_ts, prev = ts, cur
    return changes


def cmd_changes(cfg: dict, args) -> int:
    log_path = Path(cfg["log_path"])
    if not log_path.exists():
        print(f"no log at {log_path}")
        return 1
    n_runs = len({e["observed_at"] for e in read_log(log_path)})
    changes = detect_changes(log_path)
    if not changes:
        print(f"no changes detected across {n_runs} collection run(s)")
        return 0
    for c in changes:
        print(f"\n{c['domain']}  {c['record_type']}  [{c['vantage']}]   {c['from_time']} -> {c['to_time']}")
        for a in c["added"]:
            print(f"  + {a['value']}  (AS{a['asn']} {a['country'] or '?'})")
        for v in c["removed"]:
            print(f"  - {v}")
        for s in c["shifts"]:
            f_asn, f_cc = s["from"]
            t_asn, t_cc = s["to"]
            flag = "   <== JURISDICTION CHANGE" if f_cc != t_cc else ""
            print(f"  ~ {s['value']}  AS{f_asn} {f_cc} -> AS{t_asn} {t_cc}{flag}")
    print(f"\n{len(changes)} change event(s) across {n_runs} runs")
    return 1  # nonzero so `changes || alert` works in cron/monitoring


def _crtsh_certs(domain: str) -> list:
    """Certs for <domain> + subdomains from crt.sh, normalized."""
    import urllib.request
    import urllib.parse

    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + domain, "output": "json"})
    req = urllib.request.Request(url, headers={"User-Agent": "dns-witness-ct/1.0"})
    err = None
    for _ in (1, 2):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            out = []
            for c in data:
                names = set((c.get("name_value") or "").split("\n"))
                names.add(c.get("common_name") or "")
                out.append({
                    "names": names,
                    "issuer": c.get("issuer_name") or "",
                    "not_before": c.get("not_before") or "",
                    "cert_id": c.get("id"),
                })
            return out
        except Exception as e:
            err = e
    print(f"  crt.sh unavailable for {domain}: {err}")
    return []


def _certspotter_certs(domain: str) -> list:
    """Certs for <domain> + subdomains from SSLMate certSpotter (crt.sh fallback)."""
    import urllib.request
    import urllib.parse

    url = "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode({
        "domain": domain,
        "include_subdomains": "true",
    }) + "&expand=dns_names&expand=issuer"
    req = urllib.request.Request(url, headers={"User-Agent": "dns-witness-ct/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        out = []
        for c in data:
            iss = c.get("issuer")
            issuer = iss.get("name", "") if isinstance(iss, dict) else (iss or "")
            out.append({
                "names": set(c.get("dns_names") or []),
                "issuer": issuer,
                "not_before": c.get("not_before") or "",
                "cert_id": c.get("id"),
            })
        return out
    except Exception as e:
        print(f"  certSpotter unavailable for {domain}: {e}")
        return []


def _ct_certs(domain: str) -> list:
    """CT records for a domain, trying crt.sh then certSpotter."""
    certs = _crtsh_certs(domain)
    return certs if certs else _certspotter_certs(domain)


def cmd_ct(cfg: dict, args) -> int:
    """
    Certificate Transparency discovery collector. For each target domain, pull
    issued certificates from CT (via crt.sh) and record any newly-seen (sub)domain
    in a signed, tamper-evident log -- a second signal alongside DNS. A new cert is
    new infrastructure / attack surface appearing for a watched target.
    """
    priv = load_private_key(cfg)
    ct_log = Path(cfg.get("ct_log_path", "data/ct_observations.jsonl"))
    ct_log.parent.mkdir(parents=True, exist_ok=True)

    seen = set()
    if ct_log.exists():
        for e in read_log(ct_log):
            seen.add((e.get("target"), e.get("name")))

    prev_hash, seq = log_tail(ct_log)
    observed_at = utcnow_iso()
    total_new = 0
    with open(ct_log, "a", encoding="utf-8") as fh:
        for d in cfg["domains"]:
            domain = d["name"]
            new_here = 0
            for c in _ct_certs(domain):
                issuer = c["issuer"]
                not_before = c["not_before"]
                cert_id = c["cert_id"]
                names = set()
                for n in c["names"]:
                    n = (n or "").strip().lower().lstrip("*.")
                    if n and (n == domain or n.endswith("." + domain)):
                        names.add(n)
                for name in sorted(names):
                    if (domain, name) in seen:
                        continue
                    seen.add((domain, name))
                    content = {
                        "seq": seq,
                        "observed_at": observed_at,
                        "source": "ct",
                        "target": domain,
                        "name": name,
                        "issuer": issuer,
                        "not_before": not_before,
                        "cert_id": cert_id,
                        "prev_hash": prev_hash,
                    }
                    entry = make_signed_entry(content, priv)
                    fh.write(json.dumps(entry) + "\n")
                    prev_hash = entry["entry_hash"]
                    seq += 1
                    new_here += 1
                    total_new += 1
            print(f"{domain}: {new_here} new name(s) via CT")
    print(f"appended {total_new} CT observations to {ct_log} (now {seq} total)")
    return 0


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(description="dns-witness: verifiable passive DNS (v1)")
    p.add_argument("--config", default="config.yaml", help="path to config (default: config.yaml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    sp.add_argument("--force", action="store_true", help="overwrite an existing key")
    sub.add_parser("collect", help="resolve configured domains and append signed observations")
    vp = sub.add_parser("verify", help="verify a log's chain and signatures")
    vp.add_argument("--log", help="verify a specific log file (default: log_path from config)")
    sub.add_parser("ct", help="discover a target's certs/subdomains from Certificate Transparency")
    sub.add_parser("check-canary", help="warn if a canary drifted from expected")
    rp = sub.add_parser("report", help="render a searchable HTML report of the log + chain state")
    rp.add_argument("--output", default="report.html", help="output HTML path (default: report.html)")
    sub.add_parser("changes", help="show value/jurisdiction changes per record over time (monitoring)")

    args = p.parse_args()
    cfg = load_config(args.config)

    return {
        "keygen": cmd_keygen,
        "collect": cmd_collect,
        "verify": cmd_verify,
        "check-canary": cmd_check_canary,
        "report": cmd_report,
        "changes": cmd_changes,
        "ct": cmd_ct,
    }[args.cmd](cfg, args)


if __name__ == "__main__":
    sys.exit(main())
