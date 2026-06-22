# dns-witness

**Verifiable, tamper-evident passive DNS — with multi-vantage geo-anomaly detection.**

Live demo: **https://aegis-dns.standalonedefense.com**

dns-witness records DNS observations over time and **signs and hash-chains them**, so the history can be independently verified as un-altered and un-backdated — not merely trusted. It can collect from multiple **vantages** (alternate resolvers / EDNS Client Subnet) so that geofenced and geo-steered answers show up as cross-vantage disagreement.

Built on the tamper-evident evidence methodology from the Aegis project.

## Why

Passive DNS — what domains resolved to, and when — is a core supply-chain and threat-intelligence signal. But almost every passive-DNS source asks you to *trust* that the operator didn't omit, alter, or backdate records. For evidence used in security decisions, "trust me" isn't enough. dns-witness makes the record **verifiable**, and publishes observations (facts), not accusations.

## What it does

- **`collect`** — resolve configured domains (A / AAAA / CNAME / MX / NS / TXT) across one or more vantages; enrich IPs with ASN / operator / country (via Team Cymru); append each observation to a signed, hash-chained log.
- **`verify`** — re-check the whole log: chain intact, in order, every signature valid. Exits nonzero on any tampering.
- **`report`** — render a self-contained, searchable HTML report showing the data and the live chain state (non-US country codes highlighted).
- **`changes`** — show value and **jurisdiction (ASN/country) changes** per record over time; flags when a backend moves country. Exits nonzero when changes are found (cron-friendly).
- **`check-canary`** — monitor a domain whose true value you know out-of-band; drift means *your* collection was tampered, not that the world moved.
- **`ct`** — discover a target's certificates and subdomains from **Certificate Transparency** (crt.sh, with a certSpotter fallback) and record newly-seen names in a signed log. A second signal alongside DNS: a new certificate is new infrastructure / attack surface appearing for a watched target.

## Integrity model

Each observation is appended to an append-only JSONL log:

```
content    = the observation fields (including prev_hash)
canonical  = deterministic JSON of content (sorted keys)
entry_hash = sha256(canonical)
sig        = Ed25519_sign(canonical)
```

Each entry chains to the previous one and is individually signed, so the log cannot be reordered, truncated, or altered without breaking the chain, and entries cannot be forged without the private key. This is the Certificate-Transparency / Sigstore append-only-signed-log idea, applied to your own DNS observations. Anyone with the public key can verify the whole log independently — don't trust it, check it.

## Vantages (geo-anomaly detection)

DNS answers depend on *where and how* you ask — GeoDNS, CDN geo-steering, censorship. Configure multiple **vantages** (an alternate resolver and/or an EDNS Client Subnet to probe from) and the same name resolving differently across vantages becomes visible signal. See `config.example.yaml`.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config.example.yaml config.yaml      # edit domains / vantages
.venv/bin/python dns_witness.py keygen
.venv/bin/python dns_witness.py collect
.venv/bin/python dns_witness.py verify
.venv/bin/python dns_witness.py report --output report.html
.venv/bin/python dns_witness.py changes
```

Schedule `collect` (cron, or the included systemd timer) so history accumulates — change detection needs more than one run to compare.

## Deployment

`deploy.sh`, `deploy-nginx.sh`, and `deploy-timer.sh` install the tool behind nginx with a Let's Encrypt certificate and a daily systemd timer. The signing **private key stays out of the web root**; only the report, the log, and the public key are served. Set `CERTBOT_EMAIL` before running `deploy-nginx.sh`.

## Roadmap

- **OpenTimestamps anchoring** — verification independent of the operator.
- **Distributed observer nodes** that cross-verify each other (the transparency-log *witness* model) — also multi-vantage by construction, so geofencing and log-gaming are caught by the same mechanism.
- **Forensic per-record timeline** view.
- **Merkle-tree log** with signed tree heads (efficient inclusion / consistency proofs).

## A note on provenance

Built with AI assistance — and disclosed deliberately, because a tool whose premise is *"don't trust, verify"* should be transparent about its own origins. The code is open; verify it.

## License

MIT — see [LICENSE](LICENSE).
