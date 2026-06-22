#!/usr/bin/env bash
# Install OpenTimestamps on the VPS, wire anchor + anchor-report into the timer,
# and create the first anchor + history page (without a full re-collect).
set -euo pipefail
APP=/opt/dns-witness
WEB=/var/www/aegis-dns
export PATH="$APP/.venv/bin:$PATH"

cp /tmp/dns_witness.py "$APP/"

echo "== install opentimestamps-client into the venv =="
"$APP/.venv/bin/pip" install -q opentimestamps-client

echo "== update systemd service (PATH + anchor steps) =="
sudo tee /etc/systemd/system/dns-witness.service >/dev/null <<'UNIT'
[Unit]
Description=dns-witness collect + report + anchor
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=bath
WorkingDirectory=/opt/dns-witness
Environment=PATH=/opt/dns-witness/.venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/opt/dns-witness/.venv/bin/python dns_witness.py collect
ExecStart=/opt/dns-witness/.venv/bin/python dns_witness.py report --output /var/www/aegis-dns/index.html
ExecStart=/opt/dns-witness/.venv/bin/python dns_witness.py anchor
ExecStart=/opt/dns-witness/.venv/bin/python dns_witness.py anchor-report --output /var/www/aegis-dns/anchor-history.html
UNIT
sudo systemctl daemon-reload

echo "== anchor the live log now + render history + refresh report =="
cd "$APP"
"$APP/.venv/bin/python" dns_witness.py anchor | tail -2
"$APP/.venv/bin/python" dns_witness.py anchor-report --output "$WEB/anchor-history.html"
"$APP/.venv/bin/python" dns_witness.py report --output "$WEB/index.html"

echo "== make published artifacts world-readable =="
chmod -R a+rX "$WEB/anchors" 2>/dev/null || true
chmod a+r "$WEB/anchors.jsonl" "$WEB/anchor-history.html" "$WEB/index.html" 2>/dev/null || true

echo "== listing =="
ls -la "$WEB/anchor-history.html" "$WEB/anchors.jsonl"
ls "$WEB/anchors" | head
echo DONE
