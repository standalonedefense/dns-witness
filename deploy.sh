#!/usr/bin/env bash
# Deploy dns-witness app on the VPS. Reads staged files from /tmp.
set -euo pipefail

APP=/opt/dns-witness
WEB=/var/www/aegis-dns
USER_OWN="$(whoami)"

echo "== creating directories =="
sudo mkdir -p "$APP" "$WEB"
sudo cp /tmp/dns_witness.py /tmp/requirements.txt /tmp/README.md "$APP/"
sudo cp /tmp/config.vps.yaml "$APP/config.yaml"
sudo chown -R "$USER_OWN":"$USER_OWN" "$APP" "$WEB"

echo "== python venv + deps =="
cd "$APP"
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

echo "== generate key, collect, report, verify =="
.venv/bin/python dns_witness.py keygen --force
.venv/bin/python dns_witness.py collect
.venv/bin/python dns_witness.py report --output "$WEB/index.html"
.venv/bin/python dns_witness.py verify

echo "== lock down permissions =="
chmod 600 "$APP/private_key.pem"
chmod 644 "$WEB/index.html" "$WEB/observations.jsonl" "$WEB/public_key.pem"

echo "== web root contents =="
ls -la "$WEB"
