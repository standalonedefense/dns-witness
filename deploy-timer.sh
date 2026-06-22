#!/usr/bin/env bash
# Install a systemd timer that runs `collect` + `report` daily.
set -euo pipefail

sudo tee /etc/systemd/system/dns-witness.service >/dev/null <<'UNIT'
[Unit]
Description=dns-witness collect + report
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=bath
WorkingDirectory=/opt/dns-witness
ExecStart=/opt/dns-witness/.venv/bin/python dns_witness.py collect
ExecStart=/opt/dns-witness/.venv/bin/python dns_witness.py report --output /var/www/aegis-dns/index.html
UNIT

sudo tee /etc/systemd/system/dns-witness.timer >/dev/null <<'UNIT'
[Unit]
Description=Run dns-witness daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now dns-witness.timer

echo "== run once now to verify the unit works =="
sudo systemctl start dns-witness.service
echo "== service result =="
systemctl is-active dns-witness.service || true
systemctl --no-pager status dns-witness.service 2>/dev/null | grep -E "Active:|status=" | head -3 || true
echo "== next scheduled run =="
systemctl --no-pager list-timers dns-witness.timer | head -3
echo "== observation count after one extra run =="
wc -l /var/www/aegis-dns/observations.jsonl
echo "DONE"
