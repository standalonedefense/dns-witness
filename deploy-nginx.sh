#!/usr/bin/env bash
# Add an nginx server block for aegis-dns.standalonedefense.com and get a TLS cert.
# Additive: creates a NEW site; does not touch existing sites.
set -euo pipefail

SITE=aegis-dns.standalonedefense.com
CONF=/etc/nginx/sites-available/$SITE

echo "== writing nginx site =="
sudo tee "$CONF" >/dev/null <<'NGINX'
server {
    listen 80;
    listen [::]:80;
    server_name aegis-dns.standalonedefense.com;

    root /var/www/aegis-dns;
    index index.html;

    # the verifiable log and public key, served with explicit types
    location = /observations.jsonl { default_type application/x-ndjson; }
    location = /public_key.pem     { default_type application/x-pem-file; }

    location / { try_files $uri $uri/ =404; }
}
NGINX

sudo ln -sf "$CONF" /etc/nginx/sites-enabled/$SITE

echo "== nginx config test =="
sudo nginx -t

echo "== reload nginx =="
sudo systemctl reload nginx

echo "== HTTP check (via Host header, local) =="
curl -s -I -H "Host: $SITE" http://127.0.0.1/ | head -5

echo "== obtain TLS cert (Let's Encrypt, HTTP-01) =="
: "${CERTBOT_EMAIL:?Set CERTBOT_EMAIL first, e.g. CERTBOT_EMAIL=you@example.com bash deploy-nginx.sh}"
sudo certbot --nginx -d "$SITE" --non-interactive --agree-tos -m "$CERTBOT_EMAIL" --redirect

echo "== final nginx config test =="
sudo nginx -t
echo "DONE"
