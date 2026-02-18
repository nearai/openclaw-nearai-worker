#!/bin/sh
set -e

# Validate required env vars
for var in OPENCLAW_DOMAIN CERTBOT_EMAIL CLOUDFLARE_API_TOKEN; do
  eval val=\$$var
  if [ -z "$val" ]; then
    echo "ERROR: $var is required but not set" >&2
    exit 1
  fi
done

# Write Cloudflare credentials
mkdir -p /etc/certbot
cat > /etc/certbot/cloudflare.ini <<EOF
dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}
EOF
chmod 600 /etc/certbot/cloudflare.ini

# Obtain wildcard certificate (skips if already exists)
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/certbot/cloudflare.ini \
  --cert-name "${OPENCLAW_DOMAIN}" \
  -d "*.${OPENCLAW_DOMAIN}" \
  --email "${CERTBOT_EMAIL}" \
  --agree-tos \
  --non-interactive \
  --keep-until-expiring

# Background renewal loop
(
  while true; do
    sleep 12h
    certbot renew --deploy-hook "nginx -s reload"
  done
) &

# Start nginx in foreground
exec nginx -g "daemon off;"
