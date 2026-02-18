FROM nginx:alpine

RUN apk add --no-cache certbot py3-pip \
    && pip install --no-cache-dir --break-system-packages certbot-dns-cloudflare

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
