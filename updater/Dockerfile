FROM alpine:3.21

RUN apk add --no-cache curl jq docker-cli docker-cli-compose bash

# Install cosign static binary
RUN curl -fsSL https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign-linux-amd64 \
    -o /usr/local/bin/cosign && chmod +x /usr/local/bin/cosign

COPY updater/updater.sh /app/updater.sh
RUN chmod +x /app/updater.sh

COPY deploy/docker-compose.dstack.yml /app/compose/docker-compose.dstack.yml

ENTRYPOINT ["/app/updater.sh"]
