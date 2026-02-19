FROM alpine:3

RUN apk add --no-cache openssh-server openssh-client curl jq

# Create a non-login user for AuthorizedKeysCommand
RUN adduser -D -s /bin/false sshkeys

# Copy scripts
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY lookup-keys.sh /usr/local/bin/lookup-keys
COPY connect-worker.sh /usr/local/bin/connect-worker
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/lookup-keys /usr/local/bin/connect-worker

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
