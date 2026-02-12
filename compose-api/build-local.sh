#!/bin/bash
# Force fresh build: CACHEBUST invalidates cache so COPY src gets current source
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
docker build --no-cache --build-arg CACHEBUST=$(date +%s) -t openclaw-compose-api:local .
