#!/usr/bin/env bash
# One-time local setup: generates .env secrets and a self-signed TLS cert for the proxy.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  gen() { openssl rand -hex 32; }
  cat > .env <<ENV
# Shared between huginn-proxy (injects it) and the Abuse Detection API (verifies it).
PROXY_SHARED_SECRET=$(gen)
# Login Web App -> Abuse Detection API bearer token.
ABUSE_API_TOKEN=$(gen)
# Signs Login Web App session cookies.
SESSION_SECRET=$(gen)
ENV
  chmod 600 .env
  echo "wrote .env"
else
  echo ".env exists, leaving it alone"
fi

mkdir -p proxy/certs
if [[ ! -f proxy/certs/server.crt ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout proxy/certs/server.key -out proxy/certs/server.crt -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1" 2>/dev/null
  # The proxy runs as uid 10001; the key is a throwaway dev cert.
  chmod 644 proxy/certs/server.crt proxy/certs/server.key
  echo "wrote proxy/certs/server.{crt,key}"
else
  echo "proxy/certs exists, leaving it alone"
fi
