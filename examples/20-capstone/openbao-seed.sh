#!/bin/sh
# Seed OpenBao with HMAC configuration for the inventory demo.
# Runs as a one-shot container after OpenBao starts.
#
# Two HMAC configs are stored — one per output that uses HMAC:
#   secret/audit/hmac-v1 — compliance_archive (SHA-256)
#   secret/audit/hmac-v2 — security_feed (SHA-512, different salt)
#
# Each secret contains: enabled, version, salt, hash.
# The outputs.yaml resolves these via ref+openbao:// URIs at startup.
set -e

export BAO_ADDR="${BAO_ADDR:-https://openbao:8200}"
export BAO_TOKEN="${BAO_TOKEN:-demo-root-token}"

# Wait for OpenBao to be ready.
echo "Waiting for OpenBao at $BAO_ADDR..."
until bao status >/dev/null 2>&1; do sleep 0.5; done
echo "OpenBao is ready."

# Generate random salts (32 bytes, base64 encoded).
SALT_V1=$(head -c 32 /dev/urandom | base64)
SALT_V2=$(head -c 32 /dev/urandom | base64)

# HMAC v1 — used by compliance_archive output (CEF + SHA-256).
bao kv put secret/audit/hmac-v1 \
  enabled=true \
  version=v1 \
  salt="$SALT_V1" \
  hash=HMAC-SHA-256

echo "Seeded: secret/audit/hmac-v1 (SHA-256)"

# HMAC v2 — used by security_feed output (JSON + SHA-512).
# Different salt proves per-output HMAC isolation.
bao kv put secret/audit/hmac-v2 \
  enabled=true \
  version=v2 \
  salt="$SALT_V2" \
  hash=HMAC-SHA-512

echo "Seeded: secret/audit/hmac-v2 (SHA-512)"
echo "OpenBao seeding complete."
