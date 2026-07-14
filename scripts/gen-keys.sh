#!/usr/bin/env bash
set -euo pipefail
# Offline key generation using wireguardctl if available, else openssl-style note.
if command -v wireguardctl >/dev/null 2>&1; then
  wireguardctl keys gen
else
  echo "Build and run: wireguardctl keys gen" >&2
  exit 1
fi
