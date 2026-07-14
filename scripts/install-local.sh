#!/usr/bin/env bash
# Convenience wrapper: install from a local `make build` tree.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec bash "${ROOT}/scripts/install.sh" --local "$@"
