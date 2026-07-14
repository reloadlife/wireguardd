#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"

echo "Installing wireguardd and wireguardctl to ${BIN_DIR}"
install -d "${BIN_DIR}"
install -m 0755 bin/wireguardd bin/wireguardctl "${BIN_DIR}/"

install -d /etc/wireguardd
if [[ ! -f /etc/wireguardd/config.yaml ]]; then
  install -m 0600 configs/wireguardd.example.yaml /etc/wireguardd/config.yaml
  echo "Wrote /etc/wireguardd/config.yaml — set auth.token before starting"
fi

install -d /var/lib/wireguardd
if [[ -d /etc/systemd/system ]]; then
  install -m 0644 deploy/wireguardd.service /etc/systemd/system/wireguardd.service
  systemctl daemon-reload || true
  echo "Systemd unit installed. Enable with: systemctl enable --now wireguardd"
fi

echo "Done."
