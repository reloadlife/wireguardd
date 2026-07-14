# Installation

## Requirements

- **Linux** for `wireguardd` (kernel WireGuard + `CAP_NET_ADMIN` / root)
- **Linux or macOS** for `wireguardctl`
- Recommended packages: `wireguard-tools` (`wg`, `wg-quick`)
- Optional: `iproute2` (`ip`, `tc`), `nftables` (`nft`) for bandwidth backends

## Quick install (releases)

```bash
curl -fsSL https://raw.githubusercontent.com/reloadlife/wireguardd/main/scripts/install.sh | sudo bash
```

Pin a version:

```bash
curl -fsSL https://raw.githubusercontent.com/reloadlife/wireguardd/main/scripts/install.sh \
  | sudo bash -s -- --version v0.8.0
```

Control panel only:

```bash
curl -fsSL https://raw.githubusercontent.com/reloadlife/wireguardd/main/scripts/install.sh \
  | sudo bash -s -- --ctl-only
```

## After install

```bash
# 1. Set a strong API token
sudoedit /etc/wireguardd/config.yaml

# 2. Install matching ctl config (token + URL)
sudo tee /etc/wireguardctl/config.yaml >/dev/null <<EOF
server:
  url: "http://127.0.0.1:51880"
  token: "SAME_TOKEN_AS_DAEMON"
EOF
sudo chmod 600 /etc/wireguardctl/config.yaml

# 3. Start
sudo systemctl enable --now wireguardd

# 4. Verify
wireguardctl version
wireguardctl iface list
```

## Existing WireGuard host (brownfield)

```bash
wireguardctl discover          # preview
wireguardctl adopt             # import live ifaces/peers into DB
# or in daemon config:
#   wireguard.adopt_on_start: true
```

Adopt is non-destructive: it does not tear down tunnels. See the main README.

## Self-update

Both binaries can update themselves from GitHub Releases (same asset names as the installer):

```bash
wireguardctl update --check
sudo wireguardctl update

sudo systemctl stop wireguardd
sudo wireguardd update
sudo systemctl start wireguardd
```

| Flag / env | Purpose |
|------------|---------|
| `--check` | Print current vs latest; no download |
| `--force` | Reinstall even if versions match |
| `--repo owner/name` | Override default `reloadlife/wireguardd` |
| `GITHUB_TOKEN` / `GH_TOKEN` | Private forks or higher API rate limits |

The updater replaces the on-disk binary (writes `.new`, swaps with backup). Restart the daemon after `wireguardd update`.

## From source

```bash
git clone https://github.com/reloadlife/wireguardd.git
cd wireguardd
make build
sudo ./scripts/install.sh --local
```

## Uninstall

```bash
sudo systemctl disable --now wireguardd
sudo rm -f /usr/local/bin/wireguardd /usr/local/bin/wireguardctl
sudo rm -f /etc/systemd/system/wireguardd.service
sudo systemctl daemon-reload
# optional: sudo rm -rf /var/lib/wireguardd /etc/wireguardd /etc/wireguardctl
```
