# wireguardd

**wireguardd** is a Linux daemon that manages WireGuard interfaces and peers with a REST API, SQLite desired-state store, reconciler, traffic policy, Prometheus metrics, and optional SNMP.

**wireguardctl** is the control panel: full-screen TUI plus CLI (including self-update).

[![CI](https://github.com/reloadlife/wireguardd/actions/workflows/ci.yml/badge.svg)](https://github.com/reloadlife/wireguardd/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)

## Why

- **Desired state in SQLite**, applied live via `wgctrl` / `ip` (and optional `tc` / `nft`)
- **Brownfield-friendly**: adopt already-running tunnels without tearing them down
- **Hybrid conf export** with durable `# Name =` / `# Address =` comments so a DB loss still leaves peer metadata under `/etc/wireguard`
- **Dual traffic counters**: accumulative totals + rates + lookback windows
- **Client conf + QR** when a client private key is stored (or issued with rotate)

## Architecture

```
wireguardctl  ── HTTP / Unix ──►  wireguardd
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
         state.db              timeseries.db          Prometheus / SNMP
      (ifaces, peers)        (traffic samples)
              │
         reconciler ──► kernel WireGuard + ip (+ tc | nft)
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/reloadlife/wireguardd/main/scripts/install.sh | sudo bash
sudoedit /etc/wireguardd/config.yaml   # set auth.token
sudo systemctl enable --now wireguardd
```

Match the token for the CLI:

```bash
sudo tee /etc/wireguardctl/config.yaml >/dev/null <<'EOF'
server:
  url: "http://127.0.0.1:51880"
  token: "YOUR_TOKEN"
EOF
sudo chmod 600 /etc/wireguardctl/config.yaml
wireguardctl iface list
```

Full install notes: [docs/INSTALL.md](docs/INSTALL.md)

### Self-update

```bash
wireguardctl update --check
sudo wireguardctl update

sudo systemctl stop wireguardd && sudo wireguardd update && sudo systemctl start wireguardd
```

## Quick start (dev)

```bash
make build
cat > /tmp/wgd.yaml <<'EOF'
listen:
  http: "127.0.0.1:51880"
  metrics: "127.0.0.1:9091"
db:
  path: "/tmp/wireguardd-state.db"
auth:
  token: "dev-token"
wireguard:
  conf_dir: "/tmp/wireguard-conf"
  use_mock_backend: true
  bandwidth_backend: "none"
  dns_backend: "none"
log:
  level: info
  format: text
EOF
./bin/wireguardd run --config /tmp/wgd.yaml &

export WIREGUARDCTL_URL=http://127.0.0.1:51880
export WIREGUARDCTL_TOKEN=dev-token
./bin/wireguardctl iface create --name wg0 --port 51820 --address 10.7.0.1/24
./bin/wireguardctl peer create --iface wg0 --name alice --client-key --psk
./bin/wireguardctl   # full-screen TUI
```

## Attach to existing WireGuard

```bash
wireguardctl discover
wireguardctl adopt
# optional: wireguard.adopt_on_start: true
```

| Behaviour | Detail |
|-----------|--------|
| Non-destructive | Does not delete host peers, addresses, or qdiscs on adopt |
| Keys | From kernel when readable, else `conf_dir/<iface>.conf` |
| Client conf/QR | Needs `client_private_key`; use `peer issue-client-key --rotate` if missing |
| Routes/DNS/bandwidth | Safe defaults on adopt; enable backends when ready |

## Features (summary)

| Area | Notes |
|------|--------|
| Interfaces | CRUD, up/down, MTU, fwmark, DNS apply, Table= routing, import/export conf |
| Peers | AllowedIPs, PSK, suspend, quotas, bandwidth limits, auto IP allocation |
| Stats | Totals + EWMA/raw rates + windows `1m`…`24h` + history API |
| Observability | Prometheus, SNMPv2c, events |
| TUI | Full-screen, adaptive colors, QR in-terminal |

## Configuration

- Daemon example: [`configs/wireguardd.example.yaml`](configs/wireguardd.example.yaml)
- CLI example: [`configs/wireguardctl.example.yaml`](configs/wireguardctl.example.yaml)
- Details: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)

Env prefixes: `WIREGUARDD_*`, `WIREGUARDCTL_*`.

## API

Bearer token on `/v1/*`. Overview: [docs/API.md](docs/API.md). OpenAPI: [`api/openapi.yaml`](api/openapi.yaml).

```bash
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:51880/v1/stats
```

## Security

- **Never** leave `auth.token: change-me` on a real host
- Bind API to localhost or Unix socket; terminate TLS externally if remote
- Keep `allow_hooks: false` unless every API client is trusted (hooks run as root)
- See [SECURITY.md](SECURITY.md) for reporting vulnerabilities

## Development

```bash
make test
make lint
make build
```

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md)

## Donations

If this project is useful to you, donations are welcome:

| Network | Address |
|---------|---------|
| **Bitcoin** (BTC) | `bc1qy08pk2teys968hphh98rv8y9azeraf2c8vsdm8` |
| **Ethereum** (ETH / EVM) | `0x8B6CE1EA8F17f6941F13A621b92Af345a75D8c41` |
| **TRON** (TRX) | `TGXJToyAsUtw1388jR5aW9ZohjSCDtmKbg` |

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).
