# wireguardd

WireGuard management daemon (**wireguardd**) and control panel (**wireguardctl**).

- **wireguardd** — privileged daemon with REST API, Prometheus metrics, SNMP agent, SQLite desired-state store, reconciler, peer suspend / traffic & bandwidth limits.
- **wireguardctl** — Bubble Tea TUI + CLI that manages a local or remote daemon.

## Architecture

```
wireguardctl  ──REST (HTTP / Unix)──►  wireguardd
                                         │
                    ┌────────────────────┼────────────────────┐
                    │                    │                    │
               SQLite SoT          Prometheus            SNMP v2c
                    │              /metrics                 :1161
                    ▼
              reconciler ──► wgctrl / ip / wg / wg-quick / tc
```

Desired configuration lives in SQLite. Live kernel state is applied every few seconds. Optional hybrid mode also writes `/etc/wireguard/<iface>.conf` for boot via `wg-quick`.

## Features

| Area | Capabilities |
|------|----------------|
| Interfaces | Create/delete, up/down, listen port, fwmark, MTU, multi IPv4/IPv6 addresses, DNS, table mode, Pre/Post hooks (opt-in), import/export wg-quick conf |
| Peers | AllowedIPs, endpoint, PSK, keepalive, assigned IPs, tags/notes, client conf + QR (requires `generate_client_key` or `client_private_key`, plus interface `public_endpoint`) |
| Policy | Suspend (strip AllowedIPs + blackhole routes), traffic quotas (auto-suspend), bandwidth limits (tc) |
| Stats | Per-peer / per-interface totals + rates, handshake/connected tracking |
| Observability | Prometheus metrics, SNMPv2c agent, audit/enforcement events |
| Keys | Generate keypairs and PSKs |

## Quick start

```bash
# Build
make build

# Dev run (mock backend if no WireGuard kernel module)
cat > /tmp/wgd.yaml <<'EOF'
listen:
  http: "127.0.0.1:51880"
  metrics: "127.0.0.1:9091"
snmp:
  enabled: true
  listen: "127.0.0.1:1161"
db:
  path: "/tmp/wireguardd.db"
auth:
  token: "dev-token"
wireguard:
  conf_dir: "/tmp/wireguard-conf"
  persistence: "hybrid"
  use_mock_backend: true
  bandwidth_backend: "none"
log:
  level: info
  format: text
EOF

./bin/wireguardd run --config /tmp/wgd.yaml

# CLI
export WIREGUARDCTL_TOKEN=dev-token
export WIREGUARDCTL_URL=http://127.0.0.1:51880
./bin/wireguardctl iface create --name wg0 --port 51820 --address 10.7.0.1/24
./bin/wireguardctl keys gen
./bin/wireguardctl peer create --iface wg0 --name alice --allowed-ip 10.7.0.2/32 --client-key --psk
# set public_endpoint on the interface for client conf/QR (PATCH /v1/interfaces/wg0)
./bin/wireguardctl peer client-config wg0 <PUB>
./bin/wireguardctl stats

# TUI
./bin/wireguardctl --config configs/wireguardctl.example.yaml
```

## Configuration

See `configs/wireguardd.example.yaml` and `configs/wireguardctl.example.yaml`.

Environment overrides use prefix `WIREGUARDD_` / `WIREGUARDCTL_` (e.g. `WIREGUARDD_AUTH_TOKEN`).

### Persistence modes

| Mode | Behavior |
|------|----------|
| `database` | SQLite only; apply via wgctrl/`ip` |
| `wg-quick` | Also write conf files under `conf_dir` |
| `hybrid` | SQLite SoT + write conf after each successful apply (default) |

### Suspend & limits

- **Suspend**: peer stays in DB; live AllowedIPs cleared; blackhole routes for assigned IPs.
- **Traffic limit**: when effective RX+TX ≥ limit, peer is auto-suspended.
- **Bandwidth**: best-effort `tc` HTB classes per peer IP (`bandwidth_backend: tc|nft|none`).
- **Soft traffic reset**: stores offsets so user-visible counters restart without kernel reset.

## REST API

Bearer token required on `/v1/*`. OpenAPI: [`api/openapi.yaml`](api/openapi.yaml).

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | Liveness |
| GET | `/v1/interfaces` | List |
| POST | `/v1/interfaces` | Create |
| POST | `/v1/interfaces/{name}/up\|down` | Admin state |
| POST | `/v1/interfaces/{name}/peers` | Add peer |
| POST | `/v1/interfaces/{name}/peers/{pubkey}/suspend` | Suspend |
| GET | `/v1/stats` | Rollup |
| POST | `/v1/keys/generate` | Keys |
| GET | `/metrics` | Prometheus |

## Prometheus

Scrape `http://host:9091/metrics`. Metrics include per-interface and per-peer counters, rates, handshake age, connected, suspended, and limits. See `internal/metrics/prometheus.go`.

## SNMP

SNMPv2c on UDP (default `:1161`). Community from config. OID base `1.3.6.1.4.1.66666.1` (placeholder PEN). MIB sketch: `deploy/mibs/WIREGUARDD-MIB.txt`.

## Install (Linux)

```bash
make build
sudo ./scripts/install.sh
# edit /etc/wireguardd/config.yaml
sudo systemctl enable --now wireguardd
```

Requires `CAP_NET_ADMIN` (root) for real WireGuard operations. Package `wireguard-tools` recommended for `wg` / `wg-quick`.

## Development

```bash
make test          # race-enabled unit/API tests
make lint          # golangci-lint
make build cross   # local + linux amd64/arm64
```

Tests use an in-memory mock WireGuard backend; no kernel module required in CI.

## Security notes

- Default token is `change-me` — **must** be rotated.
- Database and conf files are mode `0600`.
- Hooks (`PreUp`/`PostUp`/…) are **disabled** unless `wireguard.allow_hooks: true` (they run as root).
- Private keys are omitted from list/get responses unless `?reveal=1`.
- Prefer Unix socket or localhost HTTP for the API; use TLS termination / firewall for remote access.

## License

MIT — see [LICENSE](LICENSE).
