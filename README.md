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
              reconciler ──► wgctrl / ip / wg / wg-quick / tc / nft
```

Desired configuration lives in SQLite. Live kernel state is applied every few seconds. Optional hybrid mode also writes `/etc/wireguard/<iface>.conf` for boot via `wg-quick`.

**Two SQLite files** keep config SoT off the hot write path:

| File | Contents | Profile |
|------|----------|---------|
| `state.db` (`db.path`) | interfaces, peers, events | WAL, NORMAL sync, 64 MiB cache, 256 MiB mmap |
| `timeseries.db` (`db.timeseries_path`, default `<dir>/timeseries.db`) | `traffic_samples` only | WAL, NORMAL sync, **128 MiB** cache, **512 MiB** mmap, no FKs, batched inserts/purge |

Both use `temp_store=MEMORY`, 10 s busy timeout, incremental auto-vacuum (new files). Upgrades copy legacy samples out of `state.db` before dropping that table.

## Features

| Area | Capabilities |
|------|----------------|
| Interfaces | Create/delete, up/down, listen port, fwmark, MTU, multi IPv4/IPv6 addresses, **full DNS host apply** (`resolvectl` / `resolvconf`), **full Table= routing**, Pre/Post hooks (opt-in), import/export wg-quick conf |
| Peers | AllowedIPs, endpoint, PSK, keepalive, assigned IPs, tags/notes, client conf + QR (requires `generate_client_key` or `client_private_key`, plus interface `public_endpoint`) |
| Policy | Suspend (strip AllowedIPs + blackhole routes), traffic quotas (auto-suspend), bandwidth limits (tc / nft) |
| Stats | Dual peer counters: **accumulative totals** + **time-based** rates (EWMA + raw) + lookback windows (1m/5m/15m/1h/24h), history samples, handshake/connected tracking |
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

# Full TUI control panel
./bin/wireguardctl --config configs/wireguardctl.example.yaml
# Tabs: Interfaces · Peers · Stats · Events · Keys
# n create · enter detail · e edit · s suspend · c client-conf · D delete
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

### DNS host apply (`DNS=`, wg-quick compatible)

Mixed `DNS` list: IP entries are nameservers; non-IP entries are search/routing domains.

| `dns_backend` | Behavior |
|---------------|----------|
| `auto` (default) | Prefer `resolvectl`, else `resolvconf` |
| `resolvectl` | `resolvectl dns/domain/default-route <iface> …` |
| `resolvconf` | Pipe nameserver/search into `resolvconf -a tun.<iface>` |
| `none` | Store + conf export only (no host apply) |

Cleared on interface down/delete (`resolvectl revert` / `resolvconf -d`).

### Routing table (`Table=`, wg-quick compatible)

| `table_mode` | Live behavior |
|--------------|---------------|
| `auto` (default) | AllowedIP routes in main table; `0.0.0.0/0` / `::/0` use a special table + fwmark + `suppress_prefixlength 0` (same idea as wg-quick) |
| `off` | No AllowedIP routes or policy rules |
| `number` + `table_id` | All AllowedIP routes in that table; policy rules from each interface address (`from <addr> lookup <id>`) and `iif <wg>` |

Suspended peers are excluded from route install. Interface down / delete removes managed routes and rules.

### Suspend & limits

- **Suspend**: peer stays in DB; live AllowedIPs cleared; blackhole routes for assigned IPs.
- **Traffic limit**: when effective RX+TX ≥ limit, peer is auto-suspended.
- **Bandwidth** (`bandwidth_backend`): independent **RX** and **TX** limits per peer; requires host-sized `assigned_ips` (or `/32`/`/128` in `allowed_ips`):
  - **`tc`** (default): Linux traffic control
    - **TX** (server → peer): HTB class on the WireGuard iface, filters match **destination** tunnel IP (IPv4 + IPv6)
    - **RX** (peer → server): ingress qdisc + **police** filters matching **source** tunnel IP
    - Stable per-peer class IDs, SFQ under each TX class
  - **`nft`**: full nftables backend (no tc dependency)
    - Per-iface table `inet wireguardd_<iface>` with input/forward/output hooks
    - **TX**: `oifname` + `ip[6] daddr` → `limit rate over … drop`
    - **RX**: `iifname` + `ip[6] saddr` → `limit rate over … drop`
    - Covers both locally terminated and **forwarded** tunnel traffic
    - Interface delete / zero limits → `nft delete table …` (clean teardown)
  - **`none`**: store limits in DB/API only; no host enforcement
- **Soft traffic reset**: stores offsets so user-visible counters restart without kernel reset.
- **Peer counters (dual model)**:
  - **Accumulative** (`traffic.total` / `rx_bytes`+`tx_bytes`): bytes since soft-reset
  - **Time-based rates** (`traffic.rate`): EWMA-smoothed + last-interval raw (bytes/sec)
  - **Lookback windows** (`traffic.windows`): bytes + avg rate over `1m`, `5m`, `15m`, `1h`, `24h`
  - History: `GET /v1/interfaces/{name}/peers/{pubkey}/traffic?from=&to=&limit=`

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
| GET | `/v1/stats` | Rollup (totals + rates) |
| GET | `/v1/interfaces/{name}/peers/{pubkey}/traffic` | Dual counters + sample history |
| POST | `/v1/keys/generate` | Keys |
| GET | `/metrics` | Prometheus |

## Prometheus

Scrape `http://host:9091/metrics`. Metrics include per-interface and per-peer **accumulative** counters (`*_bytes_total`), **time-based** rates (`*_bytes_per_second` EWMA + `_raw`), lookback windows (`*_bytes_window{window=…}`), handshake age, connected, suspended, and limits. See `internal/metrics/prometheus.go`.

## SNMP (full SNMPv2c agent)

Enable in config (`snmp.enabled: true`). Default listen `127.0.0.1:1161`, community from config.

| Feature | Support |
|---------|---------|
| SNMPv2c | GET, GETNEXT, GETBULK |
| SET | rejected (`notWritable`) — agent is read-only |
| Types | Integer, OctetString, OID, Counter64, Gauge32, TimeTicks |
| Exceptions | noSuchObject, noSuchInstance, endOfMibView |
| System group | `1.3.6.1.2.1.1.*` (sysDescr, sysUpTime, …) |
| Enterprise MIB | `1.3.6.1.4.1.66666.1` (placeholder PEN) |

```bash
# walk enterprise tree
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.66666.1

# interface name row 1
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.66666.1.2.1.2.1

# bulk
snmpbulkwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.4.1.66666.1.3
```

Full MIB: [`deploy/mibs/WIREGUARDD-MIB.txt`](deploy/mibs/WIREGUARDD-MIB.txt).

## Install

### One-liner (release binaries)

```bash
# public (or already authenticated host)
curl -fsSL https://raw.githubusercontent.com/reloadlife/wireguardd/main/scripts/install.sh | sudo bash

# private repo — pass a token with `repo` (or `contents:read` + releases) scope
curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://raw.githubusercontent.com/reloadlife/wireguardd/main/scripts/install.sh \
  | sudo -E env GITHUB_TOKEN="$GITHUB_TOKEN" bash
```

Options:

```bash
# pin a version
curl -fsSL …/install.sh | sudo bash -s -- --version v0.1.0

# control panel only (also the default on macOS)
curl -fsSL …/install.sh | sudo bash -s -- --ctl-only

# custom prefix
curl -fsSL …/install.sh | sudo bash -s -- --prefix /opt/wireguardd
```

### From a local build

```bash
make build
sudo ./scripts/install.sh --local
# edit /etc/wireguardd/config.yaml
sudo systemctl enable --now wireguardd
```

### Manual from GitHub Releases

Download `wireguardd_*_linux_*.tar.gz` and `wireguardctl_*_*.tar.gz` from
[Releases](https://github.com/reloadlife/wireguardd/releases), extract, and
`install` the binaries into `/usr/local/bin`.

Requires `CAP_NET_ADMIN` (root) for real WireGuard operations. Package
`wireguard-tools` is recommended for `wg` / `wg-quick`.

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

[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE) — see [LICENSE](LICENSE).
