# HTTP API

Base URL: configured `listen.http` (example `http://127.0.0.1:51880`).

Authentication: `Authorization: Bearer <auth.token>` on all `/v1/*` routes.

OpenAPI sketch: [`api/openapi.yaml`](../api/openapi.yaml) (may lag; this list is authoritative for major routes).

## Core

| Method | Path | Notes |
|--------|------|--------|
| GET | `/healthz` | Liveness (no auth) |
| GET | `/readyz` | DB ping (no auth) |
| GET | `/v1/version` | Version |
| GET | `/v1/config` | Non-secret runtime config |
| POST | `/v1/reconcile` | Force reconcile |
| GET | `/v1/events` | Audit log |
| GET | `/v1/stats` | Global rollup |
| GET | `/v1/stats/peers` | All peers |
| POST | `/v1/keys/generate` | `{ "type": "keypair" \| "preshared" }` |

## Adopt (brownfield)

| Method | Path | Notes |
|--------|------|--------|
| GET | `/v1/discover` | Preview live devices (`?name=wg0`) |
| POST | `/v1/adopt` | Import live devices; body: `{ "names": [], "read_conf": true, "overwrite": false }` |

## Interfaces

| Method | Path |
|--------|------|
| GET/POST | `/v1/interfaces` |
| GET/PATCH/DELETE | `/v1/interfaces/{name}` |
| POST | `/v1/interfaces/{name}/up` |
| POST | `/v1/interfaces/{name}/down` |
| POST | `/v1/interfaces/{name}/export` |
| POST | `/v1/interfaces/{name}/import` |

Addresses must be valid CIDRs. `public_endpoint` must be `host:port` when set.

### Multi-backend WireGuard / AmneziaWG

Each interface has:

| Field | Values |
|-------|--------|
| `backend` | `auto` · `kernel` · `userspace` (wireguard-go) · `amnezia_kernel` · `amnezia_go` |
| `protocol` | `wg` (plain) · `awg` (AmneziaWG) |
| `amnezia` | Optional `{jc,jmin,jmax,s1–s4,h1–h4,i1–i5}` (required shape for `awg`) |

`GET /v1/backends` reports which host implementations are available.

**Dual pair create** (recommended default for product ingresses):

```json
POST /v1/interfaces
{
  "name": "wg0",
  "listen_port": 51820,
  "addresses": ["10.8.0.1/24"],
  "awg_addresses": ["10.8.0.2/24"],
  "public_endpoint": "vpn.example.com:51820",
  "create_awg_pair": true
}
```

Returns `{ "wg": {...}, "awg": {...} }` with the twin on **listen_port + 10** (`51830`), protocol `awg`, and a generated noise preset. Existing interfaces without these fields keep `backend=auto` / `protocol=wg` and are unchanged.

## Peers

| Method | Path |
|--------|------|
| GET/POST | `/v1/interfaces/{name}/peers` |
| GET/PATCH/DELETE | `/v1/interfaces/{name}/peers/{pubkey}` |
| POST | `.../suspend` · `.../resume` · `.../reset-traffic` |
| GET | `.../client-config` |
| POST | `.../issue-client-key` body `{ "rotate": true }` |
| GET | `.../qr` → `image/png` |
| GET | `.../traffic` history samples |

Public keys in paths use URL-safe base64 (`+`→`-`, `/`→`_`).

Creating a peer with empty `allowed_ips` and `assigned_ips` auto-allocates the next free host IP from the interface subnet.

Optional peer policy fields (create/update):

| Field | Type | Notes |
|-------|------|--------|
| `traffic_limit_bytes` | int64 | Effective RX+TX quota; `0` = unlimited |
| `expires_at` | string | RFC3339 or `""` to clear; past → auto-suspend |
| `bandwidth_rx_bps` / `bandwidth_tx_bps` | int64 | Per-direction rate (bytes/sec) |
| `bandwidth_total_bps` | int64 | Combined rate; fills zero directions |
| `suspended` | bool | PATCH only; also `POST .../suspend` / `.../resume` |

## Metrics

`GET /metrics` on the main listener and/or dedicated `listen.metrics` address (Prometheus text format).
