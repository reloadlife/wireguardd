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

## Metrics

`GET /metrics` on the main listener and/or dedicated `listen.metrics` address (Prometheus text format).
