# Configuration

## wireguardd

Example: [`configs/wireguardd.example.yaml`](../configs/wireguardd.example.yaml)

Default path after install: `/etc/wireguardd/config.yaml`

### Essential keys

| Key | Description |
|-----|-------------|
| `auth.token` | Bearer token for `/v1/*` (**change the default**) |
| `listen.http` | API listen address (prefer `127.0.0.1:51880`) |
| `listen.unix` | Optional Unix socket path |
| `listen.metrics` | Prometheus listen (empty to disable dedicated listener) |
| `db.path` | State SQLite path |
| `db.timeseries_path` | Traffic samples SQLite (default: `<dir>/timeseries.db`) |
| `wireguard.conf_dir` | Directory for `*.conf` export / adopt merge |
| `wireguard.persistence` | `database` \| `wg-quick` \| `hybrid` |
| `wireguard.bandwidth_backend` | `tc` \| `nft` \| `none` (default `tc`; `/readyz` checks `tc`/`nft` binary) |
| `webhooks.enabled` | `false` — POST agent events to an external controller |
| `webhooks.url` | HTTPS endpoint for the controller |
| `webhooks.secret` | Optional HMAC-SHA256 key (`X-Webhook-Signature: sha256=…`) |
| `webhooks.events` | Empty/`["*"]` = all; supports `peer.*` prefix filters |
| `webhooks.timeout` | HTTP timeout (default `5s`) |
| `wireguard.dns_backend` | `auto` \| `resolvectl` \| `resolvconf` \| `none` |
| `wireguard.adopt_on_start` | Import live interfaces on boot |
| `wireguard.allow_hooks` | Allow PreUp/PostUp shell hooks (dangerous if API is exposed) |
| `snmp.enabled` | SNMPv2c agent |

### Environment overrides

Prefix `WIREGUARDD_`, nested keys with `_`:

```bash
export WIREGUARDD_AUTH_TOKEN=...
export WIREGUARDD_DB_PATH=/var/lib/wireguardd/state.db
export WIREGUARDD_LISTEN_HTTP=127.0.0.1:51880
```

Also: `WIREGUARDD_API_TOKEN` maps to `auth.token`.

## wireguardctl

Example: [`configs/wireguardctl.example.yaml`](../configs/wireguardctl.example.yaml)

Search order:

1. `--config path`
2. `$HOME/.config/wireguardctl/config.yaml`
3. `/etc/wireguardctl/config.yaml`

Environment:

```bash
export WIREGUARDCTL_URL=http://127.0.0.1:51880
export WIREGUARDCTL_TOKEN=...
# or Unix:
export WIREGUARDCTL_UNIX=/run/wireguardd/wireguardd.sock
```

## Conf-file comments (durable backup)

In `hybrid` / `wg-quick` modes, exported confs include comment metadata so peer
names, tunnel addresses, and limits survive a lost database:

```ini
# Name = alice
# Address = 10.7.0.2/32
# TrafficLimit = 10737418240
[Peer]
PublicKey = ...
AllowedIPs = 10.7.0.2/32
```

## Webhooks (controller push)

Optional HTTP callbacks for a higher-layer multi-tenant controller. All SQLite
`events` rows plus lifecycle edges are eligible.

```yaml
webhooks:
  enabled: true
  url: "https://controller.example/hooks/wireguardd"
  secret: "shared-hmac-secret"
  events: ["*"]   # or ["peer.*","interface.*","enforce"]
  timeout: 5s
```

Headers: `X-Agent: wireguardd`, `X-Event-Kind`, optional `X-Webhook-Signature: sha256=<hex>`.

Payload fields: `agent`, `version`, `ts`, `level`, `kind`, `resource` (interface),
`subject` (peer public key), `message`, `meta`.

Lifecycle kinds: `interface.up`, `interface.down`, `peer.connected`, `peer.disconnected`.
Delivery is best-effort (bounded queue); controllers should still poll.
