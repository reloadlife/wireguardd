# How wireguardd works

`wireguardd` is a Linux daemon that **manages WireGuard interfaces and peers** as desired state. It reconciles that state into the kernel (via `wgctrl` / `ip`, and optionally `tc` / `nft`), stores configuration in SQLite, and exposes a REST API. `wireguardctl` is the TUI/CLI control panel.

## Components

```
wireguardctl  ── HTTP / Unix ──►  wireguardd
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
         state.db              timeseries.db          Prometheus / SNMP
   (interfaces, peers,       (traffic samples)
    keys, settings)
              │
         reconciler ──► kernel WireGuard + addresses/routes (+ tc | nft)
```

| Piece | Role |
|-------|------|
| **state.db** | Desired interfaces, peers, client keys, settings |
| **timeseries.db** | Traffic samples for rates and lookback windows |
| **Reconciler** | Diffs desired vs live; applies create/update/delete |
| **Backend** | `wgctrl` + `ip`; optional bandwidth (tc/nft) and DNS-related helpers |
| **API** | REST under `/v1/*` with Bearer (or configured) auth |
| **wireguardctl** | Full-screen TUI + CLI; optional self-update |

## Desired-state loop

1. Operator creates or updates an **interface** (name, listen port, addresses, DNS, MTU, …).
2. Operator adds **peers** (public key, allowed IPs, endpoint, keepalive, optional PSK, optional client private key for profile export).
3. Reconciler ensures the kernel device matches: keys, peers, addresses, routes as configured.
4. Live counters are sampled into timeseries; API and TUI show totals and rates.
5. On restart, desired state is reloaded from SQLite and re-applied.

## Brownfield: discover and adopt

Hosts may already have WireGuard devices. `discover` lists them; `adopt` imports live config into the database **without tearing the tunnel down**. Optional `adopt_on_start` can import on daemon boot.

## Configuration export

Interface/peer state can be rendered to `wg-quick`-style conf under a configured directory, including durable comments (e.g. peer name, address) so metadata survives even if the DB is lost.

## Client profiles

When a client private key is stored (or issued on create/rotate), the API/TUI can emit:

- Client configuration text  
- QR encoding of that config  

for import into WireGuard-compatible clients.

## Traffic and policy extras

- **Traffic** — accumulative RX/TX plus derived rates and lookback windows from samples.  
- **Bandwidth backends** — optional per-peer or interface limits via `tc` or `nft` (configurable; can be disabled).  
- **Metrics** — Prometheus scrape endpoint; optional SNMP agent.

## Related binaries

| Binary | Purpose |
|--------|---------|
| `wireguardd` | Daemon |
| `wireguardctl` | Operator TUI/CLI |

Typical control API port: **51880** (see config). Linux required for the daemon; `wireguardctl` can run remotely against the API.
