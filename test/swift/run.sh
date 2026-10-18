#!/usr/bin/env bash
# End-to-end test for wireguardd's swift backend in local containers.
# Runs the real wireguardd (linux build) and drives it over its HTTP API, as
# node-agent does. swt0 starts as a kernel WireGuard device with a live client,
# then is cut over in place to swift (the production migration path):
#
#   server: wireguardd, "swt0" kernel wg -> swift (swiftwg)  :51820  10.80.0.1/24
#           mux alias :51830 -> :51820 (legacy PORT+10 AWG configs)
#   wgc:    plain WG client (kernel)     -> :51820  10.80.0.2
#   awgc:   AWG client (swiftwg)         -> :51820  10.80.0.3
#   awgl:   AWG client, old twin config  -> :51830  10.80.0.4
#
# Usage: test/swift/run.sh   SWIFT_ROOT defaults to ../swift
# Needs Docker with a kernel that has the wireguard module (OrbStack/Docker Desktop do).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WGD="$(cd "$HERE/../.." && pwd)"
SWIFT_ROOT="${SWIFT_ROOT:-$WGD/../swift}"
IMG=swift-mux-test
NET=wgdswift
TOKEN=swift-e2e-token
PASS=0 FAIL=0

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
x()    { docker exec "$@"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
api()  { # method path [json]
  x wgds-server curl -fsS -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    ${3:+--data "$3"} "http://127.0.0.1:51880/v1$2"
}

cleanup() {
  docker rm -f wgds-server wgds-wgc wgds-awgc wgds-awgl >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
[[ "${KEEP:-}" == 1 ]] || trap cleanup EXIT

say "build image + wireguardd"
docker build -q -f "$SWIFT_ROOT/mux/test/Dockerfile" -t "$IMG" "$SWIFT_ROOT" >/dev/null
ARCH="$(docker info -f '{{.Architecture}}')"
case "$ARCH" in aarch64|arm64) GOARCH=arm64 ;; x86_64|amd64) GOARCH=amd64 ;; *) echo "arch $ARCH" >&2; exit 1 ;; esac
BIN="$(mktemp -d)/wireguardd"
(cd "$WGD" && CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -o "$BIN" ./cmd/wireguardd)

cleanup
docker network create --subnet 172.30.82.0/24 "$NET" >/dev/null
run() { docker run -d --name "$1" --hostname "$1" --init --network "$NET" --ip "$2" --privileged "$IMG" sleep infinity >/dev/null; }
run wgds-server 172.30.82.10
run wgds-wgc    172.30.82.20
run wgds-awgc   172.30.82.30
run wgds-awgl   172.30.82.40
SRV=172.30.82.10

docker cp "$BIN" wgds-server:/usr/bin/wireguardd >/dev/null
x wgds-server apk add -q --no-cache curl >/dev/null
x -i wgds-server sh -c 'mkdir -p /var/lib/wireguardd /etc/wireguard && cat > /etc/wireguardd.yaml' <<EOF
listen:
  http: "127.0.0.1:51880"
snmp:
  enabled: false
db:
  path: "/var/lib/wireguardd/state.db"
auth:
  token: "$TOKEN"
wireguard:
  conf_dir: "/etc/wireguard"
  persistence: "database"
  reconcile_interval: 2s
  sample_interval: 5s
log:
  level: info
EOF
start_wgd() { x -d wgds-server sh -c 'wireguardd run --config /etc/wireguardd.yaml >>/var/log/wireguardd.log 2>&1'; }
start_wgd
for _ in $(seq 1 50); do api GET /interfaces >/dev/null 2>&1 && break; sleep 0.2; done

key()  { x "$1" sh -c 'umask 077; wg genkey > /k; wg pubkey < /k'; }
WGC_PUB=$(key wgds-wgc)
AWGC_PUB=$(key wgds-awgc)
AWGL_PUB=$(key wgds-awgl)

# Same noise shape the CP issues (AWG 1.x: S1/S2 + random H, no S3/S4).
NOISE='"s1":138,"s2":73,"h1":"523307567","h2":"899255190","h3":"992133429","h4":"941059059"'
AWG_IFACE="S1 = 138
S2 = 73
H1 = 523307567
H2 = 899255190
H3 = 992133429
H4 = 941059059
Jc = 4
Jmin = 40
Jmax = 70"

say "0. kernel WireGuard swt0 with a live client (today's node)"
api POST /interfaces '{"name":"swt0","listen_port":51820,"protocol":"wg","backend":"kernel","addresses":["10.80.0.1/24"]}' >/dev/null
for p in "$WGC_PUB 10.80.0.2" "$AWGC_PUB 10.80.0.3" "$AWGL_PUB 10.80.0.4"; do
  set -- $p
  api POST /interfaces/swt0/peers "{\"public_key\":\"$1\",\"name\":\"$2\",\"allowed_ips\":[\"$2/32\"]}" >/dev/null
done
SRV_PUB=""
for _ in $(seq 1 50); do
  SRV_PUB=$(x wgds-server wg show swt0 public-key 2>/dev/null || true)
  [[ -n "$SRV_PUB" ]] && break
  sleep 0.2
done
check "kernel wg device created" sh -c "docker exec wgds-server ip -d link show swt0 | grep -q 'wireguard '"
x wgds-wgc sh -c "ip link add wgc type wireguard &&
  wg set wgc private-key /k peer $SRV_PUB allowed-ips 10.80.0.0/24 endpoint $SRV:51820 persistent-keepalive 25 &&
  ip addr add 10.80.0.2/24 dev wgc && ip link set wgc up"
check "plain WG client on kernel device" x wgds-wgc ping -c2 -W2 10.80.0.1

say "cutover: PATCH swt0 -> swift (AWG profile + allow_clean, alias :51830)"
start=$(date +%s)
api PATCH /interfaces/swt0 "{\"protocol\":\"awg\",\"backend\":\"swift\",\"amnezia\":{$NOISE},\"mux_port\":51830}" >/dev/null
for _ in $(seq 1 60); do
  x wgds-server test -S /var/run/amneziawg/swt0.sock 2>/dev/null && break
  sleep 0.5
done
check "swt0 now runs on swiftwg (userspace socket)" x wgds-server test -S /var/run/amneziawg/swt0.sock
check "same server key after cutover" sh -c "[ \"\$(docker exec wgds-server awg show swt0 public-key)\" = '$SRV_PUB' ]"
back=""
for _ in $(seq 1 90); do
  if x wgds-wgc ping -c1 -W1 10.80.0.1 >/dev/null 2>&1; then back=$(( $(date +%s) - start )); break; fi
done
if [[ -n "$back" ]]; then ok "untouched plain WG client back after cutover (${back}s)"; else bad "plain WG client did not recover"; fi
check "mux alias rule installed" sh -c "docker exec wgds-server nft list table inet wireguardd_mux | grep -q 'redirect to :51820'"

say "AWG clients"
awg_client() { # container tunnel-ip server-port
  x "$1" sh -c "swiftwg awgc && sleep 0.5 && cat > /awgc.conf <<EOF
[Interface]
PrivateKey = \$(cat /k)
$AWG_IFACE

[Peer]
PublicKey = $SRV_PUB
AllowedIPs = 10.80.0.0/24
Endpoint = $SRV:$3
EOF
awg setconf awgc /awgc.conf && ip addr add $2/24 dev awgc && ip link set awgc up"
}
awg_client wgds-awgc 10.80.0.3 51820
awg_client wgds-awgl 10.80.0.4 51830

say "1. one swift device serves plain WG, AWG, and the legacy port"
# Stock WG reaching an AWG-profiled device proves allow_clean was applied.
check "plain WG client over :51820"    x wgds-wgc ping -c2 -W2 10.80.0.1
check "AWG client over :51820"         x wgds-awgc ping -c2 -W2 10.80.0.1
check "legacy AWG client over :51830"  x wgds-awgl ping -c2 -W2 10.80.0.1
check "server -> plain WG client"      x wgds-server ping -c2 -W2 10.80.0.2
check "server -> legacy AWG client"    x wgds-server ping -c2 -W2 10.80.0.4

say "2. wireguardd restart keeps tunnels (swiftwg outlives it)"
x wgds-server pkill -x wireguardd || true
sleep 1
check "plain WG with wireguardd down" x wgds-wgc ping -c2 -W2 10.80.0.1
check "AWG with wireguardd down"      x wgds-awgc ping -c2 -W2 10.80.0.1
start_wgd
sleep 5
check "plain WG after restart + reconcile" x wgds-wgc ping -c2 -W2 10.80.0.1
check "AWG after restart + reconcile"      x wgds-awgc ping -c2 -W2 10.80.0.1
check "legacy AWG after restart"           x wgds-awgl ping -c2 -W2 10.80.0.1
check "still one swiftwg process" sh -c "[ \$(docker exec wgds-server pgrep -x swiftwg | wc -l) -eq 1 ]"

say "3. conntrack flush mid-session"
x wgds-server conntrack -F >/dev/null 2>&1 || true
check "plain WG survives flush"  x wgds-wgc ping -c2 -W2 10.80.0.1
check "legacy AWG survives flush" x wgds-awgl ping -c2 -W2 10.80.0.1

say "4. rollback: PATCH swt0 -> kernel WireGuard (agent leaves amnezia params in the DB)"
start=$(date +%s)
api PATCH /interfaces/swt0 '{"protocol":"wg","backend":"kernel","mux_port":0}' >/dev/null
for _ in $(seq 1 60); do
  x wgds-server sh -c "ip -d link show swt0 2>/dev/null | grep -q 'wireguard '" && break
  sleep 0.5
done
check "swt0 back on kernel wireguard" sh -c "docker exec wgds-server ip -d link show swt0 | grep -q 'wireguard '"
check "swiftwg process gone" sh -c "! docker exec wgds-server pgrep -x swiftwg"
check "same server key after rollback" sh -c "[ \"\$(docker exec wgds-server wg show swt0 public-key)\" = '$SRV_PUB' ]"
back=""
for _ in $(seq 1 90); do
  if x wgds-wgc ping -c1 -W1 10.80.0.1 >/dev/null 2>&1; then back=$(( $(date +%s) - start )); break; fi
done
if [[ -n "$back" ]]; then ok "untouched plain WG client back after rollback (${back}s)"; else bad "plain WG client did not recover after rollback"; fi
check "alias table removed" sh -c "! docker exec wgds-server nft list table inet wireguardd_mux"

say "result [swift backend]: $PASS passed, $FAIL failed"
if ((FAIL)); then
  x wgds-server sh -c 'tail -40 /var/log/wireguardd.log; awg show; nft list table inet wireguardd_mux' || true
  exit 1
fi
