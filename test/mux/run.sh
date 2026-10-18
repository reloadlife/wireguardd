#!/usr/bin/env bash
# End-to-end test for wireguardd's swift-mux same-port mode in local containers.
# Runs the exact ruleset wireguardd renders (test/mux/render).
#
#   server: plain WG  "wgs"  kernel   :51820  10.80.0.1/24
#           AWG       "awgs" swiftwg  :51830  10.81.0.1/24   (prod: amneziawg.ko)
#           mux: non-stock flows on :51820 -> :51830
#   wgc:    plain WG client        -> :51820  10.80.0.2
#   awgc:   AWG client (new conf)  -> :51820  10.81.0.2
#   awgl:   AWG client (old conf)  -> :51830  10.81.0.3
#
# Usage: test/mux/run.sh [awg2|awg3]   SWIFT_ROOT defaults to ../swift
# Needs Docker with a kernel that has the wireguard module (OrbStack/Docker Desktop do).
set -euo pipefail

PROFILE="${1:-awg2}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WGD="$(cd "$HERE/../.." && pwd)"
SWIFT_ROOT="${SWIFT_ROOT:-$WGD/../swift}"
IMG=swift-mux-test
NET=wgdmux
PASS=0 FAIL=0

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
x()    { docker exec "$@"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }

cleanup() {
  docker rm -f wgdm-server wgdm-wgc wgdm-awgc wgdm-awgl >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

counter() {
  x wgdm-server nft list chain inet wireguardd_mux "$1" |
    awk -v c="\"$2" '$0 ~ c { for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1) }' | head -1
}

apply_rules() {
  printf 'table inet wireguardd_mux\ndelete table inet wireguardd_mux\n%s\n' "$RULES" | x -i wgdm-server nft -f -
}

say "build image + ruleset"
docker build -q -f "$SWIFT_ROOT/mux/test/Dockerfile" -t "$IMG" "$SWIFT_ROOT" >/dev/null
RULES="$(cd "$WGD" && go run ./test/mux/render 51820:51830)"

cleanup
docker network create --subnet 172.30.81.0/24 "$NET" >/dev/null
run() { docker run -d --name "$1" --hostname "$1" --network "$NET" --ip "$2" --privileged "$IMG" sleep infinity >/dev/null; }
run wgdm-server 172.30.81.10
run wgdm-wgc    172.30.81.20
run wgdm-awgc   172.30.81.30
run wgdm-awgl   172.30.81.40
SRV=172.30.81.10

key()  { x "$1" sh -c 'umask 077; wg genkey > /k; wg pubkey < /k'; }
SRV_PUB=$(key wgdm-server)   # one identity on both twins, as in prod
WGC_PUB=$(key wgdm-wgc)
AWGC_PUB=$(key wgdm-awgc)
AWGL_PUB=$(key wgdm-awgl)

AWG_IFACE="Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 18
S3 = 20
S4 = 23
H1 = 1384938201
H2 = 2938475610
H3 = 3847561092
H4 = 1928374650"
if [[ "$PROFILE" == "awg3" ]]; then
  AWG_IFACE+="
HeaderProtectionKey = $(x wgdm-server wg genkey)"
fi

say "server: wgs :51820 + awgs :51830 + wireguardd mux [$PROFILE]"
x wgdm-server sh -c "ip link add wgs type wireguard &&
  wg set wgs listen-port 51820 private-key /k peer $WGC_PUB allowed-ips 10.80.0.2/32 &&
  ip addr add 10.80.0.1/24 dev wgs && ip link set wgs up"
x wgdm-server sh -c "swiftwg awgs && sleep 0.5 && cat > /awgs.conf <<EOF
[Interface]
PrivateKey = \$(cat /k)
ListenPort = 51830
$AWG_IFACE

[Peer]
PublicKey = $AWGC_PUB
AllowedIPs = 10.81.0.2/32

[Peer]
PublicKey = $AWGL_PUB
AllowedIPs = 10.81.0.3/32
EOF
awg setconf awgs /awgs.conf && ip addr add 10.81.0.1/24 dev awgs && ip link set awgs up"
apply_rules

say "clients"
x wgdm-wgc sh -c "ip link add wgc type wireguard &&
  wg set wgc private-key /k peer $SRV_PUB allowed-ips 10.80.0.0/24 endpoint $SRV:51820 &&
  ip addr add 10.80.0.2/24 dev wgc && ip link set wgc up"
awg_client() { # container tunnel-ip server-port
  x "$1" sh -c "swiftwg awgc && sleep 0.5 && cat > /awgc.conf <<EOF
[Interface]
PrivateKey = \$(cat /k)
$AWG_IFACE

[Peer]
PublicKey = $SRV_PUB
AllowedIPs = 10.81.0.0/24
Endpoint = $SRV:$3
EOF
awg setconf awgc /awgc.conf && ip addr add $2/24 dev awgc && ip link set awgc up"
}
awg_client wgdm-awgc 10.81.0.2 51820
awg_client wgdm-awgl 10.81.0.3 51830

say "1. one public port for both flavors; old :51830 configs still work"
check "plain WG client over :51820"   x wgdm-wgc ping -c2 -W2 10.80.0.1
check "AWG client over :51820 (mux)"  x wgdm-awgc ping -c2 -W2 10.81.0.1
check "legacy AWG client over :51830" x wgdm-awgl ping -c2 -W2 10.81.0.1
[[ "$(counter classify_51820 'wg initiation')" -ge 1 ]] && ok "stock initiation stayed on wgs" || bad "stock initiation not matched"
[[ "$(counter classify_51820 'awg')" -ge 1 ]] && ok "AWG flow redirected to awgs" || bad "AWG flow not redirected"

say "2. AWG traffic never matches a stock rule"
wgsum() { local n=0 c; for c in "wg initiation" "wg response" "wg cookie" "wg transport"; do n=$((n + $(counter classify_51820 "$c"))); done; echo $n; }
x wgdm-server conntrack -F >/dev/null 2>&1 || true
x wgdm-server sh -c 'ip link set awgs down; ip link set awgs up'
before=$(wgsum)
check "AWG re-handshakes after reset" x wgdm-awgc ping -c3 -W3 10.81.0.1
after=$(wgsum)
[[ "$after" -eq "$before" ]] && ok "no AWG packet hit a stock rule ($before -> $after)" || bad "AWG packet hit a stock rule ($before -> $after)"

say "3. conntrack flush mid-session"
x wgdm-server conntrack -F >/dev/null 2>&1 || true
check "plain WG survives flush"   x wgdm-wgc ping -c2 -W2 10.80.0.1
check "AWG (mux) survives flush"  x wgdm-awgc ping -c2 -W2 10.81.0.1
check "legacy AWG survives flush" x wgdm-awgl ping -c2 -W2 10.81.0.1

say "4. server-initiated traffic reaches both AWG clients"
check "server -> AWG (mux) client"  x wgdm-server ping -c2 -W2 10.81.0.2
check "server -> legacy AWG client" x wgdm-server ping -c2 -W2 10.81.0.3

say "5. reapply keeps sessions (atomic replace)"
apply_rules
check "plain WG after reapply" x wgdm-wgc ping -c2 -W2 10.80.0.1
check "AWG (mux) after reapply" x wgdm-awgc ping -c2 -W2 10.81.0.1

say "result [$PROFILE]: $PASS passed, $FAIL failed"
if ((FAIL)); then
  x wgdm-server nft list table inet wireguardd_mux || true
  exit 1
fi
