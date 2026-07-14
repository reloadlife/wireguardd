#!/usr/bin/env bash
# wireguardd / wireguardctl installer
#
# From GitHub releases (Linux/macOS):
#   curl -fsSL https://raw.githubusercontent.com/reloadlife/wireguardd/main/scripts/install.sh | sudo bash
#
# Private repo (needs token for raw + assets):
#   curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" \
#     https://raw.githubusercontent.com/reloadlife/wireguardd/main/scripts/install.sh \
#     | sudo -E env GITHUB_TOKEN="$GITHUB_TOKEN" bash
#
# Local build tree:
#   make build && sudo ./scripts/install.sh --local
#
# Options / env:
#   --version v0.1.0 | VERSION=v0.1.0   pin release (default: latest)
#   --prefix /usr/local                install prefix (default: /usr/local)
#   --bin-dir DIR                      binary dir (default: $PREFIX/bin)
#   --no-systemd                       skip unit install
#   --ctl-only                         install only wireguardctl
#   --daemon-only                      install only wireguardd (Linux)
#   --local                            use ./bin from repo checkout
#   GITHUB_TOKEN / GH_TOKEN            auth for private releases
#   REPO=owner/name                    override repo (default: reloadlife/wireguardd)
set -euo pipefail

REPO="${REPO:-reloadlife/wireguardd}"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="${BIN_DIR:-}"
INSTALL_SYSTEMD=1
CTL_ONLY=0
DAEMON_ONLY=0
LOCAL=0
TMPDIR_BASE="${TMPDIR:-/tmp}"

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --version) VERSION="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --no-systemd) INSTALL_SYSTEMD=0; shift ;;
    --ctl-only) CTL_ONLY=1; shift ;;
    --daemon-only) DAEMON_ONLY=1; shift ;;
    --local) LOCAL=1; shift ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

if [[ -z "$BIN_DIR" ]]; then
  BIN_DIR="${PREFIX}/bin"
fi

if [[ "$CTL_ONLY" -eq 1 && "$DAEMON_ONLY" -eq 1 ]]; then
  die "use only one of --ctl-only / --daemon-only"
fi

# --- platform ---
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv6l) die "32-bit ARM is not supported; use amd64/arm64" ;;
  *) die "unsupported architecture: $ARCH_RAW" ;;
esac

case "$OS" in
  linux) ;;
  darwin)
    if [[ "$DAEMON_ONLY" -eq 1 ]]; then
      die "wireguardd is Linux-only; on macOS install wireguardctl only"
    fi
    CTL_ONLY=1
    ;;
  *) die "unsupported OS: $OS (need linux or darwin)" ;;
esac

# root for system paths
if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1 && [[ -f "${BASH_SOURCE[0]:-}" ]]; then
    warn "re-exec with sudo for install to ${BIN_DIR}"
    exec sudo -E \
      REPO="$REPO" VERSION="$VERSION" PREFIX="$PREFIX" BIN_DIR="$BIN_DIR" \
      GITHUB_TOKEN="${GITHUB_TOKEN:-}" GH_TOKEN="${GH_TOKEN:-}" \
      bash "${BASH_SOURCE[0]}" "$@"
  fi
  die "run as root: curl … | sudo bash   (or: sudo ./scripts/install.sh)"
fi

need_cmd curl
need_cmd tar
need_cmd install
need_cmd mktemp

auth_header=()
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
if [[ -n "$TOKEN" ]]; then
  auth_header=(-H "Authorization: Bearer ${TOKEN}")
fi

gh_api() {
  # GET GitHub API path relative to /repos/$REPO
  local path="$1"
  curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "${auth_header[@]+"${auth_header[@]}"}" \
    "https://api.github.com/repos/${REPO}${path}"
}

download() {
  # download URL to file (supports private release assets via API Accept)
  local url="$1" out="$2" asset_api="${3:-}"
  if [[ -n "$asset_api" ]]; then
    curl -fsSL \
      -H "Accept: application/octet-stream" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "${auth_header[@]+"${auth_header[@]}"}" \
      -o "$out" \
      "$asset_api"
  else
    curl -fsSL \
      "${auth_header[@]+"${auth_header[@]}"}" \
      -o "$out" \
      "$url"
  fi
}

version_num() {
  # strip leading v
  local v="$1"
  echo "${v#v}"
}

install_from_local() {
  local root
  root="$(cd "$(dirname "$0")/.." && pwd)"
  [[ -d "$root/bin" ]] || die "no $root/bin — run: make build"

  install -d "$BIN_DIR"
  if [[ "$CTL_ONLY" -eq 0 ]]; then
    [[ -x "$root/bin/wireguardd" ]] || die "missing $root/bin/wireguardd"
    install -m 0755 "$root/bin/wireguardd" "${BIN_DIR}/wireguardd"
    log "installed ${BIN_DIR}/wireguardd"
  fi
  if [[ "$DAEMON_ONLY" -eq 0 ]]; then
    [[ -x "$root/bin/wireguardctl" ]] || die "missing $root/bin/wireguardctl"
    install -m 0755 "$root/bin/wireguardctl" "${BIN_DIR}/wireguardctl"
    log "installed ${BIN_DIR}/wireguardctl"
  fi

  if [[ "$CTL_ONLY" -eq 0 && -f "$root/configs/wireguardd.example.yaml" ]]; then
    install -d /etc/wireguardd
    if [[ ! -f /etc/wireguardd/config.yaml ]]; then
      install -m 0600 "$root/configs/wireguardd.example.yaml" /etc/wireguardd/config.yaml
      log "wrote /etc/wireguardd/config.yaml — set auth.token before starting"
    fi
  fi
  if [[ "$CTL_ONLY" -eq 0 && "$INSTALL_SYSTEMD" -eq 1 && -d /etc/systemd/system && -f "$root/deploy/wireguardd.service" ]]; then
    install -d /var/lib/wireguardd
    install -m 0644 "$root/deploy/wireguardd.service" /etc/systemd/system/wireguardd.service
    systemctl daemon-reload || true
    log "systemd unit installed — systemctl enable --now wireguardd"
  fi
}

install_from_release() {
  need_cmd jq || {
    # minimal jq-less path: use github latest redirect + fixed asset names after resolving tag
    warn "jq not found; using simple latest-tag resolution"
  }

  local tag ver api_json asset_json
  if [[ "$VERSION" == "latest" ]]; then
    log "resolving latest release from ${REPO}"
    if command -v jq >/dev/null 2>&1; then
      api_json="$(gh_api /releases/latest)"
      tag="$(printf '%s' "$api_json" | jq -r .tag_name)"
    else
      # follow redirect Location for /releases/latest
      tag="$(curl -fsSLI "${auth_header[@]+"${auth_header[@]}"}" \
        "https://github.com/${REPO}/releases/latest" \
        | tr -d '\r' | awk -F'/tag/' '/^location:/ {print $2; exit}')"
      tag="${tag%%[[:space:]]*}"
    fi
    [[ -n "$tag" && "$tag" != "null" ]] || die "could not resolve latest release (private repo? set GITHUB_TOKEN)"
  else
    tag="$VERSION"
    [[ "$tag" == v* ]] || tag="v${tag}"
  fi
  ver="$(version_num "$tag")"
  log "installing ${tag} (${OS}/${ARCH})"

  local work
  work="$(mktemp -d "${TMPDIR_BASE}/wireguardd-install.XXXXXX")"
  trap 'rm -rf "$work"' EXIT

  # Prefer GitHub API asset download (works for private repos with token)
  local d_name c_name
  d_name="wireguardd_${ver}_linux_${ARCH}.tar.gz"
  c_name="wireguardctl_${ver}_${OS}_${ARCH}.tar.gz"

  fetch_asset() {
    local want_name="$1" dest="$2"
    if command -v jq >/dev/null 2>&1; then
      asset_json="$(gh_api "/releases/tags/${tag}")"
      local id url
      id="$(printf '%s' "$asset_json" | jq -r --arg n "$want_name" '.assets[] | select(.name==$n) | .id')"
      url="$(printf '%s' "$asset_json" | jq -r --arg n "$want_name" '.assets[] | select(.name==$n) | .url')"
      [[ -n "$id" && "$id" != "null" ]] || die "asset not found in release ${tag}: ${want_name}"
      download "" "$dest" "https://api.github.com/repos/${REPO}/releases/assets/${id}"
    else
      # public browser download URL
      local browser="https://github.com/${REPO}/releases/download/${tag}/${want_name}"
      download "$browser" "$dest" || die "download failed: ${browser}"
    fi
  }

  install -d "$BIN_DIR"

  if [[ "$CTL_ONLY" -eq 0 ]]; then
    [[ "$OS" == "linux" ]] || die "daemon only available on Linux"
    log "downloading ${d_name}"
    fetch_asset "$d_name" "${work}/${d_name}"
    tar -xzf "${work}/${d_name}" -C "$work"
    # tarball may extract flat or into a dir
    local dbin
    dbin="$(find "$work" -type f -name wireguardd | head -n1)"
    [[ -n "$dbin" ]] || die "wireguardd binary missing from archive"
    install -m 0755 "$dbin" "${BIN_DIR}/wireguardd"
    log "installed ${BIN_DIR}/wireguardd"

    # configs from archive if present
    local ex
    ex="$(find "$work" -type f -name 'wireguardd.example.yaml' | head -n1 || true)"
    install -d /etc/wireguardd /var/lib/wireguardd
    if [[ -n "$ex" && ! -f /etc/wireguardd/config.yaml ]]; then
      install -m 0600 "$ex" /etc/wireguardd/config.yaml
      log "wrote /etc/wireguardd/config.yaml — set auth.token before starting"
    fi
    if [[ "$INSTALL_SYSTEMD" -eq 1 && -d /etc/systemd/system ]]; then
      local unit
      unit="$(find "$work" -type f -name 'wireguardd.service' | head -n1 || true)"
      if [[ -n "$unit" ]]; then
        install -m 0644 "$unit" /etc/systemd/system/wireguardd.service
        systemctl daemon-reload || true
        log "systemd unit installed — systemctl enable --now wireguardd"
      fi
    fi
  fi

  if [[ "$DAEMON_ONLY" -eq 0 ]]; then
    log "downloading ${c_name}"
    fetch_asset "$c_name" "${work}/${c_name}"
    tar -xzf "${work}/${c_name}" -C "$work"
    local cbin
    cbin="$(find "$work" -type f -name wireguardctl | head -n1)"
    [[ -n "$cbin" ]] || die "wireguardctl binary missing from archive"
    install -m 0755 "$cbin" "${BIN_DIR}/wireguardctl"
    log "installed ${BIN_DIR}/wireguardctl"
  fi

  # optional checksum verify if checksums.txt available
  if command -v sha256sum >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    if fetch_asset "checksums.txt" "${work}/checksums.txt" 2>/dev/null; then
      log "verifying checksums"
      (
        cd "$work"
        # only check the archives we downloaded
        grep -E "wireguard(d|ctl)_${ver}_" checksums.txt 2>/dev/null | while read -r sum file; do
          [[ -f "$file" ]] || continue
          echo "${sum}  ${file}" | sha256sum -c - || die "checksum failed: ${file}"
        done
      ) || true
    fi
  fi
}

# --- main ---
log "wireguardd installer · repo=${REPO} · ${OS}/${ARCH}"

if [[ "$LOCAL" -eq 1 ]]; then
  install_from_local
else
  # prefer local bins if present and no explicit remote intent
  if [[ -x "./bin/wireguardd" || -x "./bin/wireguardctl" ]] && [[ "${FORCE_REMOTE:-0}" != "1" ]]; then
    if [[ -d .git || -f go.mod ]]; then
      log "detected local build tree — use --local to install from ./bin, or FORCE_REMOTE=1 for GitHub"
    fi
  fi
  install_from_release
fi

echo
log "done."
if command -v wireguardd >/dev/null 2>&1; then
  wireguardd version 2>/dev/null || "${BIN_DIR}/wireguardd" version 2>/dev/null || true
fi
if command -v wireguardctl >/dev/null 2>&1; then
  wireguardctl version 2>/dev/null || "${BIN_DIR}/wireguardctl" version 2>/dev/null || true
fi
echo
echo "Next steps (Linux daemon):"
echo "  1. Edit /etc/wireguardd/config.yaml  (set auth.token)"
echo "  2. sudo systemctl enable --now wireguardd"
echo "  3. wireguardctl iface list"
echo
echo "Docs: https://github.com/${REPO}#readme"
