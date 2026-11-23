#!/usr/bin/env bash
#==============================================================================
# Supported OS: Ubuntu from version >=22.04 , Debian 12+, Kali Linux
# Requirements: systemd, kernel >= 5.8 with BTF, Python >= 3.10, Docker,
#               Falco >= 0.38 (config.d / rules.d support).
#   sudo ./install_sentinel_falco.sh [--enforce] [--port N] [--dry-run] [--verbose]
#   sudo ./install_sentinel_falco.sh --uninstall [--yes]
set -euo pipefail
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

DETECTION=true
PORT_FLAG=""
DRY=false
VERBOSE=false
UNINSTALL=false
ASSUME_YES=false
MIN_FALCO="0.38"

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1024 && 10#$1 <= 65535 )); }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enforce)    DETECTION=false ;;
    --dry-run)    DRY=true ;;
    --verbose|-v) VERBOSE=true ;;
    --uninstall)  UNINSTALL=true ;;
    --yes|-y)     ASSUME_YES=true ;;
    --port)
      [[ -n "${2:-}" ]] || { echo -e "${RED}[!] --port needs a value.${NC}" >&2; exit 1; }
      PORT_FLAG="$2"; shift ;;
    -h|--help) echo "Usage: $0 [--enforce] [--port N] [--dry-run] [--verbose] | $0 --uninstall [--yes]"; exit 0 ;;
    *) echo -e "${RED}[!] Unknown option: $1${NC}" >&2; exit 1 ;;
  esac
  shift
done
if [[ -n "$PORT_FLAG" ]] && ! valid_port "$PORT_FLAG"; then
  echo -e "${RED}[!] Invalid port '$PORT_FLAG' (use 1024-65535).${NC}" >&2; exit 1
fi

[[ $EUID -eq 0 ]] || { echo -e "${RED}[!] Execute as root with sudo.${NC}"; exit 1; }

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf
APT="apt-get install -y -qq -o Dpkg::Options::=--force-confold -o Acquire::Retries=3"

INSTALL_DIR=/opt/Sentinel_Falco
DATA_DIR=/var/lib/Sentinel_Falco
COLLECT_INFO="$DATA_DIR/AUDIT"
FALCO_CONFIG=/etc/falco/config.d/configfalco.yaml
FALCO_RULES=/etc/falco/rules.d/rules_detection_falco.yaml
POLICY_NAME=policy_rules_defined.yaml
APT_KEYRING=/etc/apt/keyrings/verify_repo_install.gpg
APT_LIST=/etc/apt/sources.list.d/falcosecurity.list
NOTIFY_SCRIPT=/usr/local/bin/sentinel-notify.sh
LOGROTATE_CONF=/etc/logrotate.d/sentinel-falco
CLEANUP_SCRIPT=/usr/local/bin/sentinel-cleanup.sh
CLEANUP_UNIT=/etc/systemd/system/sentinel-cleanup.service
CLEANUP_TIMER=/etc/systemd/system/sentinel-cleanup.timer
ENV_FILE=/etc/falco-guard.env
RETENTION_DAYS=30

say()  { echo -e "\033[0;34m[${1:-INFO}]\033[0m ${2:-}"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
die()  { echo -e "${RED}[!] $1${NC}" >&2; exit 1; }
dbg()  { $VERBOSE && echo -e "${CYAN}[dbg]${NC} $1" || true; }

# --- staging: everything generated lands here and is validated before commit ---
STAGE="$(mktemp -d /tmp/sentinel-falco.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT
MANIFEST="$STAGE/.manifest"
: > "$MANIFEST"

stage_file() {  # $1 = mode, $2 = final destination -> echoes staging path
  local mode="$1" dest="$2" tmp="$STAGE$2"
  mkdir -p "$(dirname "$tmp")"
  printf '%s\t%s\n' "$mode" "$dest" >> "$MANIFEST"
  printf '%s' "$tmp"
}

commit_files() {
  local mode dest
  while IFS=$'\t' read -r mode dest; do
    [[ -n "$dest" ]] || continue
    if $DRY; then
      printf '    %s  ->  %s\n' "$mode" "$dest"
    else
      install -D -m "$mode" "$STAGE$dest" "$dest"
      dbg "committed $dest"
    fi
  done < "$MANIFEST"
}

#==============================================================================
# Uninstall path
#==============================================================================
if $UNINSTALL; then
  say "UNINSTALL" "Removing Sentinel_Falco (Falco itself and Docker are kept)"
  if ! $ASSUME_YES; then
    read -r -p "Confirm removal of $INSTALL_DIR, $DATA_DIR and the guard services? [y/N] " a
    [[ "${a,,}" == "y" ]] || { echo "Aborted."; exit 0; }
  fi
  for u in falco-guard.service sentinel-notify.service sentinel-cleanup.timer sentinel-cleanup.service; do
    systemctl disable --now "$u" 2>/dev/null || true
  done
  systemctl daemon-reload
  rm -f /etc/systemd/system/falco-guard.service /etc/systemd/system/sentinel-notify.service \
        "$CLEANUP_UNIT" "$CLEANUP_TIMER" "$NOTIFY_SCRIPT" "$CLEANUP_SCRIPT" \
        "$ENV_FILE" "$LOGROTATE_CONF" "$FALCO_CONFIG" "$FALCO_RULES" "$FALCO_RULES.new"
  rm -rf "$INSTALL_DIR" "$DATA_DIR"
  say "UNINSTALL" "Guard removed. The Falco package, its repo ($APT_LIST) and the keyring were left in place."
  say "UNINSTALL" "Remove them with: apt-get remove falco && rm -f $APT_LIST $APT_KEYRING && apt-get update -qq"
  exit 0
fi

$DRY && say "DRY-RUN" "${YELLOW}No changes will be applied; the file plan is printed at the end.${NC}"

#==============================================================================
# OS detection
#==============================================================================
OS_ID="$( . /etc/os-release 2>/dev/null && echo "${ID:-unknown}" || echo unknown )"
OS_LIKE="$( . /etc/os-release 2>/dev/null && echo "${ID_LIKE:-}" || true )"
OS_NAME="$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$OS_ID}" || echo "$OS_ID" )"
OS_VERSION="$( . /etc/os-release 2>/dev/null && echo "${VERSION_ID:-0}" || echo 0 )"
case " $OS_ID $OS_LIKE " in
  *" ubuntu "*|*" debian "*|*" kali "*) ;;
  *) die "Unsupported distribution: $OS_NAME. Supported: Ubuntu, Debian, Kali (or apt-based derivative)." ;;
esac
if [[ "$OS_ID" == "ubuntu" ]]; then
  [[ "$OS_VERSION" =~ ^[0-9]+(\.[0-9]+)?$ ]] || OS_VERSION=0
  IFS=. read -r _m
