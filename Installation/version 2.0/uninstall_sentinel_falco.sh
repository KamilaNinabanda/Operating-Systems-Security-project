#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

say()  { echo -e "\033[0;34m[${1:-INFO}]\033[0m ${2:-}"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
die()  { echo -e "\033[0;31m[!] $1\033[0m" >&2; exit 1; }

ASSUME_YES=false
PURGE_FALCO=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)       ASSUME_YES=true ;;
    --purge-falco)  PURGE_FALCO=true ;;
    -h|--help)
      echo "Usage: $0 [--yes] [--purge-falco]"
      exit 0 ;;
    *) echo -e "${RED}[!] Unknown option: $1${NC}" >&2; exit 1 ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || die "Execute as root with sudo."

# --- Must match install_sentinel_falco.sh exactly ---
INSTALL_DIR=/opt/Sentinel_Falco
DATA_DIR=/var/lib/Sentinel_Falco
FALCO_CONFIG=/etc/falco/config.d/configfalco.yaml
FALCO_RULES=/etc/falco/rules.d/rules_detection_falco.yaml
APT_KEYRING=/etc/apt/keyrings/verify_repo_install.gpg
APT_LIST=/etc/apt/sources.list.d/falcosecurity.list
ENV_FILE=/etc/falco-guard.env
NOTIFY_SCRIPT=/usr/local/bin/sentinel-notify.sh
CLEANUP_SCRIPT=/usr/local/bin/sentinel-cleanup.sh
LOGROTATE_CONF=/etc/logrotate.d/sentinel-falco
UNITS="falco-guard.service sentinel-notify.service sentinel-cleanup.service sentinel-cleanup.timer"

say "UNINSTALL" "${BLUE}Removing Sentinel_Falco (the Falco package and Docker are kept unless --purge-falco is given)${NC}"

# Warn about containers that would stay frozen once the guard that can release them is gone.
if [[ -s "$DATA_DIR/state.json" ]] && grep -q '"name"' "$DATA_DIR/state.json" 2>/dev/null; then
  warn "Some containers are recorded as isolated (paused / network-detached):"
  if command -v jq >/dev/null 2>&1; then
    jq -r 'to_entries[] | "  - " + .value.name + " (" + (.value.done | join(",")) + ")"' "$DATA_DIR/state.json" 2>/dev/null || true
  fi
  warn "Release them first with the guard still running, e.g.:"
  if [[ -f "$ENV_FILE" ]]; then
    TOKEN="$(sed -n 's/^GUARD_TOKEN=//p' "$ENV_FILE" | head -n 1)"
    PORT="$(sed -n 's/^GUARD_PORT=//p' "$ENV_FILE" | head -n 1)"
    warn "  curl -X POST -H \"X-Guard-Token: ${TOKEN:-<token>}\" http://127.0.0.1:${PORT:-8080}/release/<name_or_id>"
  fi
  warn "Otherwise they stay paused / without network after this uninstall; release them by hand afterwards with 'docker unpause' / 'docker network connect'."
fi

if ! $ASSUME_YES; then
  read -r -p "Remove $INSTALL_DIR, $DATA_DIR (alerts and forensic evidence included) and the services? [y/N] " a
  [[ "${a,,}" == "y" ]] || { echo "Aborted."; exit 0; }
fi

say "STOP" "Disabling services"
for u in $UNITS; do
  systemctl disable --now "$u" >/dev/null 2>&1 || true
done

say "REMOVE" "Deleting units, scripts, config and data"
rm -f /etc/systemd/system/falco-guard.service \
      /etc/systemd/system/sentinel-notify.service \
      /etc/systemd/system/sentinel-cleanup.service \
      /etc/systemd/system/sentinel-cleanup.timer
rm -f "$NOTIFY_SCRIPT" "$CLEANUP_SCRIPT" "$ENV_FILE" "$LOGROTATE_CONF"
rm -f "$FALCO_CONFIG" "$FALCO_RULES" "$FALCO_RULES.new"
rm -rf "$INSTALL_DIR" "$DATA_DIR"

systemctl daemon-reload
ok "Guard, services, config, evidence and alerts removed."

# Falco still points at the now-removed guard (http_output): restart so it drops that config
# cleanly, rather than leaving it trying to POST to a port nothing is listening on.
if systemctl list-unit-files 2>/dev/null | grep -q '^falco-modern-bpf.service'; then
  systemctl restart falco-modern-bpf.service 2>/dev/null || warn "Could not restart falco-modern-bpf; restart it by hand if needed."
fi

if $PURGE_FALCO; then
  say "PURGE" "Removing the Falco package and its repository"
  apt-get remove -y -qq falco 2>/dev/null || warn "Could not remove the falco package (continuing)."
  rm -f "$APT_LIST" "$APT_KEYRING"
  apt-get update -qq || true
  ok "Falco package and repository removed."
else
  say "KEPT" "Falco itself (package, repo, keyring) was left installed."
fi

cat <<EOM

===========================================================================
 Sentinel_Falco uninstalled.
===========================================================================
Docker containers that were isolated while the guard was running are NOT
touched by this script beyond the warning above -- check with:
  docker ps -a --filter status=paused
  docker inspect <container> --format '{{.NetworkSettings.Networks}}'
EOM
