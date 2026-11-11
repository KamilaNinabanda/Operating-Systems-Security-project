#!/usr/bin/env bash
# ==============================================================================
# Uninstaller for the guard installed by the first installer (v1, "falco-guard"),
# or by the renamed one ("Sentinel_Falco") with --sentinel.
#
#   sudo ./uninstall_sentinel_falco.sh --dry-run        # show what would be done, change nothing
#   sudo ./uninstall_sentinel_falco.sh                  # remove the v1 guard (asks for confirmation)
#   sudo ./uninstall_sentinel_falco.sh --sentinel       # remove the renamed Sentinel_Falco guard
#
# What it does, in this order:
#   1. Releases every container the guard left isolated (unpause / reconnect networks / start),
#      so no container stays frozen or cut off after the guard is gone.
#   2. Stops and removes the falco-guard service and /etc/falco-guard.env (it holds the token).
#   3. Removes the guard's Falco rules file and Falco HTTP-output config, and restarts Falco
#      so it stops sending events to a service that no longer exists.
#   4. Removes the program directory (code + Python venv).
#   5. Keeps the data directory (alerts.jsonl, state.json, evidence snapshots) unless --purge-data.
#
# It NEVER removes Docker. It only removes Falco itself with --remove-falco.
# ==============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Test hook: when set, every path is resolved inside this directory and root is not required.
# Leave it empty in real use.
P="${UNINSTALL_PREFIX:-}"

usage() {
  cat <<'EOF'
Usage: uninstall_sentinel_falco.sh [options]

  --v1            Remove the first installation: /opt/falco-guard, /var/lib/falco-guard (default)
  --sentinel      Remove the renamed installation: /opt/Sentinel_Falco, /var/lib/Sentinel_Falco
  --purge-data    Also delete the data directory (alerts, state and evidence snapshots)
  --remove-falco  Also uninstall the Falco package and its repository (Docker is never touched)
  -y, --yes       Do not ask for confirmation
  --dry-run       Only print what would be done
  -h, --help      Show this help
EOF
}

SCHEME=v1; PURGE_DATA=false; REMOVE_FALCO=false; ASSUME_YES=false; DRY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --v1)           SCHEME=v1 ;;
    --sentinel)     SCHEME=sentinel ;;
    --purge-data)   PURGE_DATA=true ;;
    --remove-falco) REMOVE_FALCO=true ;;
    -y|--yes)       ASSUME_YES=true ;;
    --dry-run)      DRY=true ;;
    -h|--help)      usage; exit 0 ;;
    *)              echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
  shift
done

[[ $EUID -eq 0 || -n "$P" ]] || { echo -e "${RED}[!] Execute as root with sudo.${NC}" >&2; exit 1; }

# --- Paths of each layout -----------------------------------------------------
case "$SCHEME" in
  v1)
    INSTALL_DIR=/opt/falco-guard
    DATA_DIR=/var/lib/falco-guard
    RULES=/etc/falco/rules.d/guard_rules.yaml
    CONFIG=/etc/falco/config.d/guard.yaml
    ;;
  sentinel)
    INSTALL_DIR=/opt/Sentinel_Falco
    DATA_DIR=/var/lib/Sentinel_Falco
    RULES=/etc/falco/rules.d/rules_detection_falco.yaml
    CONFIG=/etc/falco/config.d/configfalco.yaml
    ;;
esac
# Both layouts share the service name and the env file
SERVICE=/etc/systemd/system/falco-guard.service
ENV_FILE=/etc/falco-guard.env

WARNINGS=0
step() { echo -e "\n${BLUE}== $* ==${NC}"; }
ok()   { echo -e "  ${GREEN}ok${NC}   $*"; }
warn() { echo -e "  ${YELLOW}warn${NC} $*"; WARNINGS=$((WARNINGS+1)); }
run()  { if $DRY; then echo "  [dry-run] $*"; return 0; fi; "$@"; }

# --- What is installed? -------------------------------------------------------
FOUND=false
for path in "$P$INSTALL_DIR" "$P$DATA_DIR" "$P$RULES" "$P$CONFIG"; do
  [[ -e "$path" ]] && FOUND=true
done
UNIT_IS_MINE=false
if [[ -f "$P$SERVICE" ]] && grep -q "$INSTALL_DIR" "$P$SERVICE"; then UNIT_IS_MINE=true; FOUND=true; fi
if ! $FOUND; then
  echo "Nothing from the '$SCHEME' layout was found on this machine."
  [[ $SCHEME == v1 ]] && echo "If you installed the renamed version, run again with --sentinel."
  exit 0
fi

echo -e "${BLUE}Sentinel_Falco uninstaller${NC}  (layout: $SCHEME)$($DRY && echo '  [DRY RUN]')"
echo "This will:"
echo "  - release containers left isolated by the guard"
$UNIT_IS_MINE && echo "  - stop and remove $SERVICE and $ENV_FILE (the token is deleted)"
echo "  - remove $RULES and $CONFIG and restart Falco"
echo "  - remove $INSTALL_DIR"
if $PURGE_DATA; then echo "  - DELETE $DATA_DIR (alerts, state and evidence)"; else echo "  - keep $DATA_DIR"; fi
$REMOVE_FALCO && echo "  - uninstall the Falco package and its repository"
echo "  - leave Docker untouched"
if ! $ASSUME_YES && ! $DRY; then
  read -r -p "Continue? [y/N] " answer
  [[ $answer =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 1; }
fi

# --- 1. Release isolated containers ------------------------------------------
step "1. Releasing isolated containers"
release_isolated() {
  local state="$P$DATA_DIR/state.json" lines
  [[ -s "$state" ]] || { ok "no isolated containers recorded"; return; }
  command -v docker >/dev/null 2>&1 || { warn "docker not found: cannot release the containers listed in $state"; return; }
  command -v python3 >/dev/null 2>&1 || { warn "python3 not found: cannot read $state"; return; }
  lines=$(python3 - "$state" <<'PY'
import json, sys
try:
    state = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
for cid, rec in state.items():
    print("\t".join([cid, rec.get("name", ""), ",".join(rec.get("done", [])), ",".join(rec.get("networks", []))]))
PY
)
  [[ -n "$lines" ]] || { ok "state file has no isolated containers"; return; }
  while IFS=$'\t' read -r cid name steps nets; do
    if ! docker inspect "$cid" >/dev/null 2>&1; then
      warn "container $name ($cid) no longer exists: skipped"; continue
    fi
    if [[ ",$steps," == *",stop,"* ]]; then run docker start "$cid" >/dev/null || warn "could not start $name"; fi
    if [[ "$(docker inspect -f '{{.State.Paused}}' "$cid" 2>/dev/null)" == "true" ]]; then
      run docker unpause "$cid" >/dev/null || warn "could not unpause $name"
    fi
    if [[ ",$steps," == *",network,"* ]]; then
      local n
      for n in ${nets//,/ }; do
        run docker network connect "$n" "$cid" >/dev/null 2>&1 || true   # already connected is fine
      done
    fi
    ok "released $name"
  done <<< "$lines"
}
release_isolated

# --- 2. Service and env file ---------------------------------------------------
step "2. Service and token"
if $UNIT_IS_MINE; then
  run systemctl disable --now falco-guard.service >/dev/null 2>&1 || true
  run rm -f "$P$SERVICE" "$P$ENV_FILE"
  run systemctl daemon-reload
  run systemctl reset-failed falco-guard.service >/dev/null 2>&1 || true
  ok "falco-guard service and $ENV_FILE removed"
elif [[ -f "$P$SERVICE" ]]; then
  warn "$SERVICE belongs to the other layout: left in place (as is $ENV_FILE)"
else
  ok "no falco-guard service found"
fi

# --- 3. Falco rules and config -------------------------------------------------
step "3. Falco rules and HTTP output"
run rm -f "$P$RULES" "$P$CONFIG"
ok "removed $RULES and $CONFIG"
if ! $REMOVE_FALCO && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet falco-modern-bpf.service 2>/dev/null; then
  run systemctl restart falco-modern-bpf.service || warn "could not restart falco-modern-bpf.service"
  ok "Falco restarted without the guard's rules and HTTP output"
fi

# --- 4. Program directory and data ---------------------------------------------
step "4. Program files and data"
if [[ -d "$P$INSTALL_DIR" ]]; then run rm -rf "$P$INSTALL_DIR"; ok "removed $INSTALL_DIR"; else ok "$INSTALL_DIR not present"; fi
if [[ -d "$P$DATA_DIR" ]]; then
  if $PURGE_DATA; then
    run rm -rf "$P$DATA_DIR"; ok "deleted $DATA_DIR"
  else
    ok "kept $DATA_DIR ($(du -sh "$P$DATA_DIR" 2>/dev/null | cut -f1)): delete it with  sudo rm -rf $DATA_DIR"
  fi
fi

# --- 5. Falco package (optional) -----------------------------------------------
if $REMOVE_FALCO; then
  step "5. Removing Falco"
  for unit in falco-modern-bpf falco-bpf falco-kmod falco; do
    run systemctl disable --now "$unit.service" >/dev/null 2>&1 || true
  done
  if command -v apt-get >/dev/null 2>&1; then
    run apt-get purge -y falco || warn "apt could not purge falco"
  elif command -v dnf >/dev/null 2>&1; then
    run dnf remove -y falco || warn "dnf could not remove falco"
  else
    warn "no apt-get or dnf found: remove the falco package by hand"
  fi
  run rm -f "$P/etc/apt/sources.list.d/falcosecurity.list" "$P/etc/yum.repos.d/falcosecurity.repo" \
            "$P/etc/apt/keyrings/falco-archive-keyring.gpg" "$P/etc/apt/keyrings/verify_repo_install.gpg"
  ok "Falco package and repository removed"
fi

# --- Verification --------------------------------------------------------------
if ! $DRY; then
  step "Verification"
  leftovers=()
  for path in "$INSTALL_DIR" "$RULES" "$CONFIG"; do [[ -e "$P$path" ]] && leftovers+=("$path"); done
  $UNIT_IS_MINE && for path in "$SERVICE" "$ENV_FILE"; do [[ -e "$P$path" ]] && leftovers+=("$path"); done
  if ((${#leftovers[@]})); then warn "still present: ${leftovers[*]}"; else ok "none of the guard's files remain"; fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet falco-guard.service 2>/dev/null && $UNIT_IS_MINE; then
    warn "falco-guard.service is still active"
  else
    ok "falco-guard service is not running"
  fi
  if command -v ss >/dev/null 2>&1 && [[ -z "$P" ]] && ss -ltn 2>/dev/null | grep -qE '127\.0\.0\.1:8080\b'; then
    warn "something is still listening on 127.0.0.1:8080"
  fi
  if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx victim; then
    echo -e "  note: the test container 'victim' from the installer's example still exists:  docker rm -f victim"
  fi
fi

echo
if $DRY; then
  echo "Dry run finished: nothing was changed."
elif ((WARNINGS)); then
  echo -e "${YELLOW}Finished with $WARNINGS warning(s). Review the lines marked 'warn'.${NC}"
else
  echo -e "${GREEN}Uninstall finished.${NC}"
fi
echo "Docker was not touched$($REMOVE_FALCO || echo ', and Falco is still installed')."
