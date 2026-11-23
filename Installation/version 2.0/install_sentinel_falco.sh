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
    --enforce)   DETECTION=false ;;
    --dry-run)   DRY=true ;;
    --verbose|-v) VERBOSE=true ;;
    --uninstall) UNINSTALL=true ;;
    --yes|-y)    ASSUME_YES=true ;;
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
  say "UNINSTALL" "Guard removed. Falco package, its repo ($APT_LIST) and the keyring were left in place."
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
  IFS=. read -r _maj _min <<< "$OS_VERSION"
  if ! (( 10#${_maj:-0} > 22 || (10#${_maj:-0} == 22 && 10#${_min:-0} >= 4) )); then
    die "Ubuntu $OS_VERSION is not supported: 22.04 or newer required."
  fi
fi
IS_KALI=false
[[ "$OS_ID" == "kali" ]] && IS_KALI=true

say "Step 1 of 8" "Validating system, kernel, systemd and port"
$IS_KALI && say "KALI" "${CYAN}Kali detected: $OS_NAME${NC}"

WSL_NOTE=""
grep -qi microsoft /proc/version 2>/dev/null && \
  WSL_NOTE=" WSL detected: default WSL kernels lack BTF and need systemd ([boot] systemd=true)."
[[ -f /sys/kernel/btf/vmlinux ]] || die "Missing /sys/kernel/btf/vmlinux: modern_ebpf won't work (kernel $(uname -r)).$WSL_NOTE"
[[ -d /run/systemd/system ]]    || die "systemd is not running.$WSL_NOTE"

# Port selection: default 18080 so we do not collide with Burp, ZAP or Docker.
OLD_PORT=""
[[ -f "$ENV_FILE" ]] && OLD_PORT="$(sed -n 's/^GUARD_PORT=//p' "$ENV_FILE" | head -n 1)"
PORT="${PORT_FLAG:-${OLD_PORT:-18080}}"
valid_port "$PORT" || die "Invalid port '$PORT' (check GUARD_PORT in $ENV_FILE)."
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
docker_publishes() {
  command -v docker >/dev/null 2>&1 || return 1
  docker ps --format '{{.Ports}}' 2>/dev/null | grep -qE "(:|^)${1}->"
}
if port_in_use "$PORT"; then
  if systemctl is-active --quiet falco-guard.service 2>/dev/null && [[ "$PORT" == "${OLD_PORT:-}" ]]; then
    say "PORT" "127.0.0.1:$PORT belongs to the running falco-guard (reinstall)."
  else
    die "Port $PORT is already in use. Choose another: sudo $0 --port 18080"
  fi
elif docker_publishes "$PORT"; then
  warn "Port $PORT looks published by a Docker container; pick another if the health check fails."
fi

say "Step 2 of 8" "Installing dependencies"
command -v apt-get >/dev/null || die "This installer only supports Debian/Ubuntu (apt)."
if $DRY; then
  say "DRY-RUN" "skipping apt-get update/install"
else
  apt-get update -qq
  $APT ca-certificates curl gnupg openssl python3 python3-venv jq
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
  || die "Python >= 3.10 required (found $(python3 -V 2>&1))."

say "Step 3 of 8" "Verifying Docker"
DOCKER_INSTALL_HINT=""
DOCKER_START_HINT="sudo systemctl start docker"
if $IS_KALI; then
  DOCKER_INSTALL_HINT=" On Kali: sudo apt install docker.io"
  DOCKER_START_HINT="sudo systemctl enable --now docker"
fi
command -v docker >/dev/null 2>&1 || die "Docker is not installed.$DOCKER_INSTALL_HINT"
systemctl is-active --quiet docker || systemctl is-active --quiet snap.docker.dockerd \
  || die "Docker service is not running: $DOCKER_START_HINT"
docker info >/dev/null 2>&1 || die "Cannot talk to the Docker daemon."
ok "Docker is installed and functional."

say "Step 4 of 8" "Installing/verifying Falco (>= $MIN_FALCO)"
falco_version() {
  falco --version 2>/dev/null | sed -n 's/.*[Vv]ersion[: ]*\([0-9]\+\.[0-9]\+\).*/\1/p' | head -n 1
}
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]; }

if ! command -v falco >/dev/null; then
  if $DRY; then
    say "DRY-RUN" "would add the Falco repository and install the package"
  else
    [[ -d /etc/apt/keyrings ]] || install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --batch --dearmor --yes -o "$APT_KEYRING"
    chmod 644 "$APT_KEYRING"
    echo "deb [signed-by=$APT_KEYRING] https://download.falco.org/packages/deb stable main" > "$APT_LIST"
    chmod 644 "$APT_LIST"
    apt-get update -qq
    $APT falco
  fi
fi
if command -v falco >/dev/null; then
  FVER="$(falco_version || true)"
  if [[ -z "$FVER" ]] || ! ver_ge "$FVER" "$MIN_FALCO"; then
    die "Falco ${FVER:-unknown} is too old: >= $MIN_FALCO is required (config.d/rules.d are ignored otherwise). Upgrade: sudo apt-get install --only-upgrade falco"
  fi
  ok "Falco $FVER detected."
fi

say "Step 5 of 8" "Deploying Sentinel_Falco in $INSTALL_DIR"
$DRY || mkdir -p "$INSTALL_DIR/guard" "$INSTALL_DIR/config" /etc/falco/rules.d /etc/falco/config.d
$DRY || { install -d -m 700 "$DATA_DIR"; install -d -m 700 "$COLLECT_INFO"; }

GUARD_INIT="$(stage_file 600 "$INSTALL_DIR/guard/__init__.py")"
: > "$GUARD_INIT"

GUARD_POLICY="$(stage_file 600 "$INSTALL_DIR/guard/policy.py")"
cat > "$GUARD_POLICY" <<'__GUARD_EOF__'
"""Decision engine: ignore, alert or isolate."""
import logging
from dataclasses import dataclass

import yaml

log = logging.getLogger("guard.policy")

VALID_ACTIONS = ("alert", "isolate")


@dataclass
class DecisionActions:
    action: str
    reason: str


class Policies:
    def __init__(self, cfg: dict):
        self.cfg = cfg if isinstance(cfg, dict) else {}
        rules = self.cfg.get("rules")
        if not isinstance(rules, dict):
            log.critical("policy has no 'rules' mapping: every guard rule will only alert")
            self.cfg["rules"] = {}

    @classmethod
    def from_file(cls, path: str) -> "Policies":
        with open(path) as f:
            return cls(yaml.safe_load(f) or {})

    def _rule_action(self, rule: str) -> str | None:
        entry = self.cfg["rules"].get(rule)
        if entry is None:
            return None
        if isinstance(entry, str):          # tolerate "Rule: isolate"
            return entry
        if isinstance(entry, dict):
            return entry.get("action")
        return None

    def decide(self, event: dict) -> DecisionActions:
        fields = event.get("output_fields") or {}
        if not isinstance(fields, dict):
            fields = {}
        cid = fields.get("container.id")
        if not cid or cid == "host":
            return DecisionActions("ignore", "event outside a container")

        # Only our own rules take part in the decision; the stock ruleset stays noisy otherwise.
        if "guard" not in (event.get("tags") or []):
            return DecisionActions("ignore", "foreign rule")

        rule = event.get("rule") or ""
        action = self._rule_action(rule)
        if action not in VALID_ACTIONS:
            return DecisionActions("alert", f"rule without a valid policy: {rule!r}")
        if action == "isolate":
            return DecisionActions("isolate", f"critical rule: {rule}")
        return DecisionActions("alert", "alert only")
__GUARD_EOF__

GUARD_ISO="$(stage_file 600 "$INSTALL_DIR/guard/isolation_recovery_container.py")"
cat > "$GUARD_ISO" <<'__GUARD_EOF__'
"""Container isolation and recovery via the Docker SDK, with evidence and partial rollback."""
import json
import logging
import os
import threading
import time

import docker

log = logging.getLogger("guard.isolator")

VALID_STEPS = ("network", "pause", "stop")
_STEP_ORDER = {"network": 0, "pause": 1, "stop": 2}


def normalize_steps(steps) -> list[str]:
    """Drop unknown steps, deduplicate and enforce network -> pause -> stop."""
    raw = [s for s in (steps or []) if isinstance(s, str)]
    for s in raw:
        if s not in VALID_STEPS:
            log.warning("unknown isolation step %r ignored", s)
    kept = [s for s in dict.fromkeys(raw) if s in VALID_STEPS]
    if not kept:
        kept = ["network", "pause"]
    kept.sort(key=_STEP_ORDER.get)
    if "stop" in kept and "pause" in kept:
        kept.remove("pause")            # pause is redundant once we stop
    return kept


class ContainerIsolation:
    def __init__(self, steps, detection_mode, data_dir):
        self.steps = normalize_steps(steps)
        self.detection_mode = detection_mode
        self.collect_info = os.path.join(data_dir, "AUDIT")
        self.state_path = os.path.join(data_dir, "state.json")
        os.makedirs(self.collect_info, exist_ok=True)
        self._client = None
        self._lock = threading.Lock()
        self.state = self._load()

    # --- persistence -------------------------------------------------------
    def _load(self) -> dict:
        for path in (self.state_path, self.state_path + ".bak"):
            if not os.path.exists(path):
                continue
            try:
                with open(path) as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except (json.JSONDecodeError, OSError):
                log.error("corrupt state file %s, trying fallback", path)
        return {}

    def _save(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(self.state_path):
            try:
                os.replace(self.state_path, self.state_path + ".bak")
            except OSError:
                pass
        os.replace(tmp, self.state_path)

    # --- docker ------------------------------------------------------------
    @property
    def client(self):
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _find(self, cid: str) -> str | None:
        """Exact id first, then an exact name whose container still exists under that id."""
        if not cid:
            return None
        if cid in self.state:
            return cid
        for key, rec in self.state.items():
            if rec.get("name") != cid:
                continue
            try:
                if self.client.containers.get(key).id == key:
                    return key
            except docker.errors.NotFound:
                continue
            except Exception:
                continue
        return None

    def is_isolated(self, cid: str) -> bool:
        return self._find(cid) is not None

    def prune_stale(self) -> list[str]:
        """Forget entries whose container no longer exists."""
        with self._lock:
            gone = []
            for key in list(self.state):
                try:
                    self.client.containers.get(key)
                except docker.errors.NotFound:
                    gone.append(key)
                except Exception:
                    continue
            if gone:
                for key in gone:
                    self.state.pop(key, None)
                self._save()
                log.info("pruned %d stale isolation record(s)", len(gone))
            return gone

    # --- forensics ---------------------------------------------------------
    def _gatherInfo(self, c) -> str:
        attrs = json.loads(json.dumps(c.attrs))
        attrs["Config"]["Env"] = [
            e.split("=", 1)[0] + "=<redacted>" for e in attrs["Config"].get("Env") or []
        ]
        info = {"inspect": attrs}
        try:
            info["fs_diff"] = c.diff()
        except Exception as e:
            info["fs_diff_error"] = str(e)
        if c.status == "running":
            try:
                info["processes"] = c.top()
            except Exception as e:
                info["processes_error"] = str(e)
        try:
            info["logs_tail"] = c.logs(tail=200).decode(errors="replace")
        except Exception as e:
            info["logs_error"] = str(e)
        path = os.path.join(self.collect_info, f"{c.name}-{int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(info, f, indent=2, default=str)
        os.chmod(path, 0o600)
        return path

    # --- lifecycle ---------------------------------------------------------
    def isolate(self, cid: str, reason: str) -> dict:
        with self._lock:
            existing = self._find(cid)
            if existing:
                return {"status": "already_isolated", "container": self.state[existing].get("name")}
            c = self.client.containers.get(cid)
            try:
                host_net = c.attrs["HostConfig"]["NetworkMode"] == "host"
            except (KeyError, TypeError):
                host_net = False
            nets = list((c.attrs.get("NetworkSettings") or {}).get("Networks") or {})
            steps = [s for s in self.steps if s != "network" or not host_net]
            if host_net and not steps:
                steps = ["pause"]
            if self.detection_mode:
                return {"status": "detection_mode", "container": c.name, "would_do": steps}

            # Evidence must never block containment.
            try:
                forensics = self._gatherInfo(c)
            except Exception:
                log.exception("evidence collection failed for %s", c.name)
                forensics = None

            # Register before touching the container so a crash mid-way is recoverable.
            self.state[c.id] = {
                "name": c.name, "networks": nets, "done": [],
                "reason": reason, "ts": time.time(), "forensics": forensics,
            }
            self._save()

            errors = []
            for step in steps:
                try:
                    if step == "network":
                        if not nets:
                            raise RuntimeError("container has no networks to detach")
                        for n in nets:
                            self.client.networks.get(n).disconnect(c, force=True)
                    elif step == "pause":
                        c.pause()
                    elif step == "stop":
                        c.stop(timeout=5)
                    self.state[c.id]["done"].append(step)
                    self._save()
                except Exception as e:
                    log.exception("isolation step %s failed on %s", step, c.name)
                    errors.append(f"{step}: {e}")

            done = self.state[c.id]["done"]
            if errors and not done:
                status = "failed"
            elif errors:
                status = "partially_isolated"
            else:
                status = "isolated"
            log.warning("container %s -> %s (%s)", c.name, status, done)
            return {"status": status, "container": c.name, "steps": done,
                    "errors": errors, "forensics": forensics}

    def release(self, cid: str) -> dict:
        with self._lock:
            key = self._find(cid)
            if not key:
                return {"status": "not_isolated"}
            rec = self.state[key]
            try:
                c = self.client.containers.get(key)
            except docker.errors.NotFound:
                self.state.pop(key, None)
                self._save()
                return {"status": "container_gone", "container": rec.get("name")}

            errors = []
            if "stop" in rec.get("done", []):
                try:
                    c.start()
                except Exception as e:
                    errors.append(f"start: {e}")
            try:
                c.reload()
                if c.status == "paused":
                    c.unpause()
            except Exception as e:
                errors.append(f"unpause: {e}")
            if "network" in rec.get("done", []):
                for n in rec.get("networks", []):
                    try:
                        self.client.networks.get(n).connect(c)
                    except Exception as e:
                        errors.append(f"connect {n}: {e}")

            if errors:
                return {"status": "partially_released", "container": rec.get("name"), "errors": errors}
            self.state.pop(key, None)
            self._save()
            return {"status": "released", "container": rec.get("name")}
__GUARD_EOF__

GUARD_NOTIFY="$(stage_file 600 "$INSTALL_DIR/guard/notification_alerter.py")"
cat > "$GUARD_NOTIFY" <<'__GUARD_EOF__'
"""Alerts: JSONL log plus non-blocking Slack and generic webhook delivery."""
import json
import logging
import threading
import time

import requests

log = logging.getLogger("guard.notifier")


class Notificationalert:
    def __init__(self, alert_log, slack_url=None, webhook_url=None):
        self.alert_log, self.slack_url, self.webhook_url = alert_log, slack_url, webhook_url

    def _post(self, url, payload):
        try:
            requests.post(url, json=payload, timeout=5)
        except requests.RequestException as e:
            log.error("notification to %s failed: %s", url.split("?")[0], e)

    def send(self, event: dict, decision, result):
        fields = event.get("output_fields") or {}
        alert = {
            "ts": event.get("time") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rule": event.get("rule"), "priority": event.get("priority"),
            "container": fields.get("container.name"),
            "container_id": fields.get("container.id"),
            "image": fields.get("container.image.repository"),
            "file": fields.get("fd.name"), "cmd": fields.get("proc.cmdline"),
            "decision": decision.action, "reason": decision.reason, "isolation": result,
        }
        try:
            with open(self.alert_log, "a") as fh:
                fh.write(json.dumps(alert) + "\n")
        except OSError as e:
            log.error("cannot write alert log: %s", e)
        log.warning("ALERT %s", json.dumps(alert))

        icon = "\U0001F512" if decision.action == "isolate" else "\U0001F6A8"
        text = (f"{icon} *{alert['rule']}* ({alert['priority']})\n"
                f"Container: `{alert['container']}` ({alert['image']})\n"
                f"Details: `{alert['file'] or alert['cmd']}`\n"
                f"Action: *{decision.action}* \u2014 {decision.reason}")
        for url, payload in ((self.slack_url, {"text": text}), (self.webhook_url, alert)):
            if url:
                threading.Thread(target=self._post, args=(url, payload), daemon=True).start()
__GUARD_EOF__

GUARD_MAIN="$(stage_file 600 "$INSTALL_DIR/guard/Main_alert_falco.py")"
cat > "$GUARD_MAIN" <<'__GUARD_EOF__'
"""Falco event receiver -> decision -> alert/isolation."""
import hmac
import logging
import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from .isolation_recovery_container import ContainerIsolation
from .notification_alerter import Notificationalert
from .policy import Policies

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

TOKEN = os.getenv("GUARD_TOKEN", "")
DATA = os.getenv("GUARD_DATA", "/var/lib/Sentinel_Falco")
POLICY = os.getenv("GUARD_POLICY", "/opt/Sentinel_Falco/config/policy_rules_defined.yaml")
os.makedirs(DATA, exist_ok=True)

engine = Policies.from_file(POLICY)
detection_mode = os.getenv(
    "GUARD_DETECTION_MODE", str(engine.cfg.get("detection_mode", False))
).strip().lower() in ("1", "true", "yes")
isolator = ContainerIsolation(engine.cfg.get("isolation"), detection_mode, DATA)
notifier = Notificationalert(os.path.join(DATA, "alerts.jsonl"),
                             os.getenv("SLACK_WEBHOOK_URL"), os.getenv("ALERT_WEBHOOK_URL"))

app = FastAPI(title="Sentinel_Falco", docs_url=None, redoc_url=None, openapi_url=None)


class FalcoEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    time: str | None = None
    rule: str = ""
    priority: str | None = None
    tags: list[str] | None = None
    output_fields: dict[str, Any] | None = None


def require_token(token: str | None = Query(None), x_guard_token: str | None = Header(None)):
    """Header first, query parameter as fallback (Falco sends it in the URL). Fails closed."""
    if not TOKEN:
        logging.critical("GUARD_TOKEN missing: refusing authenticated requests")
        raise HTTPException(503, "Authentication is not configured")
    supplied = x_guard_token if x_guard_token else token
    if not supplied or not hmac.compare_digest(supplied.encode(), TOKEN.encode()):
        raise HTTPException(401, "Invalid authentication token")


@app.post("/falco", dependencies=[Depends(require_token)], status_code=202)
def falco_event(event: FalcoEvent):
    payload = event.model_dump()
    decision = engine.decide(payload)
    if decision.action == "ignore":
        return {"decision": "ignore", "reason": decision.reason}

    result = None
    if decision.action == "isolate":
        cid = (payload.get("output_fields") or {}).get("container.id")
        try:
            result = isolator.isolate(cid, decision.reason)
        except Exception as e:                     # never lose the alert to an isolation error
            logging.exception("isolation failed for %s", cid)
            result = {"status": "error", "error": str(e)}

    # Do not re-notify while the container is already contained.
    if not (isinstance(result, dict) and result.get("status") == "already_isolated"):
        notifier.send(payload, decision, result)
    return {"decision": decision.action, "reason": decision.reason, "isolation": result}


@app.get("/health")
def health():
    return {"status": "ok", "detection_mode": detection_mode, "isolation_steps": isolator.steps}


@app.get("/isolated_container", dependencies=[Depends(require_token)])
def isolated_container():
    isolator.prune_stale()
    return isolator.state


@app.post("/release/{cid}", dependencies=[Depends(require_token)])
def release(cid: str):
    return isolator.release(cid)
__GUARD_EOF__

say "Step 6 of 8" "Creating the virtualenv"
if $DRY; then
  say "DRY-RUN" "skipping venv creation and pip install"
else
  python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
  "$INSTALL_DIR/venv/bin/pip" install -q \
    "fastapi==0.115.*" "uvicorn[standard]==0.32.*" "docker==7.1.*" "PyYAML==6.0.*" "requests==2.32.*"
fi

say "Step 7 of 8" "Generating and validating policy and rules"

# Existing policy is preserved; the new one lands next to it. Rules use a .new suffix
# so Falco does not load both files (duplicate rules break the ruleset).
POLICY_DST="$INSTALL_DIR/config/$POLICY_NAME"
if [[ -f "$POLICY_DST" ]]; then
  POLICY_DST="$POLICY_DST.new"
  warn "$POLICY_NAME already exists and is preserved; the new version goes to $POLICY_DST"
fi
RULES_DST="$FALCO_RULES"
if [[ -f "$RULES_DST" ]]; then
  RULES_DST="$FALCO_RULES.new"
  warn "$FALCO_RULES exists and is preserved; the new version goes to $RULES_DST"
fi

POLICY_FILE="$(stage_file 600 "$POLICY_DST")"
cat > "$POLICY_FILE" <<'__GUARD_EOF__'
# Sentinel_Falco response policy
detection_mode: false        # true = detect and alert only, never isolate (GUARD_DETECTION_MODE overrides)
isolation: [network, pause]  # ordered automatically: network -> pause -> stop

rules:
  # Aggressive rules: full containment.
  "File Modification Escape Attempt":  {action: isolate}
  "Runtime Socket non Authorized":     {action: isolate}
  "NSENTER Execution":                 {action: isolate}
  # Noisy by design: alert first, isolate by hand if it looks real.
  "Host Filesystem non Authorized":    {action: alert}
  "Mount Detection":                   {action: alert}
  "Interactive Shell Active":          {action: alert}
__GUARD_EOF__

RULES_FILE="$(stage_file 644 "$RULES_DST")"
cat > "$RULES_FILE" <<'__GUARD_EOF__'
# Requires Falco >= 0.38.
- macro: guard_open
  condition: (evt.type in (open, openat, openat2) and fd.num >= 0)
- macro: guard_spawn
  condition: (evt.type in (execve, execveat))
- macro: guard_trusted
  condition: (container.image.repository in (falcosecurity/falco, falco-guard))
# runc opens the rootfs while creating a container: noise, not an attack. Narrow exception.
- macro: guard_runc_startup
  condition: >
    (proc.name startswith "runc:" and
     (fd.name startswith /var/lib/docker/rootfs/overlayfs/ or fd.name startswith /var/lib/docker/overlay2/))

- rule: Host Filesystem non Authorized
  desc: A container opens files from host paths
  condition: >
    guard_open and container.id != host and not guard_trusted and not guard_runc_startup and
    (fd.name startswith /host/ or fd.name startswith /hostfs/ or
     fd.name startswith /proc/1/root or fd.name startswith /var/lib/kubelet/ or
     fd.name startswith /var/lib/docker/ or fd.name startswith /var/lib/containerd/)
  output: >
    Access to the host filesystem (file=%fd.name proc=%proc.cmdline user=%user.name
    container=%container.name image=%container.image.repository:%container.image.tag id=%container.id)
  priority: CRITICAL
  tags: [container, host_fs, guard]

- rule: File Modification Escape Attempt
  desc: Writing to typical escape artifacts
  condition: >
    evt.type in (open, openat, openat2) and evt.is_open_write = true and
    container.id != host and not guard_trusted and
    (fd.name endswith release_agent or fd.name = /proc/sys/kernel/core_pattern or
     fd.name = /proc/sys/kernel/modprobe or fd.name = /sys/kernel/uevent_helper)
  output: >
    Possible container escape (file=%fd.name proc=%proc.cmdline container=%container.name id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]

- rule: Runtime Socket non Authorized
  desc: A container opens or connects to a runtime socket
  condition: >
    (guard_open or (evt.type = connect and evt.dir = <)) and container.id != host and
    not guard_trusted and
    (fd.name contains docker.sock or fd.name contains containerd.sock or fd.name contains crio.sock)
  output: >
    Access to the runtime socket (sock=%fd.name proc=%proc.cmdline container=%container.name
    image=%container.image.repository id=%container.id)
  priority: CRITICAL
  tags: [container, runtime_socket, guard]

- rule: NSENTER Execution
  desc: nsenter executed inside a container
  condition: guard_spawn and container.id != host and not guard_trusted and proc.name = nsenter
  output: >
    nsenter in container (cmd=%proc.cmdline container=%container.name id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]

- rule: Mount Detection
  desc: mount() call from a container
  condition: evt.type = mount and container.id != host and not guard_trusted and not proc.name startswith "runc:"
  output: >
    mount() in container (args=%evt.args proc=%proc.cmdline container=%container.name id=%container.id)
  priority: WARNING
  tags: [container, mount, guard]

- rule: Interactive Shell Active
  desc: Interactive shell inside a container
  condition: >
    guard_spawn and container.id != host and not guard_trusted and
    proc.name in (bash, sh, zsh, ash, dash) and proc.tty != 0
  output: >
    Interactive shell (cmd=%proc.cmdline user=%user.name container=%container.name id=%container.id)
  priority: NOTICE
  tags: [container, shell, guard]
__GUARD_EOF__

# Syntax check of the rules, then consistency check between policy and rules.
if command -v falco >/dev/null; then
  falco -V /etc/falco/falco_rules.yaml -V "$RULES_FILE" \
    || die "Falco rejected the generated rules (see above). Nothing was committed."
  ok "Rules are valid."
fi

PYBIN=""
if [[ -x "$INSTALL_DIR/venv/bin/python" ]]; then
  PYBIN="$INSTALL_DIR/venv/bin/python"
elif python3 -c 'import yaml' 2>/dev/null; then
  PYBIN="python3"
fi
if [[ -n "$PYBIN" ]]; then
  "$PYBIN" - "$RULES_FILE" "$POLICY_FILE" <<'__PY__' || die "Policy/rules consistency check failed."
import sys, yaml
rules = {r["rule"] for r in yaml.safe_load(open(sys.argv[1])) if isinstance(r, dict) and "rule" in r}
pol = yaml.safe_load(open(sys.argv[2])) or {}
entries = pol.get("rules") or {}
if not isinstance(entries, dict):
    sys.exit("policy 'rules' is not a mapping")
problems = []
for name, entry in entries.items():
    if name not in rules:
        problems.append(f"policy rule not defined in the rules file: {name!r}")
    action = entry if isinstance(entry, str) else (entry or {}).get("action")
    if action not in ("alert", "isolate"):
        problems.append(f"invalid action for {name!r}: {action!r}")
for step in pol.get("isolation") or []:
    if step not in ("network", "pause", "stop"):
        problems.append(f"invalid isolation step: {step!r}")
if problems:
    sys.exit("\n".join(problems))
print(f"policy covers {len(entries)} rule(s); steps: {pol.get('isolation')}")
__PY__
  ok "Policy matches the rules."
else
  warn "No Python with PyYAML available: skipping the policy/rules cross-check."
fi

# --- live terminal notifications -------------------------------------------
NOTIFY_FILE="$(stage_file 755 "$NOTIFY_SCRIPT")"
cat > "$NOTIFY_FILE" <<'__NOTIFY_EOF__'
#!/usr/bin/env bash
# Broadcasts a wall message per new alert. Cooldown is per container, not per rule,
# because a single exec can trip several overlapping rules.
set -uo pipefail
export LC_ALL=C.UTF-8
ALERTS=/var/lib/Sentinel_Falco/alerts.jsonl
COOLDOWN=60

clean() { local s="${1//[[:cntrl:]]/}"; printf '%s' "${s:0:200}"; }

declare -A last
tail -n0 -F "$ALERTS" 2>/dev/null | while read -r line; do
  cont=$(clean "$(jq -r '.container // "?"' <<<"$line" 2>/dev/null)")
  rule=$(clean "$(jq -r '.rule // "?"' <<<"$line" 2>/dev/null)")
  dec=$(clean "$(jq -r '.decision // "?"' <<<"$line" 2>/dev/null)")
  det=$(clean "$(jq -r '.file // .cmd // ""' <<<"$line" 2>/dev/null)")

  now=$(printf '%(%s)T' -1)
  if (( now - ${last[$cont]:-0} < COOLDOWN )); then continue; fi
  last[$cont]=$now

  wall "SENTINEL ALERT: $rule
Container: $cont | Action: $dec
Details: $det"
done
__NOTIFY_EOF__

NOTIFY_UNIT="$(stage_file 644 /etc/systemd/system/sentinel-notify.service)"
cat > "$NOTIFY_UNIT" <<'EOC'
[Unit]
Description=Sentinel_Falco: live terminal notifications
After=falco-guard.service
Wants=falco-guard.service

[Service]
ExecStart=/usr/local/bin/sentinel-notify.sh
Restart=always
RestartSec=3
StartLimitBurst=10

[Install]
WantedBy=multi-user.target
EOC

# --- retention -------------------------------------------------------------
CLEAN_FILE="$(stage_file 755 "$CLEANUP_SCRIPT")"
cat > "$CLEAN_FILE" <<'EOC'
#!/usr/bin/env bash
set -euo pipefail
find /var/lib/Sentinel_Falco/AUDIT -type f -mtime +RETENTION_DAYS -delete
EOC
sed -i "s/RETENTION_DAYS/$RETENTION_DAYS/" "$CLEAN_FILE"

CLEAN_SVC="$(stage_file 644 "$CLEANUP_UNIT")"
cat > "$CLEAN_SVC" <<'EOC'
[Unit]
Description=Sentinel_Falco: purge old forensic evidence

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sentinel-cleanup.sh
EOC

CLEAN_TMR="$(stage_file 644 "$CLEANUP_TIMER")"
cat > "$CLEAN_TMR" <<'EOC'
[Unit]
Description=Daily forensic evidence cleanup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOC

LOGROTATE_FILE="$(stage_file 644 "$LOGROTATE_CONF")"
cat > "$LOGROTATE_FILE" <<'EOC'
/var/lib/Sentinel_Falco/alerts.jsonl {
    su root root
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOC

say "Step 8 of 8" "Configuring token, Falco output and services"

TOKEN="$(sed -n 's/^GUARD_TOKEN=//p' "$ENV_FILE" 2>/dev/null | head -n 1 || true)"
[[ "$TOKEN" =~ ^[[:xdigit:]]{48,128}$ ]] || TOKEN="$(openssl rand -hex 32)"

ENV_STAGED="$(stage_file 600 "$ENV_FILE")"
{
  grep -v -E '^(GUARD_TOKEN|GUARD_DETECTION_MODE|GUARD_PORT)=' "$ENV_FILE" 2>/dev/null || true
  printf 'GUARD_TOKEN=%s\n' "$TOKEN"
  printf 'GUARD_DETECTION_MODE=%s\n' "$DETECTION"
  printf 'GUARD_PORT=%s\n' "$PORT"
} > "$ENV_STAGED"

FALCO_CONF_FILE="$(stage_file 640 "$FALCO_CONFIG")"
cat > "$FALCO_CONF_FILE" <<EOC
engine:
  kind: modern_ebpf
  modern_ebpf: {}
json_output: true
json_include_output_property: true
json_include_tags_property: true
rule_matching: all
outputs:
  rate: 100
  max_burst: 1000
syscall_event_drops:
  actions: [log, alert]
  rate: 0.03333
  max_burst: 10
  simulate_drops: false
http_output:
  enabled: true
  url: "http://127.0.0.1:${PORT}/falco?token=${TOKEN}"
  user_agent: "falco/guard"
EOC

GUARD_UNIT="$(stage_file 644 /etc/systemd/system/falco-guard.service)"
cat > "$GUARD_UNIT" <<EOC
[Unit]
Description=Sentinel_Falco: alerts and automatic container isolation
After=docker.service network.target
Wants=docker.service
StartLimitBurst=10

[Service]
User=root
UMask=0077
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=/etc/falco-guard.env
Environment=GUARD_POLICY=$INSTALL_DIR/config/$POLICY_NAME GUARD_DATA=$DATA_DIR
ExecStart=$INSTALL_DIR/venv/bin/python -m uvicorn guard.Main_alert_falco:app \\
    --host 127.0.0.1 --port $PORT --no-access-log
Restart=always
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadWritePaths=$DATA_DIR
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
EOC
unset TOKEN

say "COMMIT" "Installing generated files"
if $DRY; then
  echo "  Planned file plan:"
fi
commit_files

if $DRY; then
  echo
  say "DRY-RUN" "Would also: enable/restart falco-guard, sentinel-notify, sentinel-cleanup.timer"
  say "DRY-RUN" "            and switch Falco to falco-modern-bpf.service"
  exit 0
fi

systemctl daemon-reload
systemctl enable falco-guard.service sentinel-notify.service sentinel-cleanup.timer
systemctl restart falco-guard.service
systemctl restart sentinel-notify.service
systemctl restart sentinel-cleanup.timer
systemctl disable --now falco-kmod.service falco-bpf.service 2>/dev/null || true
systemctl enable falco-modern-bpf.service
systemctl restart falco-modern-bpf.service

for _ in {1..15}; do curl -fs "http://127.0.0.1:$PORT/health" >/dev/null && break || sleep 1; done
curl -fs "http://127.0.0.1:$PORT/health" || die "Guard not responding: journalctl -u falco-guard -n 30"
echo
systemctl is-active --quiet falco-modern-bpf || die "Falco did not start: journalctl -u falco-modern-bpf -n 30"
systemctl is-active --quiet sentinel-notify   || die "Notification service down: journalctl -u sentinel-notify -n 30"

cat <<EOM

===========================================================================================================================
 Sentinel_Falco installed. Mode: $([[ $DETECTION == true ]] && echo "DETECTION (alert only, no isolation)" || echo "ENFORCE (real isolation)")
===========================================================================================================================
API:        http://127.0.0.1:$PORT   (token in /etc/falco-guard.env)
Alerts:     tail -f /var/lib/Sentinel_Falco/alerts.jsonl
Logs:       journalctl -u falco-guard -f | journalctl -u falco-modern-bpf -f
Evidence:   ls /var/lib/Sentinel_Falco/AUDIT   (purged after $RETENTION_DAYS days)
Reload:     sudo $0 --dry-run   then   sudo $0
Remove:     sudo $0 --uninstall
EOM
