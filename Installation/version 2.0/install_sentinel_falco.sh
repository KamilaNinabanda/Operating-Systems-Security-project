#!/usr/bin/env bash
#==============================================================================
# Supported OS: Ubuntu from version >=22.04 , Debian 12+, Kali Linux
# Requirements: systemd, kernel >= 5.8 with BTF, Python >= 3.10, Docker.
#   sudo ./install_sentinel_falco.sh [--enforce] [--port N] because in KALI the default port can be already used 
#Bash shell option that changes pipeline behaviour so the pipeline fails if any command in the chain fails.
set -euo pipefail
#user file-creation mode mask: subtracts permissions from the base permissions when a new file or directory is created. 
#This is because when we collect logs, we keep private information and we do not want everybody can read it. 
umask 077
#Colors to alerts or any warning during the installation
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- INFO 
#   --enforce   real isolation (default: detection mode = detect and alert only)
#   --port N    port of the local API (default 8080, or the one used by a previous install)
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1024 && 10#$1 <= 65535 )); }
DETECTION=true
PORT_FLAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --enforce) DETECTION=false ;;
    --port)
      [[ -n "${2:-}" ]] || { echo -e "${RED}[!] --port choose a value.${NC}" >&2; exit 1; }
      PORT_FLAG="$2"; shift ;;
    -h|--help) echo "Usage: $0 [--enforce] [--port N]"; exit 0 ;;
    *) echo -e "${RED}[!] Unknown option: $1${NC}" >&2; exit 1 ;;
  esac
  shift
done
if [[ -n "$PORT_FLAG" ]] && ! valid_port "$PORT_FLAG"; then
  echo -e "${RED}[!] Invalid port '$PORT_FLAG' (use a number between 1024 and 65535).${NC}" >&2; exit 1
fi
# ------

#It verifies that we execute with sudo because the program edit and create files. 
[[ $EUID -eq 0 ]] || { echo -e "${RED}[!] Execute as root with sudo.${NC}"; exit 1; }

# This prevents the appeareance of prompts regarding services (restarting)
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf
APT="apt-get install -y -qq -o Dpkg::Options::=--force-confold"

# --- Paths ---
INSTALL_DIR=/opt/Sentinel_Falco #main directory 
DATA_DIR=/var/lib/Sentinel_Falco #where alert and state.json is. has the system state, hence the permissions are 700
COLLECT_INFO="$DATA_DIR/AUDIT" #It has all the data collected from the container before the isolation starts
FALCO_CONFIG=/etc/falco/config.d/configfalco.yaml # set the we are using the EBPF and handles the TOKEN  
FALCO_RULES=/etc/falco/rules.d/rules_detection_falco.yaml #personalized FALCO Rules (conditions for detection)
POLICY_NAME=policy_rules_defined.yaml #Where the action rules will be
APT_KEYRING=/etc/apt/keyrings/verify_repo_install.gpg #verify authenticity whe we install falco
NOTIFY_SCRIPT=/usr/local/bin/sentinel-notify.sh # to see an alert when something of the rules triggers it

say() { echo -e "\033[0;34m[${1:-INFO}]\033[0m ${2:-}"; }
die() { echo -e "\033[0;31m[!] $1\033[0m" >&2; exit 1; }

# --- OS validation ---
OS_ID="$( . /etc/os-release 2>/dev/null && echo "${ID:-unknown}" || echo unknown )"
OS_LIKE="$( . /etc/os-release 2>/dev/null && echo "${ID_LIKE:-}" || true )"
OS_NAME="$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$OS_ID}" || echo "$OS_ID" )"
OS_VERSION="$( . /etc/os-release 2>/dev/null && echo "${VERSION_ID:-0}" || echo 0 )"
case " $OS_ID $OS_LIKE " in
  *" ubuntu "*|*" debian "*|*" kali "*) ;;
  *) die "${RED}Unsupported distribution: $OS_NAME. Supported: Ubuntu, Debian and Kali Linux (or apt-based distribution).${NC}" ;;
esac
# Ubuntu: 22.04 or newer (Python should be >= 3.10. Less is not valid)
if [[ "$OS_ID" == "ubuntu" ]]; then
  [[ "$OS_VERSION" =~ ^[0-9]+(\.[0-9]+)?$ ]] || OS_VERSION=0
  IFS=. read -r _maj _min <<< "$OS_VERSION"
  if ! (( 10#${_maj:-0} > 22 || (10#${_maj:-0} == 22 && 10#${_min:-0} >= 4) )); then
    die "${RED}Ubuntu $OS_VERSION is not supported: Ubuntu 22.04 or newer is required.${NC}"
  fi
fi
IS_KALI=false
if [[ "$OS_ID" == "kali" ]]; then IS_KALI=true; fi
# --- Section of OS detection ENDS ---

#DIE: shows a message with the error and stops the intallation
say "Step 1 of 7" "${BLUE} Validating system, kernel, systemd and port${NC}"
if $IS_KALI; then say "KALI" "${CYAN}Kali Linux was detected: $OS_NAME${NC}"; fi

#we need to verify BTF AND SYSTEMD is up
WSL_NOTE=""
if grep -qi microsoft /proc/version 2>/dev/null; then
  WSL_NOTE=" WSL detected: the default WSL kernel often has no BTF and needs systemd enabled ([boot] systemd=true in /etc/wsl.conf)."
fi
[[ -f /sys/kernel/btf/vmlinux ]] || die "${YELLOW} Missing /sys/kernel/btf/vmlinux: modern_ebpf won't work (kernel $(uname -r)).$WSL_NOTE"
[[ -d /run/systemd/system ]] || die "${YELLOW} systemd is not running: Sentinel_Falco installs systemd services.$WSL_NOTE"

# Port of the local API. Burp Suite and OWASP ZAP (common on Kali) listen on 8080 by default.
ENV_FILE="/etc/falco-guard.env"
OLD_PORT=""
if [[ -f "$ENV_FILE" ]]; then OLD_PORT="$(sed -n 's/^GUARD_PORT=//p' "$ENV_FILE" | head -n 1)"; fi
PORT="${PORT_FLAG:-${OLD_PORT:-8080}}"
valid_port "$PORT" || die "${YELLOW} Invalid port '$PORT' (check GUARD_PORT in $ENV_FILE)."
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
if port_in_use "$PORT"; then
  if systemctl is-active --quiet falco-guard.service 2>/dev/null && [[ "$PORT" == "${OLD_PORT:-8080}" ]]; then
    say "PORT" "${CYAN}127.0.0.1:$PORT is used by the running falco-guard (reinstall).${NC}"
  else
    die "${RED} Port $PORT is already used by another program (Burp Suite and ZAP use 8080 by default). Choose another one: sudo $0 --port 18080"
  fi
fi
#--------------------------------

say "Step 2 of 7" "${BLUE}Installing dependencies${NC}"
command -v apt-get >/dev/null || die "${RED}CRITICAL: This installer only supports Debian/Ubuntu (apt)."
apt-get update -qq #silent installation
# JQ: used to process, filter, and extract data from JSON files or streams (for the notifications)
$APT ca-certificates curl gnupg openssl python3 python3-venv jq
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || die "${YELLOW}Python >= 3.10 is required (you have $(python3 -V))."

#----------------------------------------

say "Step 3 of 7" "${BLUE}Verifying Docker installation${NC}"

DOCKER_INSTALL_HINT=""
DOCKER_START_HINT="sudo systemctl start docker"
if $IS_KALI; then
  DOCKER_INSTALL_HINT=" On Kali: sudo apt install docker.io"
  DOCKER_START_HINT="sudo systemctl enable --now docker"
fi

# Docker has to be installed.
command -v docker >/dev/null 2>&1 \
    || die "${RED} [!] Docker is not installed. Install and configure Docker before Sentinel_Falco.$DOCKER_INSTALL_HINT"

# Docker daemon must be running.
systemctl is-active --quiet docker || systemctl is-active --quiet snap.docker.dockerd \
    || die "${YELLOW}WARNING: Docker service is not running. Start it with: $DOCKER_START_HINT"
# Verify that the daemon responds.
docker info >/dev/null 2>&1 \
    || die "${RED} [!] Cannot communicate with Docker daemon. Check Docker service status."

say "VALIDATED" "${GREEN}Docker is installed and functional.${NC}"
#------------------------------------------
#Verifies if falco is installed, if its install then just skips and goes to the next one
say "Step 4 of 7" "${BLUE}Installing Falco (official repository)${NC}"
if ! command -v falco >/dev/null; then
  install -d -m 0755 /etc/apt/keyrings 
  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor --yes -o "$APT_KEYRING"
  chmod 644 "$APT_KEYRING"   # apt verifies it as user _apt: it must be readable (umask is 077)
  echo "deb [signed-by=$APT_KEYRING] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
  chmod 644 /etc/apt/sources.list.d/falcosecurity.list
  apt-get update -qq
  $APT falco
fi
#----------------------------------------------------------------

say "Step 5 of 7" "${BLUE}Deploying Sentinel_Falco in $INSTALL_DIR${NC}"
#creates directories: alert, policies, information of containers isolated,falco configuration
#prepare dependencies to deploy the rules
mkdir -p "$INSTALL_DIR/guard" "$INSTALL_DIR/config" /etc/falco/rules.d /etc/falco/config.d
install -d -m 700 "$DATA_DIR" "$COLLECT_INFO"   # The data collected is sensitive so to avoid any security risk of leaking data the information has to be protected
touch "$INSTALL_DIR/guard/__init__.py"
cat > "$INSTALL_DIR/guard/policy.py" <<'__GUARD_EOF__'
"""Decision mechanism: ignore, alert or isolate?"""
from dataclasses import dataclass

import yaml


@dataclass
class DecisionActions:
    action: str  # ignore | alert | isolate
    reason: str


class Policies:
    def __init__(self, cfg: dict):
        self.cfg = cfg

    @classmethod
    def from_file(cls, path: str) -> "Policies":
        with open(path) as f:
            return cls(yaml.safe_load(f) or {})

    def decide(self, event: dict) -> DecisionActions:
        f = event.get("output_fields") or {}
        cid = f.get("container.id")
        if not cid or cid == "host":
            return DecisionActions("ignore", "event outside a container")

        rule = event.get("rule", "")
        configrule = (self.cfg.get("rules") or {}).get(rule)
        if configrule is None:
            return DecisionActions("alert", "rule without a policy: alert only")
        if configrule.get("action") == "isolate":
            return DecisionActions("isolate", f"Critical rule: {rule}")

        return DecisionActions("alert", "alert only")
__GUARD_EOF__
cat > "$INSTALL_DIR/guard/isolation_recovery_container.py" <<'__GUARD_EOF__'
"""Executes container isolation and recovery via Docker SDK (with forensic evidence and rollback)."""
import json
import logging
import os
import threading
import time

import docker

log = logging.getLogger("guard.isolator")


class ContainerIsolation:
    def __init__(self, steps, detection_mode, data_dir):
        self.steps = steps or ["network", "pause"]  # network | pause | stop
        self.detection_mode = detection_mode
        self.collect_info = os.path.join(data_dir, "AUDIT")
        self.state_path = os.path.join(data_dir, "state.json")
        os.makedirs(self.collect_info, exist_ok=True)
        self._client = None
        self._lock = threading.Lock()
        self.state = {}
        if os.path.exists(self.state_path):
            with open(self.state_path) as f:
                self.state = json.load(f)

    @property
    def client(self):
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _save(self):
        with open(self.state_path, "w") as f:
            json.dump(self.state, f, indent=2)

    def _find(self, cid):
        return next((k for k, r in self.state.items() if r["name"] == cid or k.startswith(cid) or cid.startswith(k)), None)

    def is_isolated(self, cid) -> bool:
        return self._find(cid) is not None

    def _gatherInfo(self, c) -> str:
        """Snapshot of the container before it is isolated; saving the result to a JSON file with restricted permissions."""
        attrs = json.loads(json.dumps(c.attrs))
        attrs["Config"]["Env"] = [e.split("=", 1)[0] + "=<not for reading>" for e in attrs["Config"].get("Env") or []]
        collectedinfo = {"inspect": attrs, "fs_diff": c.diff()}
        if c.status == "running":
            collectedinfo["processes"] = c.top()
        collectedinfo["logs_tail"] = c.logs(tail=200).decode(errors="replace")
        path = os.path.join(self.collect_info, f"{c.name}-{int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(collectedinfo, f, indent=2, default=str)
        os.chmod(path, 0o600)
        return path

    def isolate(self, cid: str, reason: str) -> dict:
        with self._lock:
            if self.is_isolated(cid):
                return {"status": "already_isolated"}
            c = self.client.containers.get(cid)
            nets = list(c.attrs["NetworkSettings"]["Networks"])
            host_net = c.attrs["HostConfig"]["NetworkMode"] == "host"
            steps = list(self.steps)
            # With network_mode=host the network cannot be disconnected: freeze the container instead.
            if host_net and "pause" not in steps and "stop" not in steps:
                steps.append("pause")
            if self.detection_mode:
                return {"status": "detection_mode", "container": c.name, "would_do": steps}

            forensics = self._gatherInfo(c)  # collect evidence first
            done = []
            for step in steps:
                if step == "network" and not host_net:
                    for n in nets:
                        self.client.networks.get(n).disconnect(c, force=True)
                elif step == "pause" and "stop" not in steps:
                    c.pause()
                elif step == "stop":
                    c.stop(timeout=5)
                else:
                    continue
                done.append(step)
            self.state[c.id] = {
                "name": c.name, "networks": nets, "done": done,
                "reason": reason, "ts": time.time(), "forensics": forensics,
            }
            self._save()
            log.warning("Container %s isolated: %s", c.name, done)
            return {"status": "isolated", "container": c.name, "steps": done, "forensics": forensics}

    def release(self, cid: str) -> dict:
        with self._lock:
            key = self._find(cid)
            if not key:
                return {"status": "not_isolated"}
            rec = self.state[key]
            c = self.client.containers.get(key)
            if "stop" in rec["done"]:
                c.start()
            c.reload()
            if c.status == "paused":
                c.unpause()
            if "network" in rec["done"]:
                for n in rec["networks"]:
                    self.client.networks.get(n).connect(c)
            del self.state[key]
            self._save()
            return {"status": "released", "container": rec["name"]}
__GUARD_EOF__
cat > "$INSTALL_DIR/guard/notification_alerter.py" <<'__GUARD_EOF__'
"""Alerts: JSONL log, Slack and generic webhook."""
import json
import logging
import time

import requests

log = logging.getLogger("guard.notifier")


class Notificationalert:
    def __init__(self, alert_log, slack_url=None, webhook_url=None):
        self.alert_log, self.slack_url, self.webhook_url = alert_log, slack_url, webhook_url

    def send(self, event: dict, decision, result):
        f = event.get("output_fields") or {}
        alert = {
            "ts": event.get("time") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rule": event.get("rule"), "priority": event.get("priority"),
            "container": f.get("container.name"), "container_id": f.get("container.id"),
            "image": f.get("container.image.repository"), "file": f.get("fd.name"),
            "cmd": f.get("proc.cmdline"), "decision": decision.action,
            "reason": decision.reason, "isolation": result,
        }
        with open(self.alert_log, "a") as fh:
            fh.write(json.dumps(alert) + "\n")
        log.warning("ALERT %s", json.dumps(alert))

        icon = "🔒" if decision.action == "isolate" else "🚨"
        text = (f"{icon} *{alert['rule']}* ({alert['priority']})\n"
                f"Container: `{alert['container']}` ({alert['image']})\n"
                f"Details: `{alert['file'] or alert['cmd']}`\n"
                f"Action: *{decision.action}* — {decision.reason}")
        for url, payload in ((self.slack_url, {"text": text}), (self.webhook_url, alert)):
            if url:
                try:
                    requests.post(url, json=payload, timeout=5)
                except requests.RequestException as e:
                    log.error("Failed to send notification: %s", e)
__GUARD_EOF__
cat > "$INSTALL_DIR/guard/Main_alert_falco.py" <<'__GUARD_EOF__'
"""Falco event receiver -> decision -> alert/isolation."""
import hmac
import logging
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from .isolation_recovery_container import ContainerIsolation
from .notification_alerter import Notificationalert
from .policy import Policies

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

TOKEN = os.getenv("GUARD_TOKEN", "")
DATA = os.getenv("GUARD_DATA", "/var/lib/Sentinel_Falco")
os.makedirs(DATA, exist_ok=True)

engine = Policies.from_file(os.getenv("GUARD_POLICY", "config/policy_rules_defined.yaml"))
detection_mode = os.getenv("GUARD_DETECTION_MODE", str(engine.cfg.get("detection_mode", False))).lower() == "true"
isolator = ContainerIsolation(engine.cfg.get("isolation"), detection_mode, DATA)
notifier = Notificationalert(os.path.join(DATA, "alerts.jsonl"),
                    os.getenv("SLACK_WEBHOOK_URL"), os.getenv("ALERT_WEBHOOK_URL"))

app = FastAPI(title="Sentinel_Falco")


def require_token(token: str | None = Query(None), x_guard_token: str | None = Header(None)):
    """Header first, query parameter as fallback (Falco sends the token in the URL). Fails closed."""
    if not TOKEN:
        logging.critical("GUARD_TOKEN is missing: refusing authenticated requests.")
        raise HTTPException(503, "Authentication is not well configured")
    supplied = x_guard_token if x_guard_token is not None else token
    if not supplied or not hmac.compare_digest(supplied.encode(), TOKEN.encode()):
        raise HTTPException(401, "Invalid authentication token")


@app.post("/falco", dependencies=[Depends(require_token)])
def falco_event(event: dict):
    decision = engine.decide(event)
    if decision.action == "ignore":
        return {"decision": "ignore", "reason": decision.reason}

    result = None
    if decision.action == "isolate":
        cid = event["output_fields"]["container.id"]
        try:
            result = isolator.isolate(cid, decision.reason)
        except Exception as e:  # never miss an alert because of an isolation failure
            logging.exception("Failed to isolate %s", cid)
            result = {"status": "error", "error": str(e)}
    notifier.send(event, decision, result)
    return {"decision": decision.action, "reason": decision.reason, "isolation": result}


@app.get("/health")
def health():
    return {"status": "ok", "detection_mode": detection_mode, "isolation_steps": isolator.steps}


@app.get("/isolated_container", dependencies=[Depends(require_token)])
def isolated_container():
    return isolator.state


@app.post("/release/{cid}", dependencies=[Depends(require_token)])
def release(cid: str):
    return isolator.release(cid)
__GUARD_EOF__
POLICY_DST="$INSTALL_DIR/config/$POLICY_NAME"
if [ -f "$POLICY_DST" ]; then POLICY_DST="$POLICY_DST.new"; echo "[i] $POLICY_NAME already exists and is preserved; the newer version is in $POLICY_DST"; fi
cat > "$POLICY_DST" <<'__GUARD_EOF__'
# Sentinel_Falco response policy
detection_mode: false            # true = detection mode: detect and alert only, never isolate
isolation: [network, pause]   # steps: network (disconnect from networks) | pause (freeze) | stop

rules:
  "Host Filesystem non Authorized":   {action: isolate}
  "File Modification Escape Attempt":  {action: isolate}
  "Runtime Socket non Authorized":    {action: isolate}
  "NSENTER Execution":                {action: isolate}
  "Mount Detection":                  {action: alert}
  "Interactive Shell Active":         {action: alert}
__GUARD_EOF__
cat > "$FALCO_RULES" <<'__GUARD_EOF__'
# The rules need Falco version 0.38 or higher to be executed
- macro: guard_open
  condition: (evt.type in (open, openat, openat2) and fd.num >= 0)
- macro: guard_spawn
  condition: (evt.type in (execve, execveat))
- macro: guard_trusted
  condition: (container.image.repository in (falcosecurity/falco, falco-guard))
# Container startup: runc opens the container rootfs while creating it (noise, not an attack).
# Depending on the Docker storage driver the path is /var/lib/docker/rootfs/overlayfs/ (containerd snapshotter)
# or /var/lib/docker/overlay2/ (classic overlay2 driver).
# Narrow exception: only that process+path pair. The rest of /var/lib/docker/ remains monitored.
- macro: guard_runc_startup
  condition: (proc.name startswith "runc:" and (fd.name startswith /var/lib/docker/rootfs/overlayfs/ or fd.name startswith /var/lib/docker/overlay2/))

- rule: Host Filesystem non Authorized
  desc: A container opens files from host paths (bind mounts of /, /proc/1/root, runtime dirs)
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
  desc: Writing to typical escape artifacts (cgroup release_agent, core_pattern, modprobe)
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
  desc: A container opens/connects to the Docker/containerd/CRI-O socket
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
#---------------------------------------

#Creates a library separate from the Ubuntu one, to avoid conflicts between versions
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q "fastapi==0.115.*" "uvicorn[standard]==0.32.*" "docker==7.1.*" "PyYAML==6.0.*" "requests==2.32.*"

#---------------------------------------------------------------
# Live terminal notifications: watches alerts.jsonl and broadcasts a message (wall) to every open terminal.
# Cooldown: the same rule + container only notifies once every COOLDOWN seconds (alerts.jsonl still logs everything).
cat > "$NOTIFY_SCRIPT" <<'__NOTIFY_EOF__'
#!/usr/bin/env bash
# Sentinel_Falco: broadcast a terminal alert (wall) for every new alert, with cooldown
ALERTS=/var/lib/Sentinel_Falco/alerts.jsonl
COOLDOWN=60        # seconds before the same rule+container can notify again
clean() { printf '%s' "$1" | tr -cd '[:print:]' | cut -c1-200; }   # strips control characters coming from the container

declare -A last

tail -n0 -F "$ALERTS" 2>/dev/null | while read -r line; do
  rule=$(clean "$(jq -r '.rule // "?"' <<<"$line")")
  cont=$(clean "$(jq -r '.container // "?"' <<<"$line")")
  dec=$(clean "$(jq -r '.decision // "?"' <<<"$line")")
  det=$(clean "$(jq -r '.file // .cmd // ""' <<<"$line")")

  key="$rule|$cont"
  now=$(printf '%(%s)T' -1)
  if (( now - ${last[$key]:-0} < COOLDOWN )); then continue; fi
  last[$key]=$now

  wall "SENTINEL ALERT: $rule
Container: $cont | Action: $dec
Details: $det"
done
__NOTIFY_EOF__
chmod 755 "$NOTIFY_SCRIPT"

cat > /etc/systemd/system/sentinel-notify.service <<'EOC'
[Unit]
Description=Sentinel_Falco: live terminal notifications
After=falco-guard.service

[Service]
ExecStart=/usr/local/bin/sentinel-notify.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOC

#---------------------------------------------------------------
say "Step 6 of 7" "${BLUE}Configuring token and Falco HTTP output${NC}"

# Keep an existing valid token, otherwise generate one
TOKEN="$(sed -n 's/^GUARD_TOKEN=//p' "$ENV_FILE" 2>/dev/null | head -n 1 || true)"
[[ "$TOKEN" =~ ^[[:xdigit:]]{48,128}$ ]] || TOKEN="$(openssl rand -hex 32)"

# Rewrite the env file atomically (mktemp creates it 600), keeping other variables such as SLACK_WEBHOOK_URL
TMP_ENV="$(mktemp "$ENV_FILE.XXXXXX")"
trap 'rm -f "$TMP_ENV"' EXIT        # do not leave temp files if the installation fails
{
    grep -v -E '^(GUARD_TOKEN|GUARD_DETECTION_MODE|GUARD_PORT)=' "$ENV_FILE" 2>/dev/null || true
    printf 'GUARD_TOKEN=%s\n' "$TOKEN"
    printf 'GUARD_DETECTION_MODE=%s\n' "$DETECTION"
    printf 'GUARD_PORT=%s\n' "$PORT"
} > "$TMP_ENV"
mv -f "$TMP_ENV" "$ENV_FILE"
trap - EXIT

# Generate Falco configuration.
cat > "$FALCO_CONFIG" <<EOC
engine:
  kind: modern_ebpf
  modern_ebpf: {}
json_output: true
json_include_output_property: true
json_include_tags_property: true
rule_matching: all
http_output:
  enabled: true
  url: "http://127.0.0.1:${PORT}/falco?token=${TOKEN}"
  user_agent: "falco/guard"
EOC

chmod 640 "$FALCO_CONFIG"
unset TOKEN

# Configure systemd service.
cat > /etc/systemd/system/falco-guard.service <<EOC
[Unit]
Description=Sentinel_Falco: alerts and automatic isolation of containers
After=docker.service network.target
Wants=docker.service

[Service]
User=root
UMask=0077
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=/etc/falco-guard.env
Environment=GUARD_POLICY=$INSTALL_DIR/config/$POLICY_NAME GUARD_DATA=$DATA_DIR
ExecStart=$INSTALL_DIR/venv/bin/python -m uvicorn guard.Main_alert_falco:app --host 127.0.0.1 --port $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOC

say "Step 7 of 7" "${CYAN}Validating rules and starting services${NC}"
if falco -V /etc/falco/falco_rules.yaml -V "$FALCO_RULES"; then
    say "OK" "${GREEN} Falco rules are valid and ready."
else
    die "Falco rule validation failed. Check the errors above."
fi

systemctl daemon-reload
systemctl enable falco-guard.service
systemctl restart falco-guard.service               # guard first... (restart also applies new code/port on a reinstall)
systemctl enable sentinel-notify.service
systemctl restart sentinel-notify.service           # live terminal notifications
systemctl disable --now falco-kmod.service falco-bpf.service 2>/dev/null || true
systemctl enable falco-modern-bpf.service
systemctl restart falco-modern-bpf.service           # ...then Falco

for i in {1..15}; do curl -fs "http://127.0.0.1:$PORT/health" >/dev/null && break || sleep 1; done
curl -fs "http://127.0.0.1:$PORT/health" || die "${RED}The guard is not responding: journalctl -u falco-guard -n 30"
echo
systemctl is-active --quiet falco-modern-bpf || die "${RED}Falco could not start: journalctl -u falco-modern-bpf -n 30"
systemctl is-active --quiet sentinel-notify || die "${RED}The notification service is not running: journalctl -u sentinel-notify -n 30"

cat <<EOM

===========================================================================================================================
 Sentinel_Falco installed. Mode: $([[ $DETECTION == true ]] && echo "DETECTION_MODE (detects and alerts only, no isolation)" || echo "ENFORCE (real isolation)")
=============================================================================================================================
API:        http://127.0.0.1:$PORT   (token saved in /etc/falco-guard.env)
Alerts:     tail -f /var/lib/Sentinel_Falco/alerts.jsonl   (live terminal alerts are broadcast automatically)
Logs:       journalctl -u falco-guard -f   |   journalctl -u falco-modern-bpf -f   |   journalctl -u sentinel-notify -f
EOM
