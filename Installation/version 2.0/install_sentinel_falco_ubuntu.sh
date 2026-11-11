#!/usr/bin/env bash
#==============================================================================
#Bash shell option that changes pipeline behaviour so the pipeline fails if any command in the chain fails.
set -euo pipefail
#Colors to alerts or any warning during the installation
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#It verifies that we execute with sudo because the program edit and create files. 
#If we include --enforce the isolation feature is included
[[ $EUID -eq 0 ]] || { echo -e "${RED}[!] Execute as root with sudo.${NC}"; exit 1; }
DETECTION=true; [[ "${1:-}" == "--enforce" ]] && DETECTION=false

# This prevents the appeareance of prompts regarding services (restarting)
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf
APT="apt-get install -y -qq -o Dpkg::Options::=--force-confold"

# --- Paths ---
INSTALL_DIR=/opt/Sentinel_Falco
DATA_DIR=/var/lib/Sentinel_Falco
COLLECT_INFO=$DATA_DIR/AUDIT
FALCO_CONFIG=/etc/falco/config.d/configfalco.yaml
FALCO_RULES=/etc/falco/rules.d/rules_detection_falco.yaml
POLICY_NAME=policy_rules_defined.yaml
APT_KEYRING=/etc/apt/keyrings/verify_repo_install.gpg

say() { echo -e "\033[0;34m[$1]\033[0m $2"; }
die() { echo -e "\033[0;31m[!] $1\033[0m" >&2; exit 1; }

#DIE: shows a message with the error and stops the intallation
say "Step 1 of 7" "${BLUE} Validating kernel and BTF${NC}"
[[ -f /sys/kernel/btf/vmlinux ]] || die "${YELLOW} Missing /sys/kernel/btf/vmlinux: modern_ebpf won't work (kernel $(uname -r))."
#--------------------------------

say "Step 2 of 7" "${BLUE}Installing dependencies${NC}"
command -v apt-get >/dev/null || die "${RED}CRITICAL: This installer only supports Debian/Ubuntu (apt)."
apt-get update -qq
$APT ca-certificates curl gnupg openssl python3 python3-venv
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || die "${YELLOW}Python >= 3.10 is required (you have $(python3 -V))."

#----------------------------------------

say "Step 3 of 7" "${BLUE}Verifying Docker${NC}"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
#------------------------------------------
#Verifies if falco is installed, if so then this step is skipped 

say 4/7 "${BLUE}Installing Falco (official repository)${NC}"
if ! command -v falco >/dev/null; then
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor --yes -o "$APT_KEYRING"
  echo "deb [signed-by=$APT_KEYRING] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
  apt-get update -qq
  $APT falco
fi
#----------------------------------------------------------------

say "Step 5 of 7" "${BLUE}Deploying Sentinel_Falco in $INSTALL_DIR${NC}"
#creates directories: alert, policies, information of containers isolated,falco configuration
#prepare dependencies to deploy the rules
mkdir -p "$INSTALL_DIR/guard" "$INSTALL_DIR/config" "$DATA_DIR" "$COLLECT_INFO" /etc/falco/rules.d /etc/falco/config.d
cd "$INSTALL_DIR"
: > "$INSTALL_DIR/guard/__init__.py"
cat > "$INSTALL_DIR/guard/policy.py" <<'__GUARD_EOF__'
"""Decision engine: ignore, alert or isolate?"""
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
    #collects data from the container that will be isolated
        attrs = json.loads(json.dumps(c.attrs))
        #Since containers can have API passwords, token or passwords the info replaces that for "not for reading"
        attrs["Config"]["Env"] = [e.split("=", 1)[0] + "=<not for reading>" for e in attrs["Config"].get("Env") or []]
        collectedinfo = {"inspect": attrs, "fs_diff": c.diff()}
        if c.status == "running":
            collectedinfo["processes"] = c.top()
        collectedinfo["logs_tail"] = c.logs(tail=200).decode(errors="replace")
        path = os.path.join(self.collect_info, f"{c.name}-{int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(collectedinfo, f, indent=2, default=str)
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

from fastapi import FastAPI, Header, HTTPException, Query

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


def _auth(token, header):
    if TOKEN and not hmac.compare_digest((token or header or ""), TOKEN):
        raise HTTPException(401, "invalid token")


@app.post("/falco")
def falco_event(event: dict, token: str | None = Query(None), x_guard_token: str | None = Header(None)):
    _auth(token, x_guard_token)
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


@app.get("/isolated_container")
def isolated_container(token: str | None = Query(None), x_guard_token: str | None = Header(None)):
    _auth(token, x_guard_token)
    return isolator.state


@app.post("/release/{cid}")
def release(cid: str, token: str | None = Query(None), x_guard_token: str | None = Header(None)):
    _auth(token, x_guard_token)
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
  "Mount Detection":                  {action: alert}   # no escalation until runc noise is validated
  "Interactive Shell Active":         {action: alert}
__GUARD_EOF__
cat > "$FALCO_RULES" <<'__GUARD_EOF__'
# The rules need Falco version 0.38 or higher to be executed
- macro: guard_open
  condition: (evt.type in (open, openat, openat2) and fd.num >= 0)
- macro: guard_spawn
  condition: (evt.type in (execve, execveat) and evt.dir = <)
- macro: guard_trusted
  condition: (container.image.repository in (falcosecurity/falco, falco-guard))
# Container startup: runc opens the rootfs at /var/lib/docker/rootfs/overlayfs/ (noise, not an attack).
# Narrow exception: only that process+path pair. The rest of /var/lib/docker/ remains monitored.
- macro: guard_runc_startup
  condition: (proc.name startswith "runc:" and fd.name startswith /var/lib/docker/rootfs/overlayfs/)

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
  condition: evt.type = mount and evt.dir = < and container.id != host and not guard_trusted and not proc.name startswith "runc:"
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
say "Step 6 of 7" "${BLUE}Configuring token and Falco HTTP output${NC}"
if [[ -f /etc/falco-guard.env ]]; then
  # Reinstall: keep the token, SLACK_WEBHOOK_URL and the mode (the mode only changes with --enforce)
  TOKEN=$(grep '^GUARD_TOKEN=' /etc/falco-guard.env | cut -d= -f2)
  [[ "${1:-}" == "--enforce" ]] && sed -i "s/^GUARD_DETECTION_MODE=.*/GUARD_DETECTION_MODE=$DETECTION/" /etc/falco-guard.env
  DETECTION=$(grep '^GUARD_DETECTION_MODE=' /etc/falco-guard.env | cut -d= -f2)
else
  TOKEN=$(openssl rand -hex 24)
  printf 'GUARD_TOKEN=%s\nGUARD_DETECTION_MODE=%s\n# SLACK_WEBHOOK_URL=\n' "$TOKEN" "$DETECTION" > /etc/falco-guard.env
fi
chmod 600 /etc/falco-guard.env

# Goes in config.d: it does not replace the default falco.yaml, it only extends it.
cat > "$FALCO_CONFIG" <<EOC
engine:
  kind: modern_ebpf
  modern_ebpf: {}
json_output: true
json_include_output_property: true
json_include_tags_property: true
rule_matching: all   # evaluate ALL rules (the default 'first' lets the stock rules shadow ours)
http_output:
  enabled: true
  url: "http://127.0.0.1:8080/falco?token=${TOKEN}"
  user_agent: "falco/guard"
EOC
chmod 640 "$FALCO_CONFIG"

cat > /etc/systemd/system/falco-guard.service <<EOC
[Unit]
Description=Sentinel_Falco: alerts and automatic isolation of containers
After=docker.service network.target
Requires=docker.service

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=/etc/falco-guard.env
Environment=GUARD_POLICY=$INSTALL_DIR/config/$POLICY_NAME GUARD_DATA=$DATA_DIR
ExecStart=$INSTALL_DIR/venv/bin/python -m uvicorn guard.Main_alert_falco:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOC

say 7/7 "${CYAN}Validating rules and starting services${NC}"
falco -V /etc/falco/falco_rules.yaml -V "$FALCO_RULES" >/dev/null 2>&1 \
  || die "${RED}The rules are not valid. Check: falco -V /etc/falco/falco_rules.yaml -V $FALCO_RULES"

systemctl daemon-reload
systemctl enable --now falco-guard.service          # guard first...
systemctl disable --now falco-kmod.service falco-bpf.service 2>/dev/null || true
systemctl enable falco-modern-bpf.service
systemctl restart falco-modern-bpf.service           # ...then Falco

for i in {1..15}; do curl -fs http://127.0.0.1:8080/health >/dev/null && break || sleep 1; done
curl -fs http://127.0.0.1:8080/health || die "${RED}The guard is not responding: journalctl -u falco-guard -n 30"
echo
systemctl is-active --quiet falco-modern-bpf || die "${RED}Falco could not start: journalctl -u falco-modern-bpf -n 30"

cat <<EOM

===========================================================================================================================
 Sentinel_Falco installed. Mode: $([[ $DETECTION == true ]] && echo "DETECTION_MODE (detects and alerts only, no isolation)" || echo "ENFORCE (real isolation)")
=============================================================================================================================
 Token (saved in /etc/falco-guard.env): $TOKEN

 Logs:       journalctl -u falco-guard -f   |   journalctl -u falco-modern-bpf -f
EOM
