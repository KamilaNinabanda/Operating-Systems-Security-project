#!/usr/bin/env bash
# ==============================================================================
# Suported platforms: Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/AlmaLinux 8.x-9.x, Fedora
#   (by default the tool runs in DRY_RUN: detects and alerts but no monitoring feature)
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}"
echo "=============================================================="
echo "      Monitoring and Alerting Tool - Setup          "
echo "=============================================================="
echo -e "${NC}"

[[ $EUID -eq 0 ]] || { echo "${RED}[!] Execute as root (sudo)."; exit 1; }
DRY=true; [[ "${1:-}" == "--enforce" ]] && DRY=false

# To avoid the questions of restarting services
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf
APT="apt-get install -y -qq -o Dpkg::Options::=--force-confold"

say() { echo -e "\033[0;34m[$1]\033[0m $2"; }
die() { echo -e "\033[0;31m[!] $1\033[0m" >&2; exit 1; }

# --- Distribution and package manager ---
. /etc/os-release 2>/dev/null || true
OSID=${ID:-desconocido}
if command -v apt-get >/dev/null; then PM=apt
elif command -v dnf >/dev/null; then PM=dnf
else die "For (Debian/Ubuntu) apt is required or dnf (RHEL/Rocky/Alma/Fedora)."; fi
echo "${BLUE}System: ${PRETTY_NAME:-$OSID} (${BLUE}package managers: $PM)"

say 1/7 "${CYAN} Checks kernel y BTF"
command -v getenforce >/dev/null && echo "SELinux: $(getenforce)"
[[ -f /sys/kernel/btf/vmlinux ]] || die "${RED} WARNING [!] /sys/kernel/btf/vmlinux: modern_ebpf won't work (kernel $(uname -r)). A kernerl >= 5.8 with BTF is needed."

say 2/7 "${BLUE} Installing base dependencies"
if [[ $PM == apt ]]; then
  apt-get update -qq
  $APT ca-certificates curl gnupg openssl python3 python3-venv
else
  # In RHEL, "curl-minimal" usually is present; "curl" is not reinstalled, to avoid package conflicts.
  command -v curl >/dev/null    || dnf install -y curl
  command -v openssl >/dev/null || dnf install -y openssl
  dnf install -y ca-certificates
fi
PYBIN=""
pick_python() {
  local c
  for c in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$c" >/dev/null && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then
      PYBIN=$(command -v "$c"); return 0
    fi
  done
  return 1
}
if ! pick_python && [[ $PM == dnf ]]; then   # p. ej. RHEL 8 has Python 3.6 by default
  dnf install -y python3.11 python3.11-pip || dnf install -y python3.12 python3.12-pip || true
  pick_python || true
fi
[[ -n "$PYBIN" ]] || die "${RED} WARNING: Python >= 3.9 is required (in RHEL/Rocky: dnf install python3.11 python3.11-pip)."
echo "Python: $PYBIN ($($PYBIN -V))"

say 3/7 "${BLUE} Docker Verification"
if command -v docker >/dev/null && docker version 2>&1 | grep -qi podman; then
  die "${RED} CRITICAL [!] PODMAN DETECTED (EMULATOR podman-docker). falco-guard needs Docker Engine. Execute: dnf remove -y podman-docker  and repeat the installation."
fi
if ! command -v docker >/dev/null; then
  if [[ $PM == apt ]]; then
    curl -fsSL https://get.docker.com | sh
  else
    MAJOR=${VERSION_ID:-0}; MAJOR=${MAJOR%%.*}
    if [[ $OSID == fedora ]]; then REPOS="fedora"
    elif [[ $MAJOR -ge 10 ]]; then REPOS="rhel centos"   # EL10: Docker documents 'rhel'; 'centos' also valid
    else REPOS="centos rhel"; fi
    #EL10 requires additional kernel modules for Docker networking (a reboot may be necessary).
    if [[ $OSID != fedora && $MAJOR -ge 10 ]]; then
      dnf install -y "kernel-modules-extra-$(uname -r)" || dnf install -y kernel-modules-extra || true
    fi
    DOCKER_OK=false
    for DREPO in $REPOS; do
      curl -fsSL "https://download.docker.com/linux/$DREPO/docker-ce.repo" -o /etc/yum.repos.d/docker-ce.repo || continue
      if dnf install -y docker-ce docker-ce-cli containerd.io; then DOCKER_OK=true; break; fi
      rm -f /etc/yum.repos.d/docker-ce.repo     # That repo didn't work; let's try the next one.
    done
    $DOCKER_OK || die "${YELLOW} Docker could not be installed (conflict with podman/runc?). Check and, if applicable: dnf install --allowerasing docker-ce docker-ce-cli containerd.io"
  fi
fi
systemctl enable --now docker
docker info >/dev/null 2>&1 || die "${RED}The Docker daemon is not responding (systemctl status docker).On Rocky/RHEL 10, reboot the machine after installing kernel-modules-extra and run the installer again.."

say 4/7 "Instalando Falco (repositorio oficial)"
if ! command -v falco >/dev/null && [[ $PM == apt ]]; then
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor --yes -o /etc/apt/keyrings/falco-archive-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
  apt-get update -qq
  $APT falco
fi
if ! command -v falco >/dev/null && [[ $PM == dnf ]]; then
  rpm --import https://falco.org/repo/falcosecurity-packages.asc
  curl -fsSL https://falco.org/repo/falcosecurity-rpm.repo -o /etc/yum.repos.d/falcosecurity.repo
  dnf install -y falco        # modern_ebpf does not need dkms or kernel-devel
fi

say 5/7 "Deploying falco tool in /opt/falco-guard"
mkdir -p /opt/falco-guard/guard /opt/falco-guard/config /var/lib/falco-guard /etc/falco/rules.d /etc/falco/config.d
cd /opt/falco-guard
: > /opt/falco-guard/guard/__init__.py
cat > /opt/falco-guard/guard/policy.py <<'__GUARD_EOF__'
"""Decision Engine: ¿ignore, alert or isolate?"""
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

import yaml


@dataclass
class Decision:
    action: str  # ignore | alert | isolate
    reason: str


class PolicyEngine:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        with open(path) as f:
            return cls(yaml.safe_load(f) or {})

    def _allowlisted(self, f: dict) -> bool:
        al = self.cfg.get("allowlist", {})
        name = f.get("container.name") or ""
        image = f.get("container.image.repository") or ""
        return name in al.get("container_names", []) or any(
            image.startswith(p) for p in al.get("image_prefixes", [])
        )

    def decide(self, event: dict) -> Decision:
        f = event.get("output_fields") or {}
        cid = f.get("container.id")
        if not cid or cid == "host":
            return Decision("ignore", "event outside a container")
        if self._allowlisted(f):
            return Decision("ignore", "container in allowlist")

        rule = event.get("rule", "")
        rcfg = (self.cfg.get("rules") or {}).get(rule)
        if rcfg is None:
            return Decision("alert", "rule without policy: alert only")
        if rcfg.get("action") == "isolate":
            return Decision("isolate", f"Critical: {rule}")

        n, window = rcfg.get("escalate_after"), rcfg.get("window", 60)
        if n:
            now = time.monotonic()
            with self._lock:
                q = self._hits[(cid, rule)]
                q.append(now)
                while q and now - q[0] > window:
                    q.popleft()
                if len(q) >= n:
                    q.clear()
                    return Decision("isolate", f"{n} events of '{rule}' in {window}s")
        return Decision("alert", "just alert")
__GUARD_EOF__
cat > /opt/falco-guard/guard/isolator.py <<'__GUARD_EOF__'
"""Container isolation via Docker SDK (with forensic evidence and reversion)."""
import json
import logging
import os
import threading
import time

import docker

log = logging.getLogger("guard.isolator")


class Isolator:
    def __init__(self, steps, dry_run, data_dir):
        self.steps = steps or ["network", "pause"]  # network | pause | stop
        self.dry_run = dry_run
        self.forensics_dir = os.path.join(data_dir, "forensics")
        self.state_path = os.path.join(data_dir, "state.json")
        os.makedirs(self.forensics_dir, exist_ok=True)
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

    def _forensics(self, c) -> str:
        attrs = json.loads(json.dumps(c.attrs))
        # Redact environment variable values ​​(which may contain secrets)
        attrs["Config"]["Env"] = [e.split("=", 1)[0] + "=<redacted>" for e in attrs["Config"].get("Env") or []]
        data = {"inspect": attrs, "fs_diff": c.diff()}
        if c.status == "running":
            data["processes"] = c.top()
        data["logs_tail"] = c.logs(tail=200).decode(errors="replace")
        path = os.path.join(self.forensics_dir, f"{c.name}-{int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def isolate(self, cid: str, reason: str) -> dict:
        with self._lock:
            if self.is_isolated(cid):
                return {"status": "already_isolated"}
            c = self.client.containers.get(cid)
            nets = list(c.attrs["NetworkSettings"]["Networks"])
            host_net = c.attrs["HostConfig"]["NetworkMode"] == "host"
            steps = list(self.steps)
            # With network_mode=host, the network cannot be disconnected: the container freezes.
            if host_net and "pause" not in steps and "stop" not in steps:
                steps.append("pause")
            if self.dry_run:
                return {"status": "dry_run", "container": c.name, "would_do": steps}

            forensics = self._forensics(c)  # first the evidence
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
            log.warning("Contenedor %s aislado: %s", c.name, done)
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
cat > /opt/falco-guard/guard/notifier.py <<'__GUARD_EOF__'
"""Alertas: log JSONL, Slack y webhook genérico."""
import json
import logging
import time

import requests

log = logging.getLogger("guard.notifier")


class Notifier:
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
        log.warning("ALERTA %s", json.dumps(alert))

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
                    log.error("Fallo al notificar: %s", e)
__GUARD_EOF__
cat > /opt/falco-guard/guard/main.py <<'__GUARD_EOF__'
"""Falco event receiver -> decision -> alert/isolation."""
import hmac
import logging
import os
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query

from .isolator import Isolator
from .notifier import Notifier
from .policy import PolicyEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

TOKEN = os.getenv("GUARD_TOKEN", "")
DATA = os.getenv("GUARD_DATA", "/var/lib/falco-guard")
os.makedirs(DATA, exist_ok=True)

engine = PolicyEngine.from_file(os.getenv("GUARD_POLICY", "config/policy.yaml"))
dry_run = os.getenv("GUARD_DRY_RUN", str(engine.cfg.get("dry_run", False))).lower() == "true"
isolator = Isolator(engine.cfg.get("isolation"), dry_run, DATA)
notifier = Notifier(os.path.join(DATA, "alerts.jsonl"),
                    os.getenv("SLACK_WEBHOOK_URL"), os.getenv("ALERT_WEBHOOK_URL"))

app = FastAPI(title="falco-guard")


def _auth(token, header):
    if TOKEN and not hmac.compare_digest((token or header or ""), TOKEN):
        raise HTTPException(401, "token no valid")


@app.post("/falco")
def falco_event(event: dict, token: Optional[str] = Query(None), x_guard_token: Optional[str] = Header(None)):
    _auth(token, x_guard_token)
    decision = engine.decide(event)
    if decision.action == "ignore":
        return {"decision": "ignore", "reason": decision.reason}

    result = None
    if decision.action == "isolate":
        cid = event["output_fields"]["container.id"]
        try:
            result = isolator.isolate(cid, decision.reason)
        except Exception as e:  # never miss an alert
            logging.exception("Failure at isolating %s", cid)
            result = {"status": "error", "error": str(e)}
    notifier.send(event, decision, result)
    return {"decision": decision.action, "reason": decision.reason, "isolation": result}


@app.get("/health")
def health():
    return {"status": "ok", "dry_run": dry_run, "isolation_steps": isolator.steps}


@app.get("/quarantine")
def quarantine(token: Optional[str] = Query(None), x_guard_token: Optional[str] = Header(None)):
    _auth(token, x_guard_token)
    return isolator.state


@app.post("/release/{cid}")
def release(cid: str, token: Optional[str] = Query(None), x_guard_token: Optional[str] = Header(None)):
    _auth(token, x_guard_token)
    return isolator.release(cid)
__GUARD_EOF__
POLICY_DST=/opt/falco-guard/config/policy.yaml
if [ -f "$POLICY_DST" ]; then POLICY_DST="$POLICY_DST.new"; echo "[i] policy.yaml is conserved; the newest version is in $POLICY_DST"; fi
cat > "$POLICY_DST" <<'__GUARD_EOF__'
# Response politics
dry_run: false            # true = just register what isolate
isolation: [network, pause]   # pasos: network (disconnect the network) | pause (freeze) | stop

allowlist:                # no alert or isolation
  container_names: [falco, falco-guard]
  image_prefixes: ["falcosecurity/"]

rules:
  "Container Accessing Host Filesystem": {action: isolate}
  "Container Escape Artifact Write":     {action: isolate}
  "Container Accessing Container Runtime Socket": {action: isolate}
  "Escape Tool Executed In Container":   {action: isolate}
  "Mount Syscall In Container":          {action: alert}   # no scaltion until check if its noise
  "Interactive Shell Spawned In Container": {action: alert}
__GUARD_EOF__
cat > /etc/falco/rules.d/guard_rules.yaml <<'__GUARD_EOF__'
# Falco rules (>= 0.38) to detect suspicious actions 
- macro: guard_open
  condition: (evt.type in (open, openat, openat2) and fd.num >= 0)
- macro: guard_spawn
  condition: (evt.type in (execve, execveat) and evt.dir = <)
- macro: guard_trusted
  condition: (container.image.repository in (falcosecurity/falco, falco-guard))
# Container startup: runc opens the rootfs at /var/lib/docker/rootfs/overlayfs/ (noise, not an attack).
# Narrow exception: only that specific process+path pair. The rest of /var/lib/docker/ remains monitored.
- macro: guard_runc_startup
  condition: (proc.name startswith "runc:" and fd.name startswith /var/lib/docker/rootfs/overlayfs/)

- rule: Container Accessing Host Filesystem
  desc:A container opens host path filest (bind mounts de / , /proc/1/root, runtime dirs)
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

- rule: Container Escape Artifact Write
  desc: : Writing to typical escape artifacts (cgroup release_agent, core_pattern, modprobe)
  condition: >
    evt.type in (open, openat, openat2) and evt.is_open_write = true and
    container.id != host and not guard_trusted and
    (fd.name endswith release_agent or fd.name = /proc/sys/kernel/core_pattern or
     fd.name = /proc/sys/kernel/modprobe or fd.name = /sys/kernel/uevent_helper)
  output: >
    Posible container scape (file=%fd.name proc=%proc.cmdline container=%container.name id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]

- rule: Container Accessing Container Runtime Socket
  desc: A container opens/connects to the Docker/containerd/CRI-O socket.
  condition: >
    (guard_open or (evt.type = connect and evt.dir = <)) and container.id != host and
    not guard_trusted and
    (fd.name contains docker.sock or fd.name contains containerd.sock or fd.name contains crio.sock)
  output: >
   Acces to the runtime socket (sock=%fd.name proc=%proc.cmdline container=%container.name
    image=%container.image.repository id=%container.id)
  priority: CRITICAL
  tags: [container, runtime_socket, guard]

- rule: Escape Tool Executed In Container
  desc: nsenter executed inside a container
  condition: guard_spawn and container.id != host and not guard_trusted and proc.name = nsenter
  output: >
    nsenter en contenedor (cmd=%proc.cmdline container=%container.name id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]

- rule: Mount Syscall In Container
  desc: Llamada mount() from a contenedor
  condition: evt.type = mount and evt.dir = < and container.id != host and not guard_trusted and not proc.name startswith "runc:"
  output: >
    mount() in container (args=%evt.args proc=%proc.cmdline container=%container.name id=%container.id)
  priority: WARNING
  tags: [container, mount, guard]

- rule: Interactive Shell Spawned In Container
  desc: Shell interactiva dentro de un contenedor
  condition: >
    guard_spawn and container.id != host and not guard_trusted and
    proc.name in (bash, sh, zsh, ash, dash) and proc.tty != 0
  output: >
    Shell interactiva (cmd=%proc.cmdline user=%user.name container=%container.name id=%container.id)
  priority: NOTICE
  tags: [container, shell, guard]
__GUARD_EOF__

"$PYBIN" -m venv /opt/falco-guard/venv || die "No se pudo crear el entorno virtual (en RHEL: dnf install python3.11-pip)."
/opt/falco-guard/venv/bin/pip install -q --upgrade pip
/opt/falco-guard/venv/bin/pip install -q "fastapi==0.115.*" "uvicorn[standard]==0.32.*" "docker==7.1.*" "PyYAML==6.0.*" "requests==2.32.*"

say 6/7 "Configurando token, modo y salida HTTP de Falco"
if [[ -f /etc/falco-guard.env ]]; then
  # Reinstalación: se conserva el token, SLACK_WEBHOOK_URL y el modo (solo cambia con --enforce)
  TOKEN=$(grep '^GUARD_TOKEN=' /etc/falco-guard.env | cut -d= -f2)
  [[ "${1:-}" == "--enforce" ]] && sed -i "s/^GUARD_DRY_RUN=.*/GUARD_DRY_RUN=$DRY/" /etc/falco-guard.env
  DRY=$(grep '^GUARD_DRY_RUN=' /etc/falco-guard.env | cut -d= -f2)
else
  TOKEN=$(openssl rand -hex 24)
  printf 'GUARD_TOKEN=%s\nGUARD_DRY_RUN=%s\n# SLACK_WEBHOOK_URL=\n' "$TOKEN" "$DRY" > /etc/falco-guard.env
fi
chmod 600 /etc/falco-guard.env

# Va en config.d: NO sustituye el falco.yaml por defecto, solo lo extiende.
cat > /etc/falco/config.d/guard.yaml <<EOC
engine:
  kind: modern_ebpf
  modern_ebpf: {}
json_output: true
json_include_output_property: true
json_include_tags_property: true
rule_matching: all   # evalúa TODAS las reglas (por defecto 'first' deja que las reglas por defecto tapen a las nuestras)
http_output:
  enabled: true
  url: "http://127.0.0.1:8080/falco?token=${TOKEN}"
  user_agent: "falco/guard"
EOC
chmod 640 /etc/falco/config.d/guard.yaml

cat > /etc/systemd/system/falco-guard.service <<'EOC'
[Unit]
Description=falco-guard: alertas y aislamiento automatico de contenedores
After=docker.service network.target
Requires=docker.service

[Service]
User=root
WorkingDirectory=/opt/falco-guard
EnvironmentFile=/etc/falco-guard.env
Environment=GUARD_POLICY=/opt/falco-guard/config/policy.yaml GUARD_DATA=/var/lib/falco-guard
ExecStart=/opt/falco-guard/venv/bin/python -m uvicorn guard.main:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOC

say 7/7 "Validando reglas y arrancando servicios"
falco -V /etc/falco/falco_rules.yaml -V /etc/falco/rules.d/guard_rules.yaml >/dev/null 2>&1 \
  || die "Las reglas no validan. Revisa: falco -V /etc/falco/falco_rules.yaml -V /etc/falco/rules.d/guard_rules.yaml"

command -v restorecon >/dev/null && restorecon -R /opt/falco-guard /var/lib/falco-guard /etc/falco /etc/falco-guard.env 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now falco-guard.service          # primero el guardián...
systemctl disable --now falco-kmod.service falco-bpf.service 2>/dev/null || true
systemctl enable falco-modern-bpf.service
systemctl restart falco-modern-bpf.service           # ...luego Falco

for i in {1..15}; do curl -fs http://127.0.0.1:8080/health >/dev/null && break || sleep 1; done
curl -fs http://127.0.0.1:8080/health || die "El guardián no responde: journalctl -u falco-guard -n 30  (con SELinux Enforcing: ausearch -m avc -ts recent)"
echo
systemctl is-active --quiet falco-modern-bpf || die "Falco no arrancó: journalctl -u falco-modern-bpf -n 30"

cat <<EOM

==============================================================
 falco-guard instalado. Modo: $([[ $DRY == true ]] && echo "DRY_RUN (solo simula el aislamiento)" || echo "ENFORCE (aísla de verdad)")
==============================================================
 Token (guardado en /etc/falco-guard.env): $TOKEN

 Probar:     docker run -d --name victim -v /:/host alpine sleep 3600
             docker exec victim cat /host/etc/hostname
             tail -n 3 /var/lib/falco-guard/alerts.jsonl
 Activar:    sudo sed -i 's/GUARD_DRY_RUN=true/GUARD_DRY_RUN=false/' /etc/falco-guard.env && sudo systemctl restart falco-guard
 Aislados:   curl -H "X-Guard-Token: $TOKEN" localhost:8080/quarantine
 Liberar:    curl -X POST -H "X-Guard-Token: $TOKEN" localhost:8080/release/<nombre>
 Logs:       journalctl -u falco-guard -f   |   journalctl -u falco-modern-bpf -f
 Recomendado: reiniciar la VM una vez (kernel/librerías actualizadas) y revisar
              alerts.jsonl 24-48 h en DRY_RUN antes de activar ENFORCE.
EOM
