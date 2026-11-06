#!/usr/bin/env bash
# ==============================================================================
# falco-guard: instalador nativo (Falco modern eBPF + guardián Python en systemd)
# Soportado: Ubuntu 22.04/24.04, Debian 12 (Python >= 3.10), kernel >= 5.8 con BTF
# Uso: sudo bash install-falco-guard.sh [--enforce]
#   (por defecto arranca en DRY_RUN: detecta y alerta pero NO aísla)
# ==============================================================================
set -euo pipefail
 
[[ $EUID -eq 0 ]] || { echo "[!] Ejecuta como root (sudo)."; exit 1; }
DRY=true; [[ "${1:-}" == "--enforce" ]] && DRY=false
 
# Sin preguntas interactivas (needrestart / debconf). 'l' solo lista, no reinicia servicios.
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf
APT="apt-get install -y -qq -o Dpkg::Options::=--force-confold"
 
say() { echo -e "\033[0;34m[$1]\033[0m $2"; }
die() { echo -e "\033[0;31m[!] $1\033[0m" >&2; exit 1; }
 
say 1/7 "Comprobando kernel y BTF"
[[ -f /sys/kernel/btf/vmlinux ]] || die "Falta /sys/kernel/btf/vmlinux: modern_ebpf no funcionará (kernel $(uname -r)). Usa un kernel >= 5.8 con BTF."
 
say 2/7 "Instalando dependencias base"
command -v apt-get >/dev/null || die "Solo Debian/Ubuntu (apt) está soportado por este instalador."
apt-get update -qq
$APT ca-certificates curl gnupg openssl python3 python3-venv
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || die "Se requiere Python >= 3.10 (tienes $(python3 -V))."
 
say 3/7 "Verificando Docker"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
 
say 4/7 "Instalando Falco (repositorio oficial)"
if ! command -v falco >/dev/null; then
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor --yes -o /etc/apt/keyrings/falco-archive-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
  apt-get update -qq
  $APT falco
fi
 
say 5/7 "Desplegando falco-guard en /opt/falco-guard"
mkdir -p /opt/falco-guard/guard /opt/falco-guard/config /var/lib/falco-guard /etc/falco/rules.d /etc/falco/config.d
cd /opt/falco-guard
: > /opt/falco-guard/guard/__init__.py
cat > /opt/falco-guard/guard/policy.py <<'__GUARD_EOF__'
"""Motor de decisión: ¿ignorar, alertar o aislar?"""
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
            return Decision("ignore", "evento fuera de un contenedor")
        if self._allowlisted(f):
            return Decision("ignore", "contenedor en allowlist")
 
        rule = event.get("rule", "")
        rcfg = (self.cfg.get("rules") or {}).get(rule)
        if rcfg is None:
            return Decision("alert", "regla sin política: solo alerta")
        if rcfg.get("action") == "isolate":
            return Decision("isolate", f"regla crítica: {rule}")
 
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
                    return Decision("isolate", f"{n} eventos de '{rule}' en {window}s")
        return Decision("alert", "solo alerta")
__GUARD_EOF__
cat > /opt/falco-guard/guard/isolator.py <<'__GUARD_EOF__'
"""Aislamiento de contenedores vía Docker SDK (con evidencia forense y reversión)."""
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
        return next((k for k in self.state if k.startswith(cid) or cid.startswith(k)), None)
 
    def is_isolated(self, cid) -> bool:
        return self._find(cid) is not None
 
    def _forensics(self, c) -> str:
        attrs = json.loads(json.dumps(c.attrs))
        # Redactar valores de variables de entorno (pueden contener secretos)
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
            # Con network_mode=host no se puede desconectar la red: se congela el contenedor.
            if host_net and "pause" not in steps and "stop" not in steps:
                steps.append("pause")
            if self.dry_run:
                return {"status": "dry_run", "container": c.name, "would_do": steps}
 
            forensics = self._forensics(c)  # primero la evidencia
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
                f"Contenedor: `{alert['container']}` ({alert['image']})\n"
                f"Detalle: `{alert['file'] or alert['cmd']}`\n"
                f"Acción: *{decision.action}* — {decision.reason}")
        for url, payload in ((self.slack_url, {"text": text}), (self.webhook_url, alert)):
            if url:
                try:
                    requests.post(url, json=payload, timeout=5)
                except requests.RequestException as e:
                    log.error("Fallo al notificar: %s", e)
__GUARD_EOF__
cat > /opt/falco-guard/guard/main.py <<'__GUARD_EOF__'
"""Receptor de eventos Falco -> decisión -> alerta/aislamiento."""
import hmac
import logging
import os
 
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
        raise HTTPException(401, "token inválido")
 
 
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
        except Exception as e:  # nunca perder la alerta por un fallo del aislamiento
            logging.exception("Fallo al aislar %s", cid)
            result = {"status": "error", "error": str(e)}
    notifier.send(event, decision, result)
    return {"decision": decision.action, "reason": decision.reason, "isolation": result}
 
 
@app.get("/health")
def health():
    return {"status": "ok", "dry_run": dry_run, "isolation_steps": isolator.steps}
 
 
@app.get("/quarantine")
def quarantine(token: str | None = Query(None), x_guard_token: str | None = Header(None)):
    _auth(token, x_guard_token)
    return isolator.state
 
 
@app.post("/release/{cid}")
def release(cid: str, token: str | None = Query(None), x_guard_token: str | None = Header(None)):
    _auth(token, x_guard_token)
    return isolator.release(cid)
__GUARD_EOF__
cat > /opt/falco-guard/config/policy.yaml <<'__GUARD_EOF__'
# Política de respuesta de falco-guard
dry_run: false            # true = solo registra qué aislaría
isolation: [network, pause]   # pasos: network (desconecta redes) | pause (congela) | stop
 
allowlist:                # nunca se alerta ni se aísla
  container_names: [falco, falco-guard]
  image_prefixes: ["falcosecurity/"]
 
rules:
  "Container Accessing Host Filesystem": {action: isolate}
  "Container Escape Artifact Write":     {action: isolate}
  "Container Accessing Container Runtime Socket": {action: isolate}
  "Escape Tool Executed In Container":   {action: isolate}
  "Mount Syscall In Container":          {action: alert, escalate_after: 3, window: 60}
  "Interactive Shell Spawned In Container": {action: alert}
__GUARD_EOF__
cat > /etc/falco/rules.d/guard_rules.yaml <<'__GUARD_EOF__'
# Reglas Falco (>= 0.38) para detectar comportamiento sospechoso en contenedores
- macro: guard_open
  condition: (evt.type in (open, openat, openat2) and fd.num >= 0)
- macro: guard_spawn
  condition: (evt.type in (execve, execveat) and evt.dir = <)
- macro: guard_trusted
  condition: (container.image.repository in (falcosecurity/falco, falco-guard))
 
- rule: Container Accessing Host Filesystem
  desc: Un contenedor abre archivos de rutas del host (bind mounts de / , /proc/1/root, runtime dirs)
  condition: >
    guard_open and container.id != host and not guard_trusted and
    (fd.name startswith /host/ or fd.name startswith /hostfs/ or
     fd.name startswith /proc/1/root or fd.name startswith /var/lib/kubelet/ or
     fd.name startswith /var/lib/docker/ or fd.name startswith /var/lib/containerd/)
  output: >
    Acceso al filesystem del host (file=%fd.name proc=%proc.cmdline user=%user.name
    container=%container.name image=%container.image.repository:%container.image.tag id=%container.id)
  priority: CRITICAL
  tags: [container, host_fs, guard]
 
- rule: Container Escape Artifact Write
  desc: Escritura en artefactos típicos de escape (cgroup release_agent, core_pattern, modprobe)
  condition: >
    evt.type in (open, openat, openat2) and evt.is_open_write = true and
    container.id != host and not guard_trusted and
    (fd.name endswith release_agent or fd.name = /proc/sys/kernel/core_pattern or
     fd.name = /proc/sys/kernel/modprobe or fd.name = /sys/kernel/uevent_helper)
  output: >
    Posible escape de contenedor (file=%fd.name proc=%proc.cmdline container=%container.name id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]
 
- rule: Container Accessing Container Runtime Socket
  desc: Un contenedor abre/conecta al socket de Docker/containerd/CRI-O
  condition: >
    (guard_open or (evt.type = connect and evt.dir = <)) and container.id != host and
    not guard_trusted and
    (fd.name contains docker.sock or fd.name contains containerd.sock or fd.name contains crio.sock)
  output: >
    Acceso al socket del runtime (sock=%fd.name proc=%proc.cmdline container=%container.name
    image=%container.image.repository id=%container.id)
  priority: CRITICAL
  tags: [container, runtime_socket, guard]
 
- rule: Escape Tool Executed In Container
  desc: nsenter ejecutado dentro de un contenedor
  condition: guard_spawn and container.id != host and not guard_trusted and proc.name = nsenter
  output: >
    nsenter en contenedor (cmd=%proc.cmdline container=%container.name id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]
 
- rule: Mount Syscall In Container
  desc: Llamada mount() desde un contenedor
  condition: evt.type = mount and evt.dir = < and container.id != host and not guard_trusted
  output: >
    mount() en contenedor (args=%evt.args proc=%proc.cmdline container=%container.name id=%container.id)
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
 
python3 -m venv /opt/falco-guard/venv
/opt/falco-guard/venv/bin/pip install -q --upgrade pip
/opt/falco-guard/venv/bin/pip install -q "fastapi==0.115.*" "uvicorn[standard]==0.32.*" "docker==7.1.*" "PyYAML==6.0.*" "requests==2.32.*"
 
say 6/7 "Configurando token, modo y salida HTTP de Falco"
if [[ -f /etc/falco-guard.env ]]; then
  TOKEN=$(grep '^GUARD_TOKEN=' /etc/falco-guard.env | cut -d= -f2)   # reutiliza el token en reinstalaciones
else
  TOKEN=$(openssl rand -hex 24)
fi
printf 'GUARD_TOKEN=%s\nGUARD_DRY_RUN=%s\n# SLACK_WEBHOOK_URL=\n' "$TOKEN" "$DRY" > /etc/falco-guard.env
chmod 600 /etc/falco-guard.env
 
# Va en config.d: NO sustituye el falco.yaml por defecto, solo lo extiende.
cat > /etc/falco/config.d/guard.yaml <<EOC
engine:
  kind: modern_ebpf
  modern_ebpf: {}
json_output: true
json_include_output_property: true
json_include_tags_property: true
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
 
systemctl daemon-reload
systemctl enable --now falco-guard.service          # primero el guardián...
systemctl disable --now falco-kmod.service falco-bpf.service 2>/dev/null || true
systemctl enable falco-modern-bpf.service
systemctl restart falco-modern-bpf.service           # ...luego Falco
 
for i in {1..15}; do curl -fs http://127.0.0.1:8080/health >/dev/null && break || sleep 1; done
curl -fs http://127.0.0.1:8080/health || die "El guardián no responde: journalctl -u falco-guard -n 30"
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
 
