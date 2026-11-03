cat > ~/setup-falco-guard.sh << 'SCRIPT_EOF'
#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# setup-falco-guard.sh
# Docker installation, Falco (modern_ebpf) and the service falco-guard
# with the rules. The scenario is for an isolated VM
# ============================================================

GUARD_DIR=/opt/falco-guard
ENV_FILE=/etc/falco-guard/env
LOG_DIR=/var/log/falco-guard

log() { echo -e "\n>>> $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "Run this script with sudo."

log "Step 1 out of 7: Installing Docker Engine from the official repository"
if ! command -v docker >/dev/null; then
  for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    apt-get remove -y "$pkg" >/dev/null 2>&1 || true
  done
  apt-get update -y
  apt-get install -y ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
  log "Docker is already installed; skip."
fi
systemctl enable --now docker

REAL_USER="${SUDO_USER:-$USER}"
usermod -aG docker "$REAL_USER" || true

log "Step 2 out of 7: Installation of Falco (driver modern_ebpf)"
if ! command -v falco >/dev/null; then
  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
    > /etc/apt/sources.list.d/falcosecurity.list
  apt-get update -y
  apt-get install -y dkms make "linux-headers-$(uname -r)" dialog || true
  FALCO_DRIVER_CHOICE=modern_ebpf FALCO_FRONTEND=noninteractive apt-get install -y falco
else
  log "Falco is already installed. Will be omitted."
fi

log "Step 3 out of 7: Configuring falco.yaml (http_output, rule_matching, rules.d)"
cp -n /etc/falco/falco.yaml /etc/falco/falco.yaml.orig || true
python3 - "$1" << 'PYEOF'
import re, sys
token = sys.argv[1]
path = "/etc/falco/falco.yaml"
text = open(path).read()

text = re.sub(r"^json_output:.*$", "json_output: true", text, flags=re.M)
if "json_output:" not in text:
    text += "\njson_output: true\n"

text = re.sub(
    r"http_output:\n(\s+enabled:.*\n\s+url:.*\n)",
    f"http_output:\n  enabled: true\n  url: \"http://127.0.0.1:8080/falco?token={token}\"\n",
    text,
)
if "http_output:" not in text:
    text += f"\nhttp_output:\n  enabled: true\n  url: \"http://127.0.0.1:8080/falco?token={token}\"\n"

if re.search(r"^rule_matching:", text, flags=re.M):
    text = re.sub(r"^rule_matching:.*$", "rule_matching: all", text, flags=re.M)
else:
    text += "\nrule_matching: all\n"

open(path, "w").write(text)
PYEOF

log "Step 4 out of 7: Custom rules"
mkdir -p /etc/falco/rules.d
cat > /etc/falco/rules.d/host_access.yaml << 'RULES_EOF'
- list: sensitive_basenames
  items: [shadow, gshadow, sudoers]

- rule: Container opens candidate sensitive file
  desc: >
    Candidate: a container opens a file with a sensitive name.
    The final confirmation (whether from the host or the container) is performed by
    the Python service correlating with the mounts.
  condition: >
    evt.type in (open, openat, openat2) and evt.is_open_read=true
    and container.id != host
    and (fd.filename in (sensitive_basenames)
         or fd.name contains "/.ssh/"
         or fd.name contains "/etc/kubernetes/"
         or fd.name contains "/var/lib/kubelet/")
  output: >
    Candidate for sensitive access (file=%fd.name cmd=%proc.cmdline
    container_id=%container.id container=%container.name
    image=%container.image.repository user=%user.name)
  priority: NOTICE
  tags: [container, custom, host_file_candidate]

- rule: Container touches Docker socket
  desc: Accessing the Docker socket from a container
  condition: >
    evt.type in (open, openat, openat2, connect) and container.id != host
    and fd.name = /var/run/docker.sock
  output: >
    Docker socket is using (cmd=%proc.cmdline container_id=%container.id
    container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [container, host_escape, custom]
RULES_EOF

falco -V /etc/falco/rules.d/host_access.yaml || fail "The rule failed validation."

log "Step 5 out of 7: Creating the service user and the Python environment"
id -u falco-guard >/dev/null 2>&1 || useradd --system --home-dir "$GUARD_DIR" --shell /usr/sbin/nologin falco-guard
mkdir -p "$GUARD_DIR" "$(dirname "$ENV_FILE")" "$LOG_DIR"
python3 -m venv "$GUARD_DIR/venv"
"$GUARD_DIR/venv/bin/pip" install --quiet fastapi uvicorn docker requests

log "Step 6 out of 7: Writing monitor.py and the configuration"
# --- monitor.py it is written using the consolidated and already validated content ---
cat > "$GUARD_DIR/monitor.py" << 'PYFILE_EOF'
import hmac
import json
import logging
import os
import posixpath
import re
import threading
import time
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler

import docker
import requests
from fastapi import Body, FastAPI, HTTPException, Query

DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"
TOKEN = os.getenv("GUARD_TOKEN", "")
ENFORCE_MODE = os.getenv("ENFORCE_MODE", "all")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
LOG_DIR = os.getenv("LOG_DIR", "/var/log/falco-guard")
COOLDOWN = int(os.getenv("COOLDOWN", "300"))

ISOLATE_PRIORITIES = {"Critical", "Alert", "Emergency"}
ISOLATE_TAGS = {"host_escape"}
IGNORE_LABEL = ("falco-guard.ignore", "true")
ENFORCE_LABEL = ("falco-guard.enforce", "true")

if len(TOKEN) < 16:
    raise RuntimeError("GUARD_TOKEN not defined or too short (minimum 16 characters)")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("falco-guard")

audit_log = logging.getLogger("falco-guard.audit")
audit_log.setLevel(logging.INFO)
audit_log.propagate = False
if os.path.isdir(LOG_DIR):
    _h = RotatingFileHandler(os.path.join(LOG_DIR, "audit.log"), maxBytes=10_000_000, backupCount=5)
    _h.setFormatter(logging.Formatter("%(message)s"))
    audit_log.addHandler(_h)


def audit(**data):
    data["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    data["dry_run"] = DRY_RUN
    audit_log.info(json.dumps(data, ensure_ascii=False))


client = docker.from_env()
_last_action: dict[str, float] = {}
_lock = threading.Lock()


def notify(msg: str):
    log.warning(msg)
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": msg}, timeout=5)
        except requests.RequestException as e:
            log.error("Slack fallo: %s", e)


def has_label(container, label) -> bool:
    return (container.labels or {}).get(label[0]) == label[1]


def inspect_risky_mounts(container) -> list[str]:
    risky = []
    for m in container.attrs.get("Mounts", []):
        if m.get("Source", "") in ("/", "/etc", "/root", "/var/run/docker.sock"):
            risky.append(m["Source"])
    if container.attrs["HostConfig"].get("Privileged"):
        risky.append("privileged")
    return risky


def isolate(container):
    container.reload()
    log.info("Isolating %s (%s)", container.name, container.short_id)
    for net_name in list(container.attrs["NetworkSettings"]["Networks"].keys()):
        try:
            client.networks.get(net_name).disconnect(container, force=True)
        except docker.errors.APIError as e:
            log.error("Couldn't connect from %s: %s", net_name, e)
    container.pause()
    try:
        container.commit(repository="quarantine", tag=f"{container.short_id}-{int(time.time())}")
    except docker.errors.APIError as e:
        log.error("commit fallo: %s", e)


SENSITIVE_EXACT = {"/etc/shadow", "/etc/gshadow", "/etc/sudoers"}
SENSITIVE_PREFIXES = ("/etc/sudoers.d/", "/etc/kubernetes/", "/var/lib/kubelet/", "/root/.ssh/")
SENSITIVE_RE = re.compile(r"^/home/[^/]+/\.ssh/")


def is_sensitive_host_path(path: str) -> bool:
    return (path in SENSITIVE_EXACT or path.startswith(SENSITIVE_PREFIXES) or bool(SENSITIVE_RE.match(path)))


def resolve_host_path(container, fd_name: str):
    best = None
    for m in container.attrs.get("Mounts", []):
        if m.get("Type") != "bind":
            continue
        dest = (m.get("Destination") or "").rstrip("/")
        src = m.get("Source") or ""
        if not dest or not src:
            continue
        if fd_name == dest or fd_name.startswith(dest + "/"):
            if best is None or len(dest) > len(best[0]):
                best = (dest, src)
    if best is None:
        return None, None
    dest, src = best
    rest = fd_name[len(dest):]
    host_path = (src.rstrip("/") + rest) or "/"
    return posixpath.normpath(host_path), src


@asynccontextmanager
async def lifespan(app):
    threading.Thread(target=watch_docker_events, daemon=True).start()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/health")
def health():
    try:
        client.ping()
        return {"status": "ok", "dry_run": DRY_RUN, "mode": ENFORCE_MODE}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"docker: {e}")


@app.post("/falco")
def falco_event(event: dict = Body(...), token: str = Query("")):
    if not hmac.compare_digest(token.encode(), TOKEN.encode()):
        raise HTTPException(status_code=401, detail="invalid token")

    fields = event.get("output_fields", {})
    cid = fields.get("container.id")
    rule, prio = event.get("rule"), event.get("priority")
    tags = set(event.get("tags", []))
    base = {"rule": rule, "priority": prio, "container_id": cid,
            "container": fields.get("container.name"), "file": fields.get("fd.name")}

    def done(status: str):
        audit(status=status, **base)
        return {"status": status}

    if not cid or cid == "host":
        return done("no-container")

    container = None

    if "host_file_candidate" in tags:
        try:
            container = client.containers.get(cid)
        except docker.errors.NotFound:
            return done("container-gone")

        fd_name = posixpath.normpath(fields.get("fd.name") or "/")
        host_path, mount_src = resolve_host_path(container, fd_name)
        if host_path is None:
            return done("internal-file")
        base["host_path"] = host_path
        base["mount_source"] = mount_src
        if not is_sensitive_host_path(host_path):
            return done("mount-not-sensitive")

        base["priority"] = "Critical"
        notify(f"[Confirmed] {container.name} reads {host_path} from the host (seen as {fd_name})")
    else:
        notify(f"[Falco] {prio} | {rule} | {event.get('output')}")
        if not (prio in ISOLATE_PRIORITIES and (tags & ISOLATE_TAGS)):
            return done("alert-only")

    with _lock:
        if time.time() - _last_action.get(cid, 0) < COOLDOWN:
            return done("cooldown")
        _last_action[cid] = time.time()

    if container is None:
        try:
            container = client.containers.get(cid)
        except docker.errors.NotFound:
            return done("container-gone")

    try:
        if has_label(container, IGNORE_LABEL):
            return done("exempt")
        if ENFORCE_MODE == "label" and not has_label(container, ENFORCE_LABEL):
            return done("alert-only-not-enforced")

        risky = inspect_risky_mounts(container)
        notify(f"Mounts de riesgo en {container.name}: {risky or 'none'}")

        if DRY_RUN:
            notify(f"[DRY_RUN] will isolate.. {container.name}")
            return done("dry-run")

        isolate(container)
        notify(f"Container {container.name} isolated")
        return done("isolated")
    except Exception as e:
        log.exception("Error while procesing %s", cid)
        audit(status="error", error=str(e), **base)
        raise HTTPException(status_code=500, detail="internal error")


FD_PATH = re.compile(r"/proc/(self|thread-self|\d+)/fd\b")


def handle_create(watch_client, ev):
    cid = ev.get("id") or (ev.get("Actor") or {}).get("ID", "")
    if not cid:
        return
    try:
        c = watch_client.containers.get(cid)
    except docker.errors.NotFound:
        audit(status="create-race-container-gone", container_id=cid[:12])
        return

    workdir = (c.attrs.get("Config") or {}).get("WorkingDir") or ""
    if not FD_PATH.search(workdir):
        return

    base = {"rule": "WorkingDir points to /proc fd (CVE-2024-21626)", "priority": "Critical",
            "container_id": c.short_id, "container": c.name, "file": workdir}
    notify(f"[Docker events] WorkingDir sospechoso en {c.name}: {workdir}")

    if has_label(c, IGNORE_LABEL):
        audit(status="exempt", **base)
        return
    if DRY_RUN:
        notify(f"[DRY_RUN] {c.name} would be removed before booting")
        audit(status="dry-run", **base)
        return
    try:
        c.remove(force=True)
        notify(f"container {c.name} removed before starting")
        audit(status="removed-before-start", **base)
    except docker.errors.APIError as e:
        log.error("No se pudo eliminar %s: %s", c.name, e)
        audit(status="error", error=str(e), **base)


def watch_docker_events():
    while True:
        try:
            watch_client = docker.from_env()
            log.info("Monitoring container creation events")
            for ev in watch_client.events(decode=True, filters={"type": "container", "event": "create"}):
                try:
                    handle_create(watch_client, ev)
                except Exception:
                    log.exception("Error processing event")
        except Exception:
            log.exception("Monitoring for fall events; retry in 5 seconds")
            time.sleep(5)
PYFILE_EOF

"$GUARD_DIR/venv/bin/python" -m py_compile "$GUARD_DIR/monitor.py" || fail "monitor.py does not compile"

cat > "$ENV_FILE" << EOF
GUARD_TOKEN=$1
DRY_RUN=true
ENFORCE_MODE=all
EOF
chown root:root "$ENV_FILE"
chmod 600 "$ENV_FILE"
chown -R root:falco-guard "$GUARD_DIR"
chmod -R g+rX,o-rwx "$GUARD_DIR"

cat > /etc/systemd/system/falco-guard.service << 'UNIT_EOF'
[Unit]
Description=Falco Guard - automated response to container alerts
After=docker.service falco-modern-bpf.service
Requires=docker.service

[Service]
User=falco-guard
Group=falco-guard
SupplementaryGroups=docker
EnvironmentFile=/etc/falco-guard/env
WorkingDirectory=/opt/falco-guard
ExecStart=/opt/falco-guard/venv/bin/uvicorn monitor:app --host 127.0.0.1 --port 8080 --no-access-log
Restart=on-failure
RestartSec=3
LogsDirectory=falco-guard

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now falco-guard
systemctl restart falco-modern-bpf

log "Step 7 out of 7: Verification"
sleep 5
systemctl is-active docker falco-modern-bpf falco-guard
curl -s http://127.0.0.1:8080/health; echo

echo
echo "=============================================="
echo " Installation complete."
echo " Token saved in: $ENV_FILE"
echo " Log out and log back in to use Docker without sudo."
echo " Test with: sudo python3 $GUARD_DIR/run_tests.py"
echo "=============================================="
SCRIPT_EOF
chmod +x ~/setup-falco-guard.sh
