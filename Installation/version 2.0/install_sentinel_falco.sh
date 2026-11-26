#!/usr/bin/env bash
# The pipeline fails if any command in it fails; unset variables are errors.
set -euo pipefail
# New files will be private during the collection of data sensitive data is kept, we do not want everyone to read it
umask 077
#Colors to guide during the installation, for warnings
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1024 && 10#$1 <= 65535 )); }

MODE_FLAG=""
PORT_FLAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --enforce)   MODE_FLAG="enforce" ;;
    --detect)    MODE_FLAG="detect" ;;
    --port)
      [[ -n "${2:-}" ]] || { echo -e "${RED}[!] --port needs a value.${NC}" >&2; exit 1; }
      PORT_FLAG="$2"; shift ;;
    -h|--help)
      echo "Usage: $0 [--enforce | --detect] [--port N]"
      exit 0 ;;
    *) echo -e "${RED}[!] Unknown option: $1${NC}" >&2; exit 1 ;;
  esac
  shift
done
if [[ -n "$PORT_FLAG" ]] && ! valid_port "$PORT_FLAG"; then
  echo -e "${RED}[!] Invalid port '$PORT_FLAG' (use a number between 1024 and 65535).${NC}" >&2; exit 1
fi

[[ $EUID -eq 0 ]] || { echo -e "${RED}[!] Execute as root with sudo.${NC}"; exit 1; }

# Avoid interactive prompts and avoid restarts
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
export FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf
APT="apt-get install -y -qq -o Dpkg::Options::=--force-confold -o Acquire::Retries=3"

# --- Directory of the project 
#The 1st two are requirements
MIN_FALCO="0.38"                                              # minimun falco needed
RETENTION_DAYS=30                                             # for how long data is stored. avoid lots of old registers
INSTALL_DIR=/opt/Sentinel_Falco                               # where the 4 modules will be
DATA_DIR=/var/lib/Sentinel_Falco                              # alerts history and which containers are being isolated
COLLECT_INFO="$DATA_DIR/AUDIT"                                # snapshot.json, it has the info collected before it was isolated
BACKUP_DIR="$DATA_DIR/backup"                                 # previous versions of the Falco rules
FALCO_CONFIG=/etc/falco/config.d/configfalco.yaml             # Specifies using the modern eBPF driver, outputting in JSON format, and the URL (including a token) to which events should be sent via HTTP.
FALCO_RULES=/etc/falco/rules.d/rules_detection_falco.yaml     # Detection rules 9 total
POLICY_NAME=policy_rules_defined.yaml                         # reads policy.py what to do alert 
APT_KEYRING=/etc/apt/keyrings/verify_repo_install.gpg         # apt requirement to download
APT_LIST=/etc/apt/sources.list.d/falcosecurity.list           # repository to install
ENV_FILE=/etc/falco-guard.env                                 # token
NOTIFY_SCRIPT=/usr/local/bin/sentinel-notify.sh               # wall alerts with 60 sec of cooldown
CLEANUP_SCRIPT=/usr/local/bin/sentinel-cleanup.sh             # deletes old data
LOGROTATE_CONF=/etc/logrotate.d/sentinel-falco                # compress copies of logs to avoid it grows too much

say()  { echo -e "\033[0;34m[${1:-INFO}]\033[0m ${2:-}"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
die()  { echo -e "\033[0;31m[!] $1\033[0m" >&2; exit 1; }
# true if $1 (version) >= $2 (minimum), both "X.Y" or "X.Y.Z".
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]; }

# Temporary workspace (rules are validated here BEFORE touching /etc/falco) and temp env file.
TMP_DIR="$(mktemp -d /tmp/sentinel-falco.XXXXXX)"
TMP_ENV=""
cleanup() {
  [[ -n "$TMP_ENV" ]] && rm -f "$TMP_ENV"
  rm -rf "$TMP_DIR"
  return 0
}
trap cleanup EXIT

#==============================================================================
# Step 1: system validation
#==============================================================================
OS_ID="$( . /etc/os-release 2>/dev/null && echo "${ID:-unknown}" || echo unknown )"
OS_LIKE="$( . /etc/os-release 2>/dev/null && echo "${ID_LIKE:-}" || true )"
OS_NAME="$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$OS_ID}" || echo "$OS_ID" )"
OS_VERSION="$( . /etc/os-release 2>/dev/null && echo "${VERSION_ID:-0}" || echo 0 )"
case " $OS_ID $OS_LIKE " in
  *" ubuntu "*|*" debian "*|*" kali "*) ;;
  *) die "Unsupported distribution: $OS_NAME. Supported: Ubuntu, Debian and Kali Linux (or apt-based)." ;;
esac
if [[ "$OS_ID" == "ubuntu" ]]; then
  [[ "$OS_VERSION" =~ ^[0-9]+(\.[0-9]+)?$ ]] || OS_VERSION=0
  IFS=. read -r _maj _min <<< "$OS_VERSION"
  if ! (( 10#${_maj:-0} > 22 || (10#${_maj:-0} == 22 && 10#${_min:-0} >= 4) )); then
    die "Ubuntu $OS_VERSION is not supported: Ubuntu 22.04 or newer is required."
  fi
fi
IS_KALI=false
if [[ "$OS_ID" == "kali" ]]; then IS_KALI=true; fi

say "Step 1 of 8" "${BLUE}Validating system, kernel, systemd, port and mode${NC}"
if $IS_KALI; then say "KALI" "${CYAN}Kali Linux detected: $OS_NAME${NC}"; fi
#for deployments with windows 
WSL_NOTE=""
if grep -qi microsoft /proc/version 2>/dev/null; then
  WSL_NOTE=" WSL detected: the default WSL kernel often has no BTF and needs systemd enabled ([boot] systemd=true in /etc/wsl.conf)."
fi
[[ -f /sys/kernel/btf/vmlinux ]] || die "Missing /sys/kernel/btf/vmlinux: modern_ebpf won't work (kernel $(uname -r)).$WSL_NOTE"
[[ -d /run/systemd/system ]]    || die "systemd is not running: Sentinel_Falco installs systemd services.$WSL_NOTE"

# Port validation 
OLD_PORT=""
OLD_MODE=""
if [[ -f "$ENV_FILE" ]]; then
  OLD_PORT="$(sed -n 's/^GUARD_PORT=//p' "$ENV_FILE" | head -n 1)"
  OLD_MODE="$(sed -n 's/^GUARD_DETECTION_MODE=//p' "$ENV_FILE" | head -n 1)"
fi
PORT="${PORT_FLAG:-${OLD_PORT:-8080}}"
valid_port "$PORT" || die "Invalid port '$PORT' (check GUARD_PORT in $ENV_FILE)."
port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
if port_in_use "$PORT"; then
  if systemctl is-active --quiet falco-guard.service 2>/dev/null && [[ "$PORT" == "${OLD_PORT:-8080}" ]]; then
    say "PORT" "${CYAN}127.0.0.1:$PORT is used by the running falco-guard (reinstall).${NC}"
  else
    die "Port $PORT is already used by another program (Burp Suite and ZAP use 8080 by default). Choose another one: sudo $0 --port 18080"
  fi
fi

# Mode: explicit flag wins; otherwise keep what the previous install used; first install = detection.
case "$MODE_FLAG" in
  enforce) DETECTION=false ;;
  detect)  DETECTION=true ;;
  *)       if [[ "$OLD_MODE" == "false" ]]; then DETECTION=false; else DETECTION=true; fi ;;
esac
if [[ -z "$MODE_FLAG" && -n "$OLD_MODE" ]]; then
  say "MODE" "Maintain the mode of the previous install ($([[ $DETECTION == true ]] && echo detection || echo enforce))."
fi

#==============================================================================
# Step 2: Installation of dependencies 
#==============================================================================
say "Step 2 of 8" "${BLUE}Installing dependencies${NC}"
command -v apt-get >/dev/null || die "This installer only supports Debian/Ubuntu (apt)."
apt-get update -qq
$APT ca-certificates curl gnupg openssl python3 python3-venv jq
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
  || die "Python >= 3.10 is required (you have $(python3 -V 2>&1))."

#==============================================================================
# Step 3: Validates Docker
#==============================================================================
say "Step 3 of 8" "${BLUE}Verifying Docker installation${NC}"
DOCKER_INSTALL_HINT=""
DOCKER_START_HINT="sudo systemctl start docker"
if $IS_KALI; then
  DOCKER_INSTALL_HINT=" On Kali: sudo apt install docker.io"
  DOCKER_START_HINT="sudo systemctl enable --now docker"
fi
command -v docker >/dev/null 2>&1 \
  || die "Docker is not installed. Install and configure Docker before Sentinel_Falco.$DOCKER_INSTALL_HINT"
systemctl is-active --quiet docker || systemctl is-active --quiet snap.docker.dockerd \
  || die "Docker service is not running. Start it with: $DOCKER_START_HINT"
docker info >/dev/null 2>&1 || die "Cannot communicate with the Docker daemon. Check the Docker service."
ok "Docker is installed and functional."

#==============================================================================
# Step 4: Falco (if needed downloaded from original repo) and version check
#==============================================================================
say "Step 4 of 8" "${BLUE}Installing / verifying Falco (>= $MIN_FALCO)${NC}"
falco_version() {   # prints MAJOR.MINOR, or nothing if it cannot be determined
  local v=""
  # 1) the installed package version is the most reliable source on apt systems
  v="$(dpkg-query -W -f='${Version}' falco 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+' | head -n 1 || true)"
  # 2) fall back to the binary itself (stdout + stderr, first "Falco version" line)
  if [[ -z "$v" ]]; then
    v="$(falco --version 2>&1 | grep -iE 'falco.*version' | grep -oE '[0-9]+\.[0-9]+' | head -n 1 || true)"
  fi
  printf '%s' "$v"
}

if ! command -v falco >/dev/null; then
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://falco.org/repo/falcosecurity-packages.asc -o "$TMP_DIR/falco.asc"
  gpg --batch --dearmor --yes -o "$APT_KEYRING" "$TMP_DIR/falco.asc"
  chmod 644 "$APT_KEYRING"   # apt reads it as user _apt (umask is 077) 
  echo "deb [signed-by=$APT_KEYRING] https://download.falco.org/packages/deb stable main" > "$APT_LIST"
  chmod 644 "$APT_LIST"
  apt-get update -qq
  $APT falco
fi
if command -v falco >/dev/null; then
  FVER="$(falco_version || true)"
  if [[ -z "$FVER" ]]; then
    # Cannot tell the version: do not block. The rule validation in Step 5 catches real incompatibilities.
    warn "Could not read the Falco version (check: falco --version). Continuing; rules are validated in Step 5."
  elif ! ver_ge "$FVER" "$MIN_FALCO"; then
    die "Falco $FVER is too old: >= $MIN_FALCO is required (config.d / rules.d need it). Upgrade: sudo apt-get install --only-upgrade falco"
  else
    ok "Falco $FVER detected."
  fi
fi

#==============================================================================
# Step 5: generate and VALIDATE the Falco rules (nothing is written to /etc yet)
#==============================================================================
say "Step 5 of 8" "${BLUE}Generating and validating detection rules${NC}"

# NOTE: Falco runs as a host service, so no container needs a "trusted image" exemption.
# (Trusting an image NAME is spoofable: `docker tag alpine <name>` would bypass every rule.)
cat > "$TMP_DIR/core.yaml" <<'__RULES_EOF__'
# Sentinel_Falco detection rules. Requires Falco >= 0.38.
- macro: guard_open
  condition: (evt.type in (open, openat, openat2) and fd.num >= 0)
- macro: guard_spawn
  condition: (evt.type in (execve, execveat))
# Container startup: runc opens the container rootfs while creating it (noise, not an attack).
- macro: guard_runc_startup
  condition: (proc.name startswith "runc:" and (fd.name startswith /var/lib/docker/rootfs/overlayfs/ or fd.name startswith /var/lib/docker/overlay2/))

- rule: Host Filesystem non Authorized
  desc: A container opens files from host paths (host mounts, /proc/1/root, runtime dirs)
  condition: >
    guard_open and container.id != host and not guard_runc_startup and
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
    container.id != host and
    (fd.name endswith release_agent or fd.name = /proc/sys/kernel/core_pattern or
     fd.name = /proc/sys/kernel/modprobe or fd.name = /sys/kernel/uevent_helper)
  output: >
    Possible container escape (file=%fd.name proc=%proc.cmdline container=%container.name id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]

- rule: Runtime Socket non Authorized
  desc: A container opens or connects to the Docker/containerd/CRI-O socket
  condition: >
    (guard_open or (evt.type = connect and evt.dir = <)) and container.id != host and
    (fd.name contains docker.sock or fd.name contains containerd.sock or fd.name contains crio.sock)
  output: >
    Access to the runtime socket (sock=%fd.name proc=%proc.cmdline container=%container.name
    image=%container.image.repository id=%container.id)
  priority: CRITICAL
  tags: [container, runtime_socket, guard]

- rule: NSENTER Execution
  desc: nsenter executed inside a container
  condition: guard_spawn and container.id != host and proc.name = nsenter
  output: >
    nsenter in container (cmd=%proc.cmdline container=%container.name id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]

- rule: Mount Detection
  desc: mount() call from a container
  condition: evt.type = mount and container.id != host and not proc.name startswith "runc:"
  output: >
    mount() in container (args=%evt.args proc=%proc.cmdline container=%container.name id=%container.id)
  priority: WARNING
  tags: [container, mount, guard]

- rule: Interactive Shell Active
  desc: Interactive shell inside a container
  condition: >
    guard_spawn and container.id != host and
    proc.name in (bash, sh, zsh, ash, dash) and proc.tty != 0
  output: >
    Interactive shell (cmd=%proc.cmdline user=%user.name container=%container.name id=%container.id)
  priority: NOTICE
  tags: [container, shell, guard]
__RULES_EOF__

# Optional rule: detects the host root (or /etc, /root) bind-mounted into a container
cat > "$TMP_DIR/mount.yaml" <<'__RULES_EOF__'

- rule: Sensitive Host Mount
  desc: Container started with the host root, /etc or /root bind-mounted (any destination path)
  condition: >
    guard_spawn and container.id != host and proc.vpid = 1 and
    (container.mounts startswith "/:" or container.mounts contains " /:" or
     container.mounts startswith "/etc:" or container.mounts contains " /etc:" or
     container.mounts startswith "/root:" or container.mounts contains " /root:")
  output: >
    Sensitive host directory mounted in container (mounts=%container.mounts cmd=%proc.cmdline
    container=%container.name image=%container.image.repository id=%container.id)
  priority: CRITICAL
  tags: [container, host_mount, guard]
__RULES_EOF__

# Optional rule: catches a process changing its working directory into a /proc/<pid>/fd/<n>
# descriptor instead of a real path -- nobody does this legitimately. It is the generic
# signature of the CVE-2024-21626 technique (runc leaks a directory fd that is later used
# via -w /proc/self/fd/N, landing the container's cwd on the host filesystem). It fires
# BEFORE the container reads or writes anything through that cwd.
# Depends on evt.arg.path for the chdir syscall; some Falco builds expose it under a
# different field name, so this file is validated on its own and skipped if rejected.
cat > "$TMP_DIR/escape_fd.yaml" <<'__RULES_EOF__'

- rule: Procfs File Descriptor Breakout Attempt
  desc: A container process changes its working directory into a /proc/<pid>/fd/<n> entry (CVE-2024-21626 pattern)
  condition: >
    evt.type = chdir and container.id != host and
    evt.arg.path startswith /proc/ and evt.arg.path contains /fd/
  output: >
    chdir into a /proc file descriptor, possible host breakout (path=%evt.arg.path
    proc=%proc.cmdline container=%container.name image=%container.image.repository id=%container.id)
  priority: CRITICAL
  tags: [container, escape, guard]
__RULES_EOF__

# Optional rule: a container opening /etc/shadow or /etc/gshadow. IMPORTANT LIMITATION: every
# container image ships its own /etc/shadow, and Falco sees the same resolved path "/etc/shadow"
# whether the process is reading its own file or the host's through a breakout like the one above --
# there is no field that tells the two apart. The trusted-binary exclusion below keeps this from
# firing on normal login/password tooling; anything else opening it (a shell, a custom binary) is
# almost always abnormal, including the escaped read in the CVE-2024-21626 demo. Tune
# guard_sensitive_reader_trusted if a legitimate process in your containers needs this file.
cat > "$TMP_DIR/sensitive_file.yaml" <<'__RULES_EOF__'

- macro: guard_sensitive_file
  condition: >
    (fd.name = /etc/shadow or fd.name = /etc/gshadow or
     fd.name startswith /etc/shadow- or fd.name startswith /etc/gshadow-)
- macro: guard_sensitive_reader_trusted
  condition: >
    (proc.name in (login, sshd, passwd, chpasswd, useradd, userdel, usermod, groupadd,
                   groupdel, groupmod, su, sudo, unix_chkpwd, vipw, vigr, chage, chfn, chsh))

- rule: Sensitive Host File Access
  desc: A container process opens /etc/shadow or /etc/gshadow outside of normal auth tooling
  condition: guard_open and container.id != host and guard_sensitive_file and not guard_sensitive_reader_trusted
  output: >
    Sensitive credential file opened in container (file=%fd.name proc=%proc.cmdline user=%user.name
    container=%container.name image=%container.image.repository id=%container.id)
  priority: CRITICAL
  tags: [container, credentials, guard]
__RULES_EOF__

falco_check() {  # falco_check file...  -> validates the given rule files together with the stock ruleset
  local args=(-V /etc/falco/falco_rules.yaml) f
  for f in "$@"; do args+=(-V "$f"); done
  falco "${args[@]}" > "$TMP_DIR/falco_check.log" 2>&1
}

# Each optional file is validated on top of whatever was already accepted, so one rule this
# Falco build rejects does not take any of the others down with it.
RULES_ALL="$TMP_DIR/rules_all.yaml"
ACCEPTED=("$TMP_DIR/core.yaml")
OPTIONAL=(
  "$TMP_DIR/mount.yaml:Sensitive Host Mount"
  "$TMP_DIR/escape_fd.yaml:Procfs File Descriptor Breakout Attempt"
  "$TMP_DIR/sensitive_file.yaml:Sensitive Host File Access"
)
if command -v falco >/dev/null; then
  falco_check "${ACCEPTED[@]}" || { cat "$TMP_DIR/falco_check.log" >&2; die "Falco rejected the core rules (see above). Nothing was changed on the system."; }
  ok "Core rules are valid."
  for entry in "${OPTIONAL[@]}"; do
    f="${entry%%:*}"; label="${entry#*:}"
    if falco_check "${ACCEPTED[@]}" "$f"; then
      ACCEPTED+=("$f")
      ok "'$label' rule is valid."
    else
      warn "'$label' is not supported by this Falco build: skipped (the rest of the ruleset is unaffected)."
    fi
  done
else
  # Defensive fallback: Step 4 installs Falco unconditionally, so this should not happen in practice.
  for entry in "${OPTIONAL[@]}"; do ACCEPTED+=("${entry%%:*}"); done
  warn "Falco was not found: rules were not validated against it."
fi
cat "${ACCEPTED[@]}" > "$RULES_ALL"

#==============================================================================
# Step 6: guard code, virtualenv and policy
#==============================================================================
say "Step 6 of 8" "${BLUE}Deploying Sentinel_Falco in $INSTALL_DIR${NC}"
mkdir -p "$INSTALL_DIR/guard" "$INSTALL_DIR/config" /etc/falco/rules.d /etc/falco/config.d
install -d -m 700 "$DATA_DIR" "$COLLECT_INFO" "$BACKUP_DIR"
touch "$INSTALL_DIR/guard/__init__.py"

cat > "$INSTALL_DIR/guard/policy.py" <<'__GUARD_EOF__'
"""Decision engine: ignore, alert or isolate."""
import logging
from dataclasses import dataclass

import yaml

log = logging.getLogger("guard.policy")

VALID_ACTIONS = ("alert", "isolate")


@dataclass
class DecisionActions:
    action: str  # ignore | alert | isolate
    reason: str


class Policies:
    def __init__(self, cfg: dict):
        self.cfg = cfg if isinstance(cfg, dict) else {}
        if not isinstance(self.cfg.get("rules"), dict):
            log.critical("policy has no 'rules' mapping: every guard rule will only alert")
            self.cfg["rules"] = {}

    @classmethod
    def from_file(cls, path: str) -> "Policies":
        with open(path) as f:
            return cls(yaml.safe_load(f) or {})

    def _rule_action(self, rule: str):
        entry = self.cfg["rules"].get(rule)
        if isinstance(entry, str):          # tolerate "Rule: isolate"
            return entry
        if isinstance(entry, dict):
            return entry.get("action")
        return None

    def decide(self, event: dict) -> DecisionActions:
        fields = event.get("output_fields")
        if not isinstance(fields, dict):
            fields = {}
        cid = fields.get("container.id")
        if not cid or cid == "host":
            return DecisionActions("ignore", "event outside a container")

        # Only the guard's own rules take part; stock Falco rules would only add noise.
        tags = event.get("tags")
        if not isinstance(tags, list) or "guard" not in tags:
            return DecisionActions("ignore", "rule not owned by the guard")

        rule = event.get("rule") or ""
        action = self._rule_action(rule)
        if action not in VALID_ACTIONS:
            return DecisionActions("alert", f"rule without a valid policy: {rule!r}")
        if action == "isolate":
            return DecisionActions("isolate", f"Critical rule: {rule}")
        return DecisionActions("alert", "alert only")
__GUARD_EOF__

cat > "$INSTALL_DIR/guard/isolation_recovery_container.py" <<'__GUARD_EOF__'
"""Container isolation and recovery via the Docker SDK (atomic state, evidence, partial rollback)."""
import json
import logging
import os
import threading
import time

import docker

log = logging.getLogger("guard.isolator")

VALID_STEPS = ("network", "pause", "stop")
_ORDER = {"network": 0, "pause": 1, "stop": 2}
_HEX = set("0123456789abcdef")


def normalize_steps(steps) -> list:
    """Drop unknown steps, deduplicate and enforce network -> pause -> stop."""
    raw = [s for s in (steps or []) if isinstance(s, str)]
    for s in raw:
        if s not in VALID_STEPS:
            log.warning("unknown isolation step %r ignored", s)
    kept = [s for s in dict.fromkeys(raw) if s in VALID_STEPS] or ["network", "pause"]
    kept.sort(key=_ORDER.get)
    if "stop" in kept and "pause" in kept:
        kept.remove("pause")                # pause is redundant once the container is stopped
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

    # --- persistence (atomic, with a .bak fallback) -------------------------
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
                log.error("unreadable state file %s, trying fallback", path)
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

    # --- docker -------------------------------------------------------------
    @property
    def client(self):
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _find(self, cid):
        """Match by full id, by unambiguous short id (Falco sends 12 chars) or by exact name."""
        if not cid:
            return None
        if cid in self.state:
            return cid
        low = cid.lower()
        if len(low) >= 12 and set(low) <= _HEX:
            matches = [k for k in self.state if k.startswith(low)]
            if len(matches) == 1:
                return matches[0]
        for key, rec in self.state.items():
            if rec.get("name") != cid:
                continue
            try:
                self.client.containers.get(key)     # the record must still point at a real container
                return key
            except docker.errors.NotFound:
                continue
            except Exception:
                return key                           # docker unreachable: trust the record
        return None

    def is_isolated(self, cid) -> bool:
        return self._find(cid) is not None

    def prune_stale(self) -> list:
        """Forget records whose container no longer exists."""
        with self._lock:
            gone = []
            for key in list(self.state):
                try:
                    self.client.containers.get(key)
                except docker.errors.NotFound:
                    gone.append(key)
                except Exception:
                    continue
            for key in gone:
                self.state.pop(key, None)
            if gone:
                self._save()
                log.info("pruned %d stale isolation record(s)", len(gone))
            return gone

    # --- forensics (best effort, never blocks containment) ------------------
    def _gather_info(self, c, procs) -> str:
        attrs = json.loads(json.dumps(c.attrs, default=str))
        cfg = attrs.get("Config") or {}
        cfg["Env"] = [e.split("=", 1)[0] + "=<redacted>" for e in cfg.get("Env") or []]
        info = {"inspect": attrs, "processes_before_isolation": procs}
        for key, fn in (("fs_diff", c.diff),
                        ("logs_tail", lambda: c.logs(tail=200).decode(errors="replace"))):
            try:
                info[key] = fn()
            except Exception as e:
                info[key + "_error"] = str(e)
        path = os.path.join(self.collect_info, f"{c.name}-{int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(info, f, indent=2, default=str)
        os.chmod(path, 0o600)
        return path

    # --- lifecycle ----------------------------------------------------------
    def isolate(self, cid: str, reason: str) -> dict:
        with self._lock:
            existing = self._find(cid)
            if existing:
                return {"status": "already_isolated", "container": self.state[existing].get("name")}
            c = self.client.containers.get(cid)
            host_net = (c.attrs.get("HostConfig") or {}).get("NetworkMode") == "host"
            nets = list((c.attrs.get("NetworkSettings") or {}).get("Networks") or {})
            # Network cannot be detached with network_mode=host or when there is nothing to detach.
            steps = [s for s in self.steps if not (s == "network" and (host_net or not nets))] or ["pause"]
            if self.detection_mode:
                return {"status": "detection_mode", "container": c.name, "would_do": steps}

            # Contain FIRST. Only a cheap process snapshot is taken before (top fails on paused containers).
            procs = None
            if c.status == "running":
                try:
                    procs = c.top()
                except Exception as e:
                    procs = {"error": str(e)}

            # Register before touching the container so a crash half-way stays recoverable.
            self.state[c.id] = {"name": c.name, "networks": nets, "done": [], "reason": reason,
                                "ts": time.time(), "forensics": None}
            self._save()
            rec = self.state[c.id]
            errors = []
            for step in steps:
                try:
                    if step == "network":
                        ok = 0
                        for n in nets:
                            try:
                                self.client.networks.get(n).disconnect(c, force=True)
                                ok += 1
                            except Exception as e:
                                errors.append(f"network {n}: {e}")
                        if not ok:
                            continue
                    elif step == "pause":
                        c.pause()
                    elif step == "stop":
                        c.stop(timeout=5)
                    rec["done"].append(step)
                    self._save()
                except Exception as e:
                    log.exception("isolation step %s failed on %s", step, c.name)
                    errors.append(f"{step}: {e}")

            done = list(rec["done"])
            if not done:                       # nothing was applied: do not pretend it is isolated
                self.state.pop(c.id, None)
                self._save()

            try:
                forensics = self._gather_info(c, procs)
            except Exception:
                log.exception("evidence collection failed for %s", c.name)
                forensics = None
            if done:
                rec["forensics"] = forensics
                self._save()

            status = "failed" if not done else ("partially_isolated" if errors else "isolated")
            log.warning("container %s -> %s (%s)", c.name, status, done)
            return {"status": status, "container": c.name, "steps": done,
                    "errors": errors, "forensics": forensics}

    def release(self, cid: str, force: bool = False) -> dict:
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
            done = rec.get("done", [])
            if "stop" in done:
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
            if "network" in done:
                current = set((c.attrs.get("NetworkSettings") or {}).get("Networks") or {})
                for n in rec.get("networks", []):
                    if n in current:
                        continue
                    try:
                        self.client.networks.get(n).connect(c)
                    except Exception as e:
                        errors.append(f"connect {n}: {e}")

            if errors and not force:
                return {"status": "partially_released", "container": rec.get("name"),
                        "errors": errors, "hint": "retry, or add ?force=true to drop the record"}
            self.state.pop(key, None)
            self._save()
            return {"status": "released", "container": rec.get("name"), "errors": errors}
__GUARD_EOF__

cat > "$INSTALL_DIR/guard/notification_alerter.py" <<'__GUARD_EOF__'
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
            log.error("notification delivery failed: %s", e)   # never log the URL: it holds a secret

    def send(self, event: dict, decision, result):
        f = event.get("output_fields") or {}
        alert = {
            "ts": event.get("time") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rule": event.get("rule"), "priority": event.get("priority"),
            "container": f.get("container.name"), "container_id": f.get("container.id"),
            "image": f.get("container.image.repository"), "file": f.get("fd.name"),
            "cmd": f.get("proc.cmdline"), "mounts": f.get("container.mounts"),
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
                f"Details: `{alert['file'] or alert['cmd'] or alert['mounts']}`\n"
                f"Action: *{decision.action}* \u2014 {decision.reason}")
        for url, payload in ((self.slack_url, {"text": text}), (self.webhook_url, alert)):
            if url:
                threading.Thread(target=self._post, args=(url, payload), daemon=True).start()
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
POLICY = os.getenv("GUARD_POLICY", "/opt/Sentinel_Falco/config/policy_rules_defined.yaml")
os.makedirs(DATA, exist_ok=True)

engine = Policies.from_file(POLICY)
# Safe default: if the variable is missing the guard only detects. The installer always sets it.
detection_mode = os.getenv("GUARD_DETECTION_MODE", "true").strip().lower() in ("1", "true", "yes")
isolator = ContainerIsolation(engine.cfg.get("isolation"), detection_mode, DATA)
notifier = Notificationalert(os.path.join(DATA, "alerts.jsonl"),
                             os.getenv("SLACK_WEBHOOK_URL"), os.getenv("ALERT_WEBHOOK_URL"))

app = FastAPI(title="Sentinel_Falco", docs_url=None, redoc_url=None, openapi_url=None)


def require_token(token: str | None = Query(None), x_guard_token: str | None = Header(None)):
    """Header first, query parameter as fallback (Falco sends the token in the URL). Fails closed."""
    if not TOKEN:
        logging.critical("GUARD_TOKEN is missing: refusing authenticated requests.")
        raise HTTPException(503, "Authentication is not configured")
    supplied = x_guard_token or token
    if not supplied or not hmac.compare_digest(supplied.encode(), TOKEN.encode()):
        raise HTTPException(401, "Invalid authentication token")


@app.post("/falco", dependencies=[Depends(require_token)])
def falco_event(event: dict):
    decision = engine.decide(event)
    if decision.action == "ignore":
        return {"decision": "ignore", "reason": decision.reason}

    result = None
    if decision.action == "isolate":
        cid = (event.get("output_fields") or {}).get("container.id")
        try:
            result = isolator.isolate(cid, decision.reason)
        except Exception as e:  # never lose the alert because of an isolation failure
            logging.exception("Failed to isolate %s", cid)
            result = {"status": "error", "error": str(e)}

    # A container that is already contained does not need to be announced again.
    if not (isinstance(result, dict) and result.get("status") == "already_isolated"):
        notifier.send(event, decision, result)
    return {"decision": decision.action, "reason": decision.reason, "isolation": result}


@app.get("/health")
def health():
    return {"status": "ok", "detection_mode": detection_mode, "isolation_steps": isolator.steps}


@app.get("/isolated_container", dependencies=[Depends(require_token)])
def isolated_container():
    isolator.prune_stale()
    return isolator.state


@app.post("/release/{cid}", dependencies=[Depends(require_token)])
def release(cid: str, force: bool = False):
    return isolator.release(cid, force)
__GUARD_EOF__

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q "fastapi==0.115.*" "uvicorn[standard]==0.32.*" "docker==7.1.*" "PyYAML==6.0.*" "requests==2.32.*"

# --- Policy: an existing one is preserved (it is user-tunable); the new default is saved as .new ---
cat > "$TMP_DIR/policy.yaml" <<'__POLICY_EOF__'
# Sentinel_Falco response policy.
# Detection vs enforcement is controlled by the installer (--detect / --enforce) via GUARD_DETECTION_MODE.
isolation: [network, pause]   # steps, applied in this order: network (disconnect) -> pause (freeze) | stop

rules:
  "Host Filesystem non Authorized":            {action: isolate}
  "File Modification Escape Attempt":          {action: isolate}
  "Runtime Socket non Authorized":              {action: isolate}
  "NSENTER Execution":                          {action: isolate}
  "Sensitive Host Mount":                       {action: isolate}
  "Procfs File Descriptor Breakout Attempt":    {action: isolate}
  "Sensitive Host File Access":                 {action: isolate}
  "Mount Detection":                            {action: alert}
  "Interactive Shell Active":                   {action: alert}
__POLICY_EOF__

POLICY_DST="$INSTALL_DIR/config/$POLICY_NAME"
if [[ -f "$POLICY_DST" ]]; then
  install -m 600 "$TMP_DIR/policy.yaml" "$POLICY_DST.new"
  warn "$POLICY_NAME already exists and is preserved; the new default is in $POLICY_DST.new"
else
  install -m 600 "$TMP_DIR/policy.yaml" "$POLICY_DST"
fi

# Cross-check the policy that will really be used against the rules about to be installed.
"$INSTALL_DIR/venv/bin/python" - "$POLICY_DST" "$RULES_ALL" <<'__PY__' || die "Policy validation failed (see above). Nothing was activated."
import sys, yaml
pol = yaml.safe_load(open(sys.argv[1])) or {}
rules = {r["rule"] for r in (yaml.safe_load(open(sys.argv[2])) or []) if isinstance(r, dict) and "rule" in r}
entries = pol.get("rules")
if not isinstance(entries, dict):
    sys.exit("policy: 'rules' must be a mapping")
errors = []
for name, entry in entries.items():
    action = entry if isinstance(entry, str) else (entry or {}).get("action")
    if action not in ("alert", "isolate"):
        errors.append(f"policy: invalid action for {name!r}: {action!r}")
for step in pol.get("isolation") or []:
    if step not in ("network", "pause", "stop"):
        errors.append(f"policy: invalid isolation step: {step!r}")
if errors:
    sys.exit("\n".join(errors))
for name in sorted(rules - set(entries)):
    print(f"[!] rule {name!r} has no policy entry: it will only alert", file=sys.stderr)
for name in sorted(set(entries) - rules):
    print(f"[i] policy entry {name!r} has no matching rule (ignored)", file=sys.stderr)
print(f"policy OK: {len(entries)} entries, steps {pol.get('isolation')}")
__PY__

# Validated: now the rules can go to /etc/falco. The previous version is backed up outside rules.d.
if [[ -f "$FALCO_RULES" ]] && ! cmp -s "$FALCO_RULES" "$RULES_ALL"; then
  BK="$BACKUP_DIR/$(basename "$FALCO_RULES").$(date +%Y%m%d%H%M%S)"
  cp -p "$FALCO_RULES" "$BK"
  say "BACKUP" "Previous rules saved in $BK"
fi
install -m 644 "$RULES_ALL" "$FALCO_RULES"
rm -f "$FALCO_RULES.new"      # stale file from older installers

#==============================================================================
# Step 7: token, Falco config, notifications, retention and systemd units
#==============================================================================
say "Step 7 of 8" "${BLUE}Configuring token, Falco output, notifications and services${NC}"

# Keep an existing valid token, otherwise generate one.
TOKEN="$(sed -n 's/^GUARD_TOKEN=//p' "$ENV_FILE" 2>/dev/null | head -n 1 || true)"
[[ "$TOKEN" =~ ^[[:xdigit:]]{48,128}$ ]] || TOKEN="$(openssl rand -hex 32)"

# Rewrite the env file atomically (mktemp creates it 600), keeping other variables such as SLACK_WEBHOOK_URL.
TMP_ENV="$(mktemp "$ENV_FILE.XXXXXX")"
{
  grep -v -E '^(GUARD_TOKEN|GUARD_DETECTION_MODE|GUARD_PORT)=' "$ENV_FILE" 2>/dev/null || true
  printf 'GUARD_TOKEN=%s\n' "$TOKEN"
  printf 'GUARD_DETECTION_MODE=%s\n' "$DETECTION"
  printf 'GUARD_PORT=%s\n' "$PORT"
} > "$TMP_ENV"
mv -f "$TMP_ENV" "$ENV_FILE"
TMP_ENV=""

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

# --- Guard service (hardened). --no-access-log keeps the token out of the journal. ---
cat > /etc/systemd/system/falco-guard.service <<EOC
[Unit]
Description=Sentinel_Falco: alerts and automatic isolation of containers
After=docker.service network.target
Wants=docker.service

[Service]
User=root
UMask=0077
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
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
LockPersonality=yes

[Install]
WantedBy=multi-user.target
EOC

# --- Live terminal notifications (wall). Cooldown per rule+container. ---
cat > "$NOTIFY_SCRIPT" <<'__NOTIFY_EOF__'
#!/usr/bin/env bash
# Sentinel_Falco: broadcast a terminal alert (wall) for every new alert, with cooldown.
set -uo pipefail
export LC_ALL=C.UTF-8
ALERTS=/var/lib/Sentinel_Falco/alerts.jsonl
COOLDOWN=60        # seconds before the same rule+container can notify again

clean() { local s="${1//[[:cntrl:]]/}"; printf '%s' "${s:0:200}"; }   # strip control characters coming from containers

declare -A last
tail -n0 -F "$ALERTS" 2>/dev/null | while read -r line; do
  rule=$(clean "$(jq -r '.rule // "?"' <<<"$line" 2>/dev/null)")
  cont=$(clean "$(jq -r '.container // "?"' <<<"$line" 2>/dev/null)")
  dec=$(clean "$(jq -r '.decision // "?"' <<<"$line" 2>/dev/null)")
  det=$(clean "$(jq -r '.file // .cmd // .mounts // ""' <<<"$line" 2>/dev/null)")

  key="$rule|$cont"          # per rule: a low-severity alert must never hide a critical one
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
Wants=falco-guard.service

[Service]
ExecStart=/usr/local/bin/sentinel-notify.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOC

# --- Retention: rotate alerts.jsonl and purge old evidence ---
cat > "$LOGROTATE_CONF" <<'EOC'
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
chmod 644 "$LOGROTATE_CONF"

cat > "$CLEANUP_SCRIPT" <<EOC
#!/usr/bin/env bash
set -euo pipefail
find $COLLECT_INFO -type f -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -type f -mtime +365 -delete
EOC
chmod 755 "$CLEANUP_SCRIPT"

cat > /etc/systemd/system/sentinel-cleanup.service <<EOC
[Unit]
Description=Sentinel_Falco: purge old forensic evidence

[Service]
Type=oneshot
ExecStart=$CLEANUP_SCRIPT
EOC

cat > /etc/systemd/system/sentinel-cleanup.timer <<'EOC'
[Unit]
Description=Daily Sentinel_Falco evidence cleanup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOC

#==============================================================================
# Step 8: start services
#==============================================================================
say "Step 8 of 8" "${CYAN}Starting services${NC}"
systemctl daemon-reload
systemctl enable falco-guard.service sentinel-notify.service sentinel-cleanup.timer >/dev/null
systemctl restart falco-guard.service               # guard first... (also applies new code/port on a reinstall)
systemctl restart sentinel-notify.service
systemctl restart sentinel-cleanup.timer
systemctl disable --now falco-kmod.service falco-bpf.service 2>/dev/null || true
systemctl enable falco-modern-bpf.service >/dev/null
systemctl restart falco-modern-bpf.service           # ...then Falco

for _ in {1..15}; do curl -fs "http://127.0.0.1:$PORT/health" >/dev/null && break || sleep 1; done
curl -fs "http://127.0.0.1:$PORT/health" || die "The guard is not responding: journalctl -u falco-guard -n 30"
echo
systemctl is-active --quiet falco-modern-bpf || die "Falco could not start: journalctl -u falco-modern-bpf -n 30"
systemctl is-active --quiet sentinel-notify   || die "Notification service is not running: journalctl -u sentinel-notify -n 30"

cat <<EOM

===========================================================================================================================
 Sentinel_Falco installed. Mode: $([[ $DETECTION == true ]] && echo "DETECTION (detects and alerts only, no isolation)" || echo "ENFORCE (real isolation)")
===========================================================================================================================
API:        http://127.0.0.1:$PORT   (token in $ENV_FILE)
Alerts:     tail -f $DATA_DIR/alerts.jsonl   (live terminal alerts are broadcast automatically)
Logs:       journalctl -u falco-guard -f | journalctl -u falco-modern-bpf -f | journalctl -u sentinel-notify -f
Evidence:   $COLLECT_INFO   (purged after $RETENTION_DAYS days)
Release:    curl -X POST -H "X-Guard-Token: \$TOKEN" http://127.0.0.1:$PORT/release/<name_or_id>
EOM
