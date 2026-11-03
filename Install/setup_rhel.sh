# For RHEL/CentOS/Fedora/Rocky/Alma

cat > ~/falco-guard-repo/install/setup-falco-guard.sh << 'SCRIPT_EOF'
#!/usr/bin/env bash
set -euo pipefail

GUARD_DIR=/opt/falco-guard
ENV_FILE=/etc/falco-guard/env
LOG_DIR=/var/log/falco-guard

log() { echo -e "\n>>> $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "use SUDO."
[ -n "${1:-}" ] || fail "Use: sudo ./setup-falco-guard.sh <token>"
TOKEN="$1"
[ "${#TOKEN}" -ge 16 ] || fail "The token needs at least 16 characters."

# ---------- Detection ----------
if [ ! -f /etc/os-release ]; then
  fail "The distribution was not found (/etc/os-release no existe)."
fi
. /etc/os-release
DISTRO_FAMILY=""
case "${ID_LIKE:-$ID}" in
  *debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
  *rhel*|*fedora*|*centos*) DISTRO_FAMILY="rhel" ;;
  *) fail "Not supported distribution: ID=$ID ID_LIKE=${ID_LIKE:-}" ;;
esac
log "Detected distribution: $PRETTY_NAME (familia: $DISTRO_FAMILY)"

# ---------- kernel verification ----------
KVER=$(uname -r | cut -d. -f1,2)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
KMINOR=$(echo "$KVER" | cut -d. -f2)
if [ "$KMAJOR" -lt 5 ] || { [ "$KMAJOR" -eq 5 ] && [ "$KMINOR" -lt 8 ]; }; then
  log "Warning: kernel $KVER is less than 5.8. modern_ebpf it may not work;"
  log "the script will use the driver kmod as an alternative."
  FALCO_DRIVER="kmod"
else
  FALCO_DRIVER="modern_ebpf"
fi

# ============================================================
# Step 1: Docker Engine
# ============================================================
log "Installation of Docker Engine"
if ! command -v docker >/dev/null; then
  if [ "$DISTRO_FAMILY" = "debian" ]; then
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
    # RHEL/CentOS/Fedora/Rocky/Alma
    PKG_MGR=$(command -v dnf || command -v yum)
    "$PKG_MGR" install -y dnf-plugins-core 2>/dev/null || true
    "$PKG_MGR" config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo 2>/dev/null \
      || "$PKG_MGR" config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    "$PKG_MGR" install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
else
  log "Docker is already install, will be omitted."
fi
systemctl enable --now docker
REAL_USER="${SUDO_USER:-$USER}"
usermod -aG docker "$REAL_USER" || true

# ============================================================
# Step 2: Falco section
# ============================================================
log "Installation of Falco (driver: $FALCO_DRIVER)"
if ! command -v falco >/dev/null; then
  if [ "$DISTRO_FAMILY" = "debian" ]; then
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
      > /etc/apt/sources.list.d/falcosecurity.list
    apt-get update -y
    apt-get install -y dkms make "linux-headers-$(uname -r)" dialog || true
    FALCO_DRIVER_CHOICE=$FALCO_DRIVER FALCO_FRONTEND=noninteractive apt-get install -y falco
  else
    PKG_MGR=$(command -v dnf || command -v yum)
    curl -fsSL https://falco.org/repo/falcosecurity-rpm.repo -o /etc/yum.repos.d/falcosecurity.repo
    "$PKG_MGR" install -y "kernel-devel-$(uname -r)" dkms make gcc 2>/dev/null || true
    FALCO_DRIVER_CHOICE=$FALCO_DRIVER FALCO_FRONTEND=noninteractive "$PKG_MGR" install -y falco
  fi
else
  log "Falco is already installed, will be ommited."
fi


SCRIPT_EOF
