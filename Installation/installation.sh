#!/usr/bin/env bash
# ==============================================================================
# Falco Sentinel - One-Click Automated Linux Installer
# Sets up Falco with Modern eBPF & the Python Automated Isolation Sentinel
# Supported: Ubuntu 20.04/22.04/24.04, Debian 11/12, Rocky Linux 9, RHEL 9, Fedora
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}"
echo "=============================================================="
echo "      Falco Sentinel - Automated eBPF Security Setup          "
echo "=============================================================="
echo -e "${NC}"

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This installation script must be run as root (use sudo).${NC}"
   exit 1
fi

# 1. Pre-flight Kernel & eBPF Compatibility Verification
echo -e "${BLUE}[1/6] Checking Linux Kernel and modern eBPF BTF support...${NC}"
KERNEL_VERSION=$(uname -r)
echo "    -> Kernel release: $KERNEL_VERSION"

if [[ -f "/sys/kernel/btf/vmlinux" ]]; then
    echo -e "${GREEN}    [✓] Kernel BTF (/sys/kernel/btf/vmlinux) detected! Modern eBPF is fully supported.${NC}"
else
    echo -e "${YELLOW}    [!] Warning: /sys/kernel/btf/vmlinux not found directly.${NC}"
    echo "        Falco will attempt to load BTF from kernel-devel/kernel-headers or fallback to kernel module."
fi

# 2. Verify Docker Engine
echo -e "${BLUE}[2/6] Verifying Docker daemon presence...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}    -> Docker is not installed. Installing Docker Engine...${NC}"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
else
    echo -e "${GREEN}    [✓] Docker is installed and running.${NC}"
fi

# Ensure quarantine Docker network exists
docker network inspect falco-quarantine &>/dev/null || \
    docker network create --driver bridge --internal falco-quarantine

# 3. Install Falco from official repository
echo -e "${BLUE}[3/6] Installing official Falco package...${NC}"
if command -v apt-get &> /dev/null; then
    # Debian / Ubuntu
    apt-get update -qq
    apt-get install -y -qq curl gnupg software-properties-common lsb-release
    
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /etc/apt/keyrings/falco-archive-keyring.gpg --yes
    echo "deb [signed-by=/etc/apt/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
    
    apt-get update -qq
    apt-get install -y -qq falco
elif command -v dnf &> /dev/null; then
    # RHEL / Rocky / Fedora
    rpm --import https://falco.org/repo/falcosecurity-packages.asc
    curl -s -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
    dnf install -y falco
else
    echo -e "${RED}[!] Unsupported package manager. Please install Falco manually.${NC}"
    exit 1
fi
echo -e "${GREEN}    [✓] Falco binary installed successfully.${NC}"

# 4. Deploy Hardened Falco Rules & Modern eBPF Config
echo -e "${BLUE}[4/6] Deploying hardened eBPF rules and configuration...${NC}"
mkdir -p /etc/falco

cat << 'EOF' > /etc/falco/falco_rules.local.yaml
- macro: container_started
  condition: (container.id != "" and container.id != "host")

- macro: sensitive_host_files
  condition: >
    (fd.name startswith /etc/shadow or
     fd.name startswith /etc/passwd or
     fd.name startswith /etc/sudoers or
     fd.name startswith /root/.ssh or
     fd.name startswith /host/etc or
     fd.name startswith /host/proc or
     fd.name startswith /rootfs/etc)

- rule: Unexpected Host Filesystem Access from Container
  desc: Detects containers attempting to access sensitive host files.
  condition: >
    evt.type in (open, openat, openat2) and
    (evt.is_open_read=true or evt.is_open_write=true) and
    container_started and
    sensitive_host_files
  output: "CRITICAL: Suspicious host filesystem access (container=%container.name id=%container.id file=%fd.name cmd=%proc.cmdline user=%user.name)"
  priority: CRITICAL
  tags: [filesystem, container_security]

- rule: Container Access to Docker Daemon Socket
  desc: Detects container attempting to access host docker socket
  condition: >
    evt.type in (connect, open, openat) and
    container_started and
    (fd.name in (/var/run/docker.sock, /run/docker.sock, /host/var/run/docker.sock))
  output: "EMERGENCY: Docker socket breakout attempt (container=%container.name id=%container.id socket=%fd.name cmd=%proc.cmdline)"
  priority: EMERGENCY
  tags: [docker_escape, privilege_escalation]
EOF

cat << 'EOF' > /etc/falco/falco.yaml
engine:
  kind: modern_ebpf

rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml

json_output: true
json_include_output_property: true

http_output:
  enabled: true
  url: "http://127.0.0.1:5000/webhook/falco"

buffered_outputs: false
priority: notice
EOF

# 5. Set up Python Sentinel Isolation Daemon
echo -e "${BLUE}[5/6] Setting up Python Sentinel daemon & virtualenv...${NC}"
mkdir -p /opt/falco-sentinel
mkdir -p /var/log/falco-sentinel/forensics

# Ensure Python3 and venv are installed
if command -v apt-get &> /dev/null; then
    apt-get install -y -qq python3 python3-venv python3-pip
elif command -v dnf &> /dev/null; then
    dnf install -y python3 python3-pip
fi

python3 -m venv /opt/falco-sentinel/venv
/opt/falco-sentinel/venv/bin/pip install --upgrade pip
/opt/falco-sentinel/venv/bin/pip install docker flask requests

# Copy Python Sentinel Script
cp ./falco_sentinel.py /opt/falco-sentinel/falco_sentinel.py 2>/dev/null || \
cat << 'EOF' > /opt/falco-sentinel/falco_sentinel.py
import os, sys, time, json, logging
from datetime import datetime, timezone
import docker
from flask import Flask, jsonify, request

DEFAULT_ACTION = os.getenv("SENTINEL_ISOLATION_ACTION", "quarantine_network")
QUARANTINE_NET = "falco-quarantine"
FORENSICS_DIR = "/var/log/falco-sentinel/forensics"
os.makedirs(FORENSICS_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Sentinel] %(message)s")
app = Flask(__name__)
client = docker.from_env()

def isolate(cid, cname, policy):
    try:
        c = client.containers.get(cid)
        if policy == "quarantine_network":
            qnet = client.networks.get(QUARANTINE_NET)
            qnet.connect(c)
            for n in list(c.attrs.get("NetworkSettings", {}).get("Networks", {}).keys()):
                if n != QUARANTINE_NET:
                    client.networks.get(n).disconnect(c, force=True)
            logging.warning(f"ISOLATED: Container {cname} moved to quarantine network")
            return "quarantined"
        elif policy == "pause":
            c.pause()
            logging.warning(f"ISOLATED: Container {cname} paused")
            return "paused"
        elif policy == "stop":
            c.stop(timeout=5)
            logging.warning(f"ISOLATED: Container {cname} stopped")
            return "stopped"
    except Exception as e:
        logging.error(f"Isolation error on {cid}: {e}")
        return "error"

@app.route("/webhook/falco", methods=["POST"])
def webhook():
    data = request.json or {}
    pri = data.get("priority", "NOTICE")
    fields = data.get("output_fields", {})
    cid = fields.get("container.id")
    cname = fields.get("container.name", "unknown")
    if pri in ["WARNING", "ERROR", "CRITICAL", "EMERGENCY"] and cid and cid != "host":
        action = isolate(cid, cname, DEFAULT_ACTION)
        return jsonify({"status": "isolated", "action": action}), 200
    return jsonify({"status": "ignored"}), 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
EOF

# Install Systemd service for Sentinel
cat << 'EOF' > /etc/systemd/system/falco-sentinel.service
[Unit]
Description=Falco Sentinel eBPF Auto-Isolation Daemon
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/falco-sentinel
Environment="SENTINEL_ISOLATION_ACTION=quarantine_network"
ExecStart=/opt/falco-sentinel/venv/bin/python /opt/falco-sentinel/falco_sentinel.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now falco-sentinel.service
systemctl enable --now falco-modern-bpf.service 2>/dev/null || systemctl enable --now falco.service

# 6. Verification and Status Report
echo -e "${BLUE}[6/6] Verifying services status...${NC}"
sleep 2

if systemctl is-active --quiet falco-sentinel; then
    echo -e "${GREEN}    [✓] falco-sentinel daemon is ACTIVE and listening on port 5000${NC}"
else
    echo -e "${YELLOW}    [!] Check sentinel service: systemctl status falco-sentinel${NC}"
fi

echo -e "${GREEN}"
echo "=============================================================="
echo "    Falco Sentinel Successfully Installed & Activated!        "
echo "=============================================================="
echo -e "${NC}"
echo "Run test attack: bash test_exploit.sh"
