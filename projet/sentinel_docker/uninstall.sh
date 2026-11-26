#!/bin/bash
# Sentinel_Docker uninstaller — reverses install.sh.
set -e
echo "Stopping responder..."
pkill -f sentinel_webhook 2>/dev/null || true
echo "Removing the plugin from the daemon..."
echo '{}' > /etc/docker/daemon.json
systemctl disable --now docker-authz 2>/dev/null || true
systemctl restart docker
echo "Restoring Falco defaults..."
rm -f /etc/falco/rules.d/rules_detection_falco.yaml /etc/falco/config.d/sentinel.yaml
systemctl restart falco-modern-bpf 2>/dev/null || true
echo "Sentinel_Docker removed."
