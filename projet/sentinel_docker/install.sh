#!/bin/bash
# Sentinel_Docker installer — deploys the prevention + detection layers from sentinel.conf.
# Run as root, in an ISOLATED VM only.
# NOTE: adapt the paths below to match where your files are deployed.
set -e
CONF="$(dirname "$0")/sentinel.conf"
mkdir -p /opt/sentinel/prevention /opt/sentinel/detection /var/log/sentinel

echo "[1/6] Dependencies..."
apt-get update -qq && apt-get install -y -qq falco python3-flask python3-docker

echo "[2/6] Prevention module (AuthZ plugin)..."
install -m 644 prevention/policy.json          /opt/sentinel/prevention/
install -m 644 prevention/authz_plugin.py      /opt/sentinel/prevention/
install -m 644 prevention/docker-authz.service /etc/systemd/system/
systemctl daemon-reload
# mode from sentinel.conf: pass --fail-closed if prevention.mode = fail-closed
PREV_MODE=$(grep -A1 '^prevention:' "$CONF" | grep mode | awk '{print $2}')
EXTRA=""; [ "$PREV_MODE" = "fail-closed" ] && EXTRA="--fail-closed"
sed -i "s|ExecStart=.*|ExecStart=/usr/bin/python3 /opt/sentinel/prevention/authz_plugin.py $EXTRA|" \
    /etc/systemd/system/docker-authz.service
systemctl daemon-reload

echo "[3/6] Wiring the daemon to the plugin (plugins attach at daemon startup)..."
echo '{ "authorization-plugins": ["authz"] }' > /etc/docker/daemon.json
systemctl enable --now docker-authz
systemctl restart docker

echo "[4/6] Detection module (Falco rules + outputs)..."
install -m 644 detection/rules_detection_falco.yaml /etc/falco/rules.d/
install -m 644 falco/config.d/configfalco.yaml      /etc/falco/config.d/sentinel.yaml
systemctl restart falco-modern-bpf

echo "[5/6] Policy engine + responder..."
install -m 644 detection/sentinel_webhook.py /opt/sentinel/detection/
install -m 644 detection/responder.py        /opt/sentinel/detection/ 2>/dev/null || true
DET_MODE=$(grep -A3 '^detection:' "$CONF" | grep mode | awk '{print $2}')
ENF=""; [ "$DET_MODE" = "enforce" ] && ENF="--enforce"
nohup python3 /opt/sentinel/detection/sentinel_webhook.py $ENF \
      > /var/log/sentinel/webhook.log 2>&1 &

echo "[6/6] Sanity checks..."
docker info --format 'authz plugins: {{.Plugins.Authorization}}'
systemctl is-active falco-modern-bpf
curl -s -X POST http://127.0.0.1:5000/webhook/falco -H 'Content-Type: application/json' -d '{}' | head -1
echo "Sentinel_Docker deployed."
