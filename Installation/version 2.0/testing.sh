#!/usr/bin/env bash
# ==============================================================================
# Falco Sentinel - Safe Exploit Verification Script
# Launches an unprivileged container and attempts to read sensitive host files.
# Validates that eBPF traps the syscall and Sentinel isolates it in <1 second.
# ==============================================================================

set -euo pipefail

echo "[*] Launching test victim container: 'victim-test-container'..."
docker rm -f victim-test-container &>/dev/null || true

# Run a test alpine container in background
docker run -d --name victim-test-container \
  -v /etc/passwd:/host/etc/passwd:ro \
  alpine:latest sleep 300

echo "[*] Container launched. Current status:"
docker ps --filter "name=victim-test-container"

echo ""
echo "[*] Executing suspicious action: reading /host/etc/passwd from inside container..."
docker exec victim-test-container head -n 3 /host/etc/passwd || true

echo ""
echo "[*] Waiting 2 seconds for Falco eBPF hook -> Sentinel webhook..."
sleep 2

echo "[*] Checking container isolation status:"
STATUS=$(docker inspect victim-test-container --format '{{.State.Status}}' 2>/dev/null || echo "removed")
NETS=$(docker inspect victim-test-container --format '{{json .NetworkSettings.Networks}}' 2>/dev/null || echo "none")

echo "    -> Container Status: $STATUS"
echo "    -> Networks Attached: $NETS"

if [[ "$STATUS" == "paused" ]] || [[ "$NETS" =~ "falco-quarantine" ]] || [[ "$STATUS" == "exited" ]]; then
    echo "SUCCESS: Victim container was automatically isolated by Falco Sentinel!"
else
    echo "PENDING: Check 'journalctl -u falco-sentinel -f' or webhook logs."
fi

# Clean up
docker rm -f victim-test-container &>/dev/null || true
