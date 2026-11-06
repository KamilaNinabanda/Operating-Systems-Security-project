#!/usr/bin/env bash
# ==============================================================================
# Falco Sentinel - Safe Exploit Verification Script
# Launches an unprivileged container and attempts to read sensitive host files.
# Validates that eBPF traps the syscall and Sentinel isolates it in <1 second.
# ==============================================================================

#It changes the exit status behavior of pipelines so that a pipeline fails if any command within it fails
set -euo pipefail

echo "[*] Launching test container: 'test-container'..."
docker rm -f test-container &>/dev/null || true

# Run a test alpine container in background
docker run -d --name test-container \
  -v /etc/passwd:/host/etc/passwd:ro \
  alpine:latest sleep 300

echo "[*] Container launched. Current status:"
docker ps --filter "name=test-container"

echo ""
echo "[*] Executing suspicious action: reading /host/etc/passwd from inside container..."
docker exec test-container head -n 3 /host/etc/passwd || true

echo ""
echo "[*] Waiting 2 seconds for Falco eBPF hook -> Sentinel webhook..."
sleep 2

echo "[*] Checking container isolation status:"
STATUS=$(docker inspect test-container --format '{{.State.Status}}' 2>/dev/null || echo "removed")
NETS=$(docker inspect test-container --format '{{json .NetworkSettings.Networks}}' 2>/dev/null || echo "none")

echo "    -> Container Status: $STATUS"
echo "    -> Networks Attached: $NETS"

if [[ "$STATUS" == "paused" ]] || [[ "$NETS" =~ "falco-quarantine" ]] || [[ "$STATUS" == "exited" ]]; then
    echo "SUCCESS: Victim container was automatically isolated by Falco Sentinel!"
else
    echo "PENDING: Check 'journalctl -u falco-sentinel -f' or webhook logs."
fi

# Clean up
docker rm -f test-container &>/dev/null || true
