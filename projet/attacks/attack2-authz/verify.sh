#!/bin/bash
echo "=== the audit trail: the plugin received NOTHING ==="
grep 'name=pwned' /var/log/docker-authz/audit.jsonl | tail -1
# expected: "declared_len":2097299, "received_len":0, "truncated":true,
#           "decision":"allow"   <- the bypass signature
echo "=== the daemon logged NOTHING (silent middleware) ==="
sudo journalctl -u docker --since "-10 min" | grep -c "Request body is larger" || true
