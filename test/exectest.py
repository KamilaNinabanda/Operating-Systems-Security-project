mkdir -p ~/falco-guard-repo/tests
cat > ~/falco-guard-repo/tests/run_tests.py << 'EOF'
#!/usr/bin/env python3
"""End-to-end tests for falco-guard.

Requires the falco-guard service to be active (systemctl status falco-guard)
and Falco to be sending alerts to it (http_output configured with the token).

Usage: sudo python3 run_tests.py

Works with both DRY_RUN=true (checks the logged decision) and
DRY_RUN=false (additionally verifies that the container is paused and disconnected from the network).
Creates and deletes its own test containers (prefixed with 'fg-').
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

AUDIT = "/var/log/falco-guard/audit.log"
HEALTH = "http://127.0.0.1:8080/health"
RULE = "Container opens candidate sensitive file"
WAIT = 15   # maximum seconds to wait for the service's decision
QUIET = 6   # seconds to wait to ensure "nothing happens"


def sh(cmd):
return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def audit_lines():
try:
with open(AUDIT) as f:
return f.read().splitlines()
except FileNotFoundError:
return []


def new_rows(before, name):
rows = []
for line in audit_lines()[before:]:
try:
d = json.loads(line)
except ValueError:
continue
if d.get("container") == name and d.get("rule") == RULE:
rows.append(d)
return rows


def main():
try:
health = json.load(urllib.request.urlopen(HEALTH, timeout=5)) 
except Exception as e: 
print(f"Service not responding on {HEALTH}: {e}") 
return 2 
dry = health["dry_run"] 
action = "dry-run" if dry else "isolated" 
print(f"Service mode: {'DRY_RUN (simulation)' if dry else 'REAL ISOLATION'}\n") 

tmp = tempfile.mkdtemp(prefix="fg-test-") 
with open(os.path.join(tmp, "shadow"), "w") as f: 
f.write("data\n") 

# (name, docker run arguments, command, expected state, expected host_path) 
scenarios = [ 
("fg-a-host", "-v /:/host", "cat /host/etc/shadow", action, "/etc/shadow"), 
("fg-b-data", "-v /:/data", "cat /data/etc/shadow", action, "/etc/shadow"), 
("fg-c-etc", "-v /etc:/cfg", "cat /cfg/shadow", action, "/etc/shadow"), 
("fg-d-internal", "", "cat /etc/shadow", "internal-file", None), 
("fg-e-innocuous", f"-v {tmp}:/data", "cat /data/shadow", "mount-not-sensitive", None), 
("fg-f-exempt", "--label falco-guard.ignore=true -v /:/data", "cat /data/etc/shadow", "exempt", "/etc/shadow"), 
("fg-g-legit", "", "cat /etc/hostname", None, None), 
] 

results = [] 
for name, run_args, cmd, expected, exp_path in scenarios: 
sh(f"docker rm -f {name}") 
r = sh(f"docker run -d --name {name} {run_args} alpine sleep 600") 
if r.returncode != 0: 
results.append((name, "FAIL", f"could not be created: {r.stderr.strip()[:80]}")) 
continue 

before = len(audit_lines()) 
sh(f"docker exec {name} {cmd} > /dev/null") 

if expected is None: 
time.sleep(QUIET) 
rows = new_rows(before, name) 
ok = not rows 
results.append((name, "PASS" if ok else "FAIL", 
"no alerts (success)" if ok else f"alert: {rows[0]['status']}")) 
continue 

deadline, rows = time.time() + WAIT, [] 
while time.time() < deadline and not rows: 
time.sleep(1) 
rows = new_rows(before, name) 
if not rows: 
results.append((name, "FAIL", "no decision reached the audit log")) 
continue 

d = rows[-1] 
ok = d["status"] == expected and (exp_path is None or d.get("host_path") == exp_path) 
detail = f"status={d['status']} host_path={d.get('host_path')}" 

if ok and expected == "isolated": 
time.sleep(2) 
paused = sh(f"docker inspect -f '{{{{.State.Paused}}}}' {name}").stdout.strip() 
nets = sh(f"docker inspect -f '{{{{len .NetworkSettings.Networks}}}}' {name}").stdout.strip() 
ok = paused == "true" and nets == "0" 
detail += f" paused={paused} networks={nets}" 
results.append((name, "PASS" if ok else "FAIL", detail)) 

# Cleaning 
for name, *_ in scenarios: 
sh(f"docker unpause {name}") 
sh(f"docker rm -f {name}") 
sh("docker rmi $(docker images quarantine -q)") 
shutil.rmtree(tmp, ignore_errors=True) 

print(f"{'SCENARIO':<16}{'RESULT':<11}DETAIL") 
for name, res, detail in results: 
print(f"{name:<16}{res:<11}{detail}") 
fails = sum(1 f
