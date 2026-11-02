mkdir -p ~/falco-guard-repo/tools
cat > ~/falco-guard-repo/tools/check_versions.py << 'EOF'
#!/usr/bin/env python3
"""Checks versions against Leaky Vessels (CVE-2024-21626 and related).

Usage:
python3 check_versions.py            output as a table
python3 check_versions.py --json     output as JSON

Exit code: 0 if everything is patched, 1 if any component is vulnerable.

Note: The thresholds correspond to the security advisories published in
January 2024. If you are using packages from a distribution that includes
backports, they may contain the patch under a different version number;
always verify against your distribution's official security advisory
before making any security-related decisions.
"""
import json
import re
import subprocess
import sys


def run(cmd):
try:
return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
except (FileNotFoundError, subprocess.TimeoutExpired):
return ""


def parse(text):
m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
return tuple(int(x) for x in m.groups()) if m else None


def runc_ok(v):          # fixed in 1.1.12
return v >= (1, 1, 12)


def containerd_ok(v):    # fixed in 1.6.28 and 1.7.13; 1.8+ and 2.x already include the fix
if v[:2] == (1, 6):
return v >= (1, 6, 28)
if v[:2] == (1, 7):
return v >= (1, 7, 13)
return v[:2] >= (1, 8)


def docker_ok(v):        # fixed in 24.0.9 and 25.0.2; 25.0.3+ and 26+ as well
if v[0] == 24:
return v >= (24, 0, 9)
return v >= (25, 0, 2)


CHECKS = [
("runc", ["runc", "--version"], runc_ok, ">= 1.1.12"),
("containerd", ["containerd", "--version"], containerd_ok, ">= 1.6.28 / 1.7.13"),
("docker", ["docker", "version", "--format", "{{.Server.Version}}"], docker_ok, ">= 24.0.9 / 25.0.2"),
]

results, vulnerable = [], False
for name, cmd, ok_fn, required in CHECKS:
out = run(cmd)
v = parse(out)
if v is None:
status = "unknown"
elif ok_fn(v):
status = "ok"
else:
status, vulnerable = "VULNERABLE", True
results.append({"componente": name, "version": ".".join(map(str, v)) if v else None,
"requerido": required, "estado": status})

if "--json" in sys.argv:
print(json.dumps(results, indent=2))
else:
print(f"{'COMPONENT':<12}{'VERSION':<12}{'REQUIRED':<22}STATUS")
for r in results:
print(f"{r['componente']:<12}{str(r['version']):<12}{r['requerido']:<22}{r['estado']}")
print("\nNote: If you are using distribution-provided packages, they may include the patch with a different version number.")
print("Check against your distribution's security advisory.")

sys.exit(1 if vulnerable else 0) 0)
EOF
