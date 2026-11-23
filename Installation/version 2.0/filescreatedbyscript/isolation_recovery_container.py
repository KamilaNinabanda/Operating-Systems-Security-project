cat > "$INSTALL_DIR/guard/isolation_recovery_container.py" <<'__GUARD_EOF__'
"""Executes container isolation and recovery via Docker SDK (with forensic evidence and rollback)."""
import json
import logging
import os
import threading
import time

import docker

log = logging.getLogger("guard.isolator")


class ContainerIsolation:
    def __init__(self, steps, detection_mode, data_dir):
        self.steps = steps or ["network", "pause"]  # network | pause | stop
        self.detection_mode = detection_mode
        self.collect_info = os.path.join(data_dir, "AUDIT")
        self.state_path = os.path.join(data_dir, "state.json")
        os.makedirs(self.collect_info, exist_ok=True)
        self._client = None
        self._lock = threading.Lock()  #serialize isolation and release operations.
        self.state = {}
        if os.path.exists(self.state_path):
            with open(self.state_path) as f:
                self.state = json.load(f)

    @property
    def client(self):
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _save(self):
        with open(self.state_path, "w") as f:
            json.dump(self.state, f, indent=2)

    def _find(self, cid):
        return next((k for k, r in self.state.items() if r["name"] == cid or k.startswith(cid) or cid.startswith(k)), None)

    def is_isolated(self, cid) -> bool:
        return self._find(cid) is not None

    def _gatherInfo(self, c) -> str:
        """Snapshot of the container before it is isolated; saving the result to a JSON file with restricted permissions."""
        attrs = json.loads(json.dumps(c.attrs))
        #gathers the ENV environmental variables. is the pair of variable and result like password=132 with this, the 132 will turn into not for reading
        attrs["Config"]["Env"] = [e.split("=", 1)[0] + "=<not for reading>" for e in attrs["Config"].get("Env") or []]
        collectedinfo = {"inspect": attrs, "fs_diff": c.diff()}
        if c.status == "running":
            collectedinfo["processes"] = c.top()
        collectedinfo["logs_tail"] = c.logs(tail=200).decode(errors="replace")
        path = os.path.join(self.collect_info, f"{c.name}-{int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(collectedinfo, f, indent=2, default=str)
        os.chmod(path, 0o600)
        return path

    def isolate(self, cid: str, reason: str) -> dict:
        with self._lock:
            #avoid isolating twice avoid corruption
            if self.is_isolated(cid):
                return {"status": "already_isolated"}
            c = self.client.containers.get(cid)
            nets = list(c.attrs["NetworkSettings"]["Networks"])
            host_net = c.attrs["HostConfig"]["NetworkMode"] == "host"
            steps = list(self.steps)
            # With network_mode=host the network cannot be disconnected: freeze the container instead.
            if host_net and "pause" not in steps and "stop" not in steps:
                steps.append("pause")
            if self.detection_mode:
                return {"status": "detection_mode", "container": c.name, "would_do": steps}

            forensics = self._gatherInfo(c)  # collect evidence first
            done = []
            for step in steps:
                if step == "network" and not host_net:
                    for n in nets:
                        self.client.networks.get(n).disconnect(c, force=True)
                elif step == "pause" and "stop" not in steps:
                    c.pause()
                elif step == "stop":
                    c.stop(timeout=5)
                else:
                    continue
                done.append(step)
            self.state[c.id] = {
                "name": c.name, "networks": nets, "done": done,
                "reason": reason, "ts": time.time(), "forensics": forensics,
            }
            self._save()
            log.warning("Container %s isolated: %s", c.name, done)
            return {"status": "isolated", "container": c.name, "steps": done, "forensics": forensics}

    def release(self, cid: str) -> dict:
        with self._lock:
            key = self._find(cid)
            if not key:
                return {"status": "not_isolated"}
            rec = self.state[key]
            c = self.client.containers.get(key)
            if "stop" in rec["done"]:
                c.start()
            c.reload()
            if c.status == "paused":
                c.unpause()
            if "network" in rec["done"]:
                for n in rec["networks"]:
                    self.client.networks.get(n).connect(c)
            del self.state[key]
            self._save()
            return {"status": "released", "container": rec["name"]}
