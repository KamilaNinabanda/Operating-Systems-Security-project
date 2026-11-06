#!/usr/bin/env python3
"""
Automated eBPF Container Runtime Monitoring & Isolation Daemon

Listens for Falco eBPF security alerts via HTTP webhook and automatically enforces
isolation policies (Network Quarantine, Pause, Stop, or Kill) while capturing
pre-isolation forensic snapshots.
"""

import os
import sys
import time
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import docker
from docker.errors import NotFound, APIError
from flask import Flask, jsonify, request

# Configuration via Environment Variables
LOG_LEVEL = os.getenv("SENTINEL_LOG_LEVEL", "INFO")
DEFAULT_ISOLATION_ACTION = os.getenv("SENTINEL_ISOLATION_ACTION", "quarantine_network")  # quarantine_network | pause | stop | kill | dry_run
COOLDOWN_SECONDS = int(os.getenv("SENTINEL_COOLDOWN_SECONDS", "60"))
FORENSICS_DIR = os.getenv("SENTINEL_FORENSICS_DIR", "/var/log/falco-sentinel/forensics")
AUDIT_LOG_FILE = os.getenv("SENTINEL_AUDIT_LOG", "/var/log/falco-sentinel/audit.log")
QUARANTINE_NET_NAME = os.getenv("SENTINEL_QUARANTINE_NET", "falco-quarantine")
SLACK_WEBHOOK_URL = os.getenv("SENTINEL_SLACK_WEBHOOK", "")
PORT = int(os.getenv("SENTINEL_PORT", "5000"))

# Containers/images that MUST NEVER be isolated (infrastructure protection)
SAFELIST_NAMES = {"falco", "falco-sentinel", "cadvisor", "node-exporter", "kube-proxy"}
SAFELIST_LABELS = {"falco.sentinel.protected": "true", "k8s-app": "kube-system"}

# Ensure log and forensics directories exist
os.makedirs(FORENSICS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)

# Logger Setup
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] [Sentinel] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger("FalcoSentinel")

app = Flask(__name__)

# State tracking for cooldowns & alert history
cooldown_cache: Dict[str, float] = {}
recent_incidents = []

def init_docker_client() -> Optional[docker.DockerClient]:
    """Initializes the Docker client from the local Docker daemon socket."""
    try:
        client = docker.from_env()
        client.ping()
        logger.info("Successfully connected to Docker Daemon via socket.")
        return client
    except Exception as exc:
        logger.error(f"FATAL: Unable to connect to Docker socket: {exc}")
        return None

docker_client = init_docker_client()

def ensure_quarantine_network():
    """Creates an isolated Docker bridge network with no default gateway/routing."""
    if not docker_client:
        return
    try:
        docker_client.networks.get(QUARANTINE_NET_NAME)
    except NotFound:
        try:
            docker_client.networks.create(
                name=QUARANTINE_NET_NAME,
                driver="bridge",
                internal=True,  # Disallows external internet/host routing
                labels={"falco.sentinel.network": "quarantine"},
                check_duplicate=True
            )
            logger.info(f"Created isolated quarantine bridge network: {QUARANTINE_NET_NAME}")
        except Exception as err:
            logger.error(f"Failed to create quarantine network: {err}")

ensure_quarantine_network()

def is_container_safelisted(container) -> bool:
    """Checks whether a container is protected from automated isolation."""
    name_attr = getattr(container, "name", "")
    if isinstance(name_attr, str):
        name = name_attr.lstrip("/")
        if name in SAFELIST_NAMES or any(name.startswith(pfx) for pfx in ("k8s_POD", "falco-", "falco")):
            return True
    labels = getattr(container, "labels", {}) or {}
    if isinstance(labels, dict):
        for key, val in SAFELIST_LABELS.items():
            if labels.get(key) == val:
                return True
    return False

def capture_forensic_snapshot(container, alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Captures volatile forensic state (processes, diffs, network, logs) prior to isolation."""
    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "container_id": container.id,
        "container_name": container.name,
        "image": container.image.tags,
        "alert": alert_data,
        "processes": [],
        "filesystem_diff": [],
        "recent_logs": [],
        "network_settings": {},
        "mounts": []
    }

    try:
        snapshot["processes"] = container.top().get("Processes", [])
    except Exception as e:
        snapshot["processes_error"] = str(e)

    try:
        # docker diff lists filesystem modifications made since image boot
        snapshot["filesystem_diff"] = (container.diff() or [])[:100]
    except Exception as e:
        snapshot["diff_error"] = str(e)

    try:
        raw_logs = container.logs(tail=50).decode("utf-8", errors="replace")
        snapshot["recent_logs"] = raw_logs.splitlines()[-30:]
    except Exception as e:
        snapshot["logs_error"] = str(e)

    try:
        attrs = container.attrs
        snapshot["network_settings"] = attrs.get("NetworkSettings", {}).get("Networks", {})
        snapshot["mounts"] = attrs.get("Mounts", [])
    except Exception as e:
        snapshot["metadata_error"] = str(e)

    # Persist snapshot to forensics directory
    file_path = os.path.join(FORENSICS_DIR, f"forensics_{container.short_id}_{int(time.time())}.json")
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
        logger.info(f"Forensic snapshot saved to: {file_path}")
    except Exception as err:
        logger.error(f"Failed to persist forensic snapshot: {err}")

    return snapshot

def execute_isolation(container_id: str, container_name: str, policy: str) -> Dict[str, Any]:
    """Executes the requested isolation action against the malicious container."""
    if not docker_client:
        return {"status": "error", "message": "Docker client unavailable"}

    try:
        container = docker_client.containers.get(container_id)
    except NotFound:
        return {"status": "error", "message": f"Container {container_id} not found (already terminated?)"}

    if is_container_safelisted(container):
        logger.warning(f"Container {container_name} ({container_id}) is SAFELISTED. Skipping isolation.")
        return {"status": "whitelisted", "action": "ignored"}

    if policy == "quarantine_network":
        # Disconnect from all current networks and connect to isolated sinkhole bridge
        current_nets = list(container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys())
        quarantine_net = docker_client.networks.get(QUARANTINE_NET_NAME)
        
        # Connect to quarantine first so container is never left in half-state
        quarantine_net.connect(container)
        for net_name in current_nets:
            if net_name != QUARANTINE_NET_NAME:
                try:
                    docker_client.networks.get(net_name).disconnect(container, force=True)
                except Exception as net_err:
                    logger.warning(f"Could not disconnect {net_name}: {net_err}")

        logger.warning(f"ISOLATION: Container {container_name} quarantined to network '{QUARANTINE_NET_NAME}'")
        return {"status": "isolated", "action": "network_quarantine"}

    elif policy == "pause":
        container.pause()
        logger.warning(f"ISOLATION: Paused container {container_name} ({container_id})")
        return {"status": "isolated", "action": "pause"}

    elif policy == "stop":
        container.stop(timeout=5)
        logger.warning(f"ISOLATION: Stopped container {container_name} ({container_id})")
        return {"status": "isolated", "action": "stop"}

    elif policy == "kill":
        container.kill()
        logger.warning(f"ISOLATION: Killed container {container_name} ({container_id})")
        return {"status": "isolated", "action": "kill"}

    elif policy == "dry_run":
        logger.info(f"DRY RUN: Alert registered for {container_name}; no active isolation enforced.")
        return {"status": "monitored", "action": "dry_run"}

    return {"status": "ignored", "action": "none"}

@app.route("/webhook/falco", methods=["POST"])
def falco_webhook():
    """Primary webhook endpoint configured in Falco yaml http_output."""
    payload = request.get_json(silent=True) or {}
    if not payload:
        return jsonify({"status": "error", "message": "Empty or invalid JSON"}), 400

    output_fields = payload.get("output_fields", {})
    rule = payload.get("rule", "Unknown Rule")
    priority = payload.get("priority", "NOTICE")
    output_message = payload.get("output", "")
    
    container_id = output_fields.get("container.id")
    container_name = output_fields.get("container.name", "unknown")
    proc_cmdline = output_fields.get("proc.cmdline", "n/a")
    file_path = output_fields.get("fd.name", "n/a")
    user_name = output_fields.get("user.name", "unknown")

    logger.warning(
        f"FALCO EVENT: [{priority}] Rule: '{rule}' | Container: '{container_name}' ({container_id}) | "
        f"Cmd: {proc_cmdline} | File: {file_path} | User: {user_name}"
    )

    # Filter out host-level events where no container exists
    if not container_id or container_id in ("host", "none", ""):
        return jsonify({"status": "ignored", "reason": "Host process event"}), 200

    # Rate Limiting & Cooldown Protection per Container
    now = time.time()
    last_action_time = cooldown_cache.get(container_id, 0)
    if (now - last_action_time) < COOLDOWN_SECONDS:
        logger.info(f"Cooldown active for container {container_id}. Suppressing redundant isolation.")
        return jsonify({"status": "throttled", "reason": "Cooldown active"}), 200

    # Capture Forensics & Enforce Isolation on Critical/Error/Warning
    if priority in ["WARNING", "ERROR", "CRITICAL", "EMERGENCY"]:
        cooldown_cache[container_id] = now
        
        forensic_data = {}
        if docker_client:
            try:
                c = docker_client.containers.get(container_id)
                forensic_data = capture_forensic_snapshot(c, payload)
            except Exception as e:
                logger.error(f"Could not take pre-isolation snapshot: {e}")

        result = execute_isolation(container_id, container_name, DEFAULT_ISOLATION_ACTION)

        incident_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": rule,
            "priority": priority,
            "container_id": container_id,
            "container_name": container_name,
            "output": output_message,
            "action_result": result,
            "has_forensics": bool(forensic_data)
        }
        recent_incidents.insert(0, incident_record)
        if len(recent_incidents) > 100:
            recent_incidents.pop()

        return jsonify({
            "status": "success",
            "rule": rule,
            "container_id": container_id,
            "isolation": result
        }), 200

    return jsonify({"status": "ignored", "reason": f"Priority {priority} below threshold"}), 200

@app.route("/api/status", methods=["GET"])
def get_status():
    """Health check and active policy endpoint."""
    return jsonify({
        "status": "healthy",
        "docker_connected": docker_client is not None,
        "default_action": DEFAULT_ISOLATION_ACTION,
        "cooldown_seconds": COOLDOWN_SECONDS,
        "quarantine_network": QUARANTINE_NET_NAME,
        "safelist": list(SAFELIST_NAMES),
        "recent_incidents_count": len(recent_incidents)
    }), 200

@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    """Lists recent container security incidents captured by the daemon."""
    return jsonify({"incidents": recent_incidents}), 200

@app.route("/api/containers/<cid>/unquarantine", methods=["POST"])
def unquarantine_container(cid: str):
    """Restores a container from pause or reconnects its original default bridge network."""
    if not docker_client:
        return jsonify({"status": "error", "message": "Docker client unavailable"}), 500
    try:
        container = docker_client.containers.get(cid)
        # If paused, unpause
        if container.status == "paused":
            container.unpause()
        
        # If on quarantine network, reconnect to bridge
        bridge_net = docker_client.networks.get("bridge")
        quarantine_net = docker_client.networks.get(QUARANTINE_NET_NAME)
        try:
            quarantine_net.disconnect(container, force=True)
        except Exception:
            pass
        bridge_net.connect(container)

        logger.info(f"Operator manually restored container {container.name} ({cid})")
        return jsonify({"status": "success", "message": f"Container {cid} restored"}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400

if __name__ == "__main__":
    logger.info(f"Falco Sentinel daemon starting on 0.0.0.0:{PORT} with policy '{DEFAULT_ISOLATION_ACTION}'...")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
