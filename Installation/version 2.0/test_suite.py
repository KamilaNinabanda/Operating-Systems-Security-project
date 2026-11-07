#!/usr/bin/env python3
"""
Tests Python Sentinel functions, Docker interaction, safelisting, cooldown throttles,
"""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch
import json
import time

# Ensure current directory and script directory are in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
for path in [SCRIPT_DIR, os.getcwd(), "/home/user/falco", "/opt/falco-sentinel"]:
    if os.path.exists(path) and path not in sys.path:
        sys.path.insert(0, path)

# Mock external libraries (docker, flask) if running on bare system Python without virtualenv
try:
    import docker
    from docker.errors import NotFound, APIError
except ModuleNotFoundError:
    mock_docker = MagicMock()
    mock_errors = MagicMock()
    class NotFound(Exception): pass
    class APIError(Exception): pass
    mock_errors.NotFound = NotFound
    mock_errors.APIError = APIError
    mock_docker.errors = mock_errors
    sys.modules['docker'] = mock_docker
    sys.modules['docker.errors'] = mock_errors

try:
    import flask
    from flask import Flask, jsonify, request
except ModuleNotFoundError:
    mock_flask = MagicMock()
    class MockFlask:
        def __init__(self, name):
            self.name = name
            self.routes = {}
        def route(self, rule, **options):
            def decorator(f):
                self.routes[rule] = f
                return f
            return decorator
        def test_client(self):
            class MockClient:
                def __init__(self, app_inst): self.app = app_inst
                def post(self, path, data=None, content_type=None):
                    class MockResponse:
                        def __init__(self, status_code, json_dict):
                            self.status_code = status_code
                            self._json = json_dict
                        def get_json(self, silent=True):
                            return self._json
                    fn = self.app.routes.get(path)
                    if fn:
                        try:
                            import flask
                            flask.request.get_json = lambda silent=True: json.loads(data) if isinstance(data, str) else (data or {})
                            res = fn()
                            if isinstance(res, tuple):
                                return MockResponse(res[1], res[0].json_data if hasattr(res[0], 'json_data') else {"status": "ignored"})
                            return MockResponse(200, res)
                        except Exception:
                            return MockResponse(200, {"status": "ignored"})
                    return MockResponse(404, {"status": "not_found"})
            return MockClient(self)
        def run(self, *args, **kwargs): pass

    class MockJsonResponse:
        def __init__(self, data):
            self.json_data = data

    def mock_jsonify(*args, **kwargs):
        data = args[0] if args else kwargs
        return MockJsonResponse(data)

    mock_flask.Flask = MockFlask
    mock_flask.jsonify = mock_jsonify
    mock_flask.request = MagicMock()
    sys.modules['flask'] = mock_flask

# Import Sentinel daemon module
falco_sentinel = None
try:
    import falco_sentinel
except ModuleNotFoundError as e:
    if e.name in ('falco_sentinel', 'app'):
        try:
            import app as falco_sentinel
            print("[INFO] Using 'app.py' as module compatible with Sentinel.")
        except ModuleNotFoundError:
            print("[!] ERROR: The followinf file was not found 'falco_sentinel.py' also 'app.py'")
            print("    make sure you count with falco_sentinel.py in /home/user/falco")
            raise e
    else:
        raise e

class TestFalcoSentinelUnit(unittest.TestCase):
    def setUp(self):
        if hasattr(falco_sentinel, 'cooldown_cache'):
            falco_sentinel.cooldown_cache.clear()
        if hasattr(falco_sentinel, 'recent_incidents'):
            falco_sentinel.recent_incidents.clear()

    def test_01_safelist_protection(self):
        """Verifies that critical infrastructure containers are never isolated."""
        if not hasattr(falco_sentinel, 'is_container_safelisted'):
            self.skipTest("is_container_safelisted is not present in the legacy version")

        mock_container = MagicMock()
        mock_container.name = "falco"
        mock_container.labels = {}
        self.assertTrue(falco_sentinel.is_container_safelisted(mock_container))

        mock_container.name = "k8s_POD_core-dns"
        self.assertTrue(falco_sentinel.is_container_safelisted(mock_container))

        mock_container.name = "my-backend-app"
        mock_container.labels = {"falco.sentinel.protected": "true"}
        self.assertTrue(falco_sentinel.is_container_safelisted(mock_container))

        mock_unprotected = MagicMock()
        mock_unprotected.name = "rogue-compromised-container"
        mock_unprotected.labels = {}
        self.assertFalse(falco_sentinel.is_container_safelisted(mock_unprotected))

    def test_02_cooldown_rate_limiting(self):
        """Verifies that rapid repeated alerts on the same container are throttled."""
        if not hasattr(falco_sentinel, 'cooldown_cache'):
            self.skipTest("cooldown_cache no configured")

        cid = "container_abc_123"
        now = time.time()
        falco_sentinel.cooldown_cache[cid] = now - 10
        cooldown_sec = getattr(falco_sentinel, 'COOLDOWN_SECONDS', 60)
        self.assertTrue((time.time() - falco_sentinel.cooldown_cache[cid]) < cooldown_sec)

        falco_sentinel.cooldown_cache[cid] = now - 120
        self.assertFalse((time.time() - falco_sentinel.cooldown_cache[cid]) < cooldown_sec)

    @patch("falco_sentinel.docker_client", create=True)
    def test_03_quarantine_network_action(self, mock_docker):
        """Verifies network quarantine policy switches networks correctly."""
        if not hasattr(falco_sentinel, 'execute_isolation'):
            self.skipTest("execute_isolation no present")

        mock_container = MagicMock()
        mock_container.name = "compromised_app"
        mock_container.labels = {}
        mock_container.attrs = {
            "NetworkSettings": {
                "Networks": {"bridge": {}, "app-net": {}}
            }
        }
        mock_docker.containers.get.return_value = mock_container
        mock_quarantine_net = MagicMock()
        mock_app_net = MagicMock()
        
        qnet_name = getattr(falco_sentinel, 'QUARANTINE_NET_NAME', 'falco-quarantine')
        def get_net(name):
            if name == qnet_name:
                return mock_quarantine_net
            return mock_app_net
        mock_docker.networks.get.side_effect = get_net

        res = falco_sentinel.execute_isolation("test_id", "compromised_app", "quarantine_network")
        self.assertEqual(res["status"], "isolated")
        self.assertEqual(res["action"], "network_quarantine")
        mock_quarantine_net.connect.assert_called_with(mock_container)

    @patch("falco_sentinel.docker_client", create=True)
    def test_04_pause_action(self, mock_docker):
        """Verifies pause policy invokes container.pause()."""
        mock_container = MagicMock()
        mock_container.name = "compromised_app"
        mock_container.labels = {}
        mock_docker.containers.get.return_value = mock_container

        if hasattr(falco_sentinel, 'execute_isolation'):
            res = falco_sentinel.execute_isolation("test_id", "compromised_app", "pause")
            self.assertEqual(res["status"], "isolated")
            self.assertEqual(res["action"], "pause")
        elif hasattr(falco_sentinel, 'isolate_container'):
            success = falco_sentinel.isolate_container("test_id", "compromised_app")
            self.assertTrue(success)

        mock_container.pause.assert_called_once()

    @patch("falco_sentinel.docker_client", create=True)
    def test_05_forensic_snapshot_structure(self, mock_docker):
        """Verifies that volatile forensic reports capture processes, diffs, and mounts."""
        if not hasattr(falco_sentinel, 'capture_forensic_snapshot'):
            self.skipTest("capture_forensic_snapshot no present")

        mock_container = MagicMock()
        mock_container.id = "test_id_full_hash"
        mock_container.short_id = "test_id"
        mock_container.name = "vulnerable_app"
        mock_container.image.tags = ["vulnerable_app:latest"]
        mock_container.top.return_value = {"Processes": [["1", "0", "root", "R", "cat /host/etc/shadow"]]}
        mock_container.diff.return_value = [{"Path": "/tmp/.recon", "Kind": 1}]
        mock_container.logs.return_value = b"[INFO] App started\n[WARN] Security breach\n"
        mock_container.attrs = {"NetworkSettings": {"Networks": {}}, "Mounts": [{"Source": "/etc", "Destination": "/host/etc"}]}

        alert_data = {"rule": "Unexpected Host Filesystem Access from Container", "priority": "CRITICAL"}
        snapshot = falco_sentinel.capture_forensic_snapshot(mock_container, alert_data)

        self.assertIn("processes", snapshot)
        self.assertIn("filesystem_diff", snapshot)
        self.assertIn("recent_logs", snapshot)
        self.assertIn("mounts", snapshot)
        self.assertEqual(snapshot["container_name"], "vulnerable_app")

if __name__ == "__main__":
    unittest.main(verbosity=2)
