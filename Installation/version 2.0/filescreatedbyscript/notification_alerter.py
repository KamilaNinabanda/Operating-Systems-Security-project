cat > "$INSTALL_DIR/guard/notification_alerter.py" <<'__GUARD_EOF__'
"""Alerts: JSONL log, Slack and generic webhook."""
import json
import logging
import time

import requests

log = logging.getLogger("guard.notifier")


class Notificationalert:
    def __init__(self, alert_log, slack_url=None, webhook_url=None):
        self.alert_log, self.slack_url, self.webhook_url = alert_log, slack_url, webhook_url

    def send(self, event: dict, decision, result):
        f = event.get("output_fields") or {}
        alert = {
            "ts": event.get("time") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rule": event.get("rule"), "priority": event.get("priority"),
            "container": f.get("container.name"), "container_id": f.get("container.id"),
            "image": f.get("container.image.repository"), "file": f.get("fd.name"),
            "cmd": f.get("proc.cmdline"), "decision": decision.action,
            "reason": decision.reason, "isolation": result,
        }
        with open(self.alert_log, "a") as fh:
            fh.write(json.dumps(alert) + "\n")
        log.warning("ALERT %s", json.dumps(alert))

        icon = "🔒" if decision.action == "isolate" else "🚨"
        text = (f"{icon} *{alert['rule']}* ({alert['priority']})\n"
                f"Container: `{alert['container']}` ({alert['image']})\n"
                f"Details: `{alert['file'] or alert['cmd']}`\n"
                f"Action: *{decision.action}* — {decision.reason}")
        for url, payload in ((self.slack_url, {"text": text}), (self.webhook_url, alert)):
            if url:
                try:
                    requests.post(url, json=payload, timeout=5)
                except requests.RequestException as e:
                    log.error("Failed to send notification: %s", e)
