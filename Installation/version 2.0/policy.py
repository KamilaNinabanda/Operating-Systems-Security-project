"""Decision mechanism: ignore, alert or isolate?"""
from dataclasses import dataclass

import yaml


@dataclass
class DecisionActions:
    action: str  # ignore | alert | isolate
    reason: str


class Policies:
    def __init__(self, cfg: dict):
        self.cfg = cfg

    @classmethod
    def from_file(cls, path: str) -> "Policies":
        with open(path) as f:
            return cls(yaml.safe_load(f) or {})

    def decide(self, event: dict) -> DecisionActions:
        f = event.get("output_fields") or {}
        cid = f.get("container.id")
        if not cid or cid == "host":
            return DecisionActions("ignore", "event outside a container")

        rule = event.get("rule", "")
        configrule = (self.cfg.get("rules") or {}).get(rule)
        if configrule is None:
            return DecisionActions("alert", "rule without a policy: alert only")
        if configrule.get("action") == "isolate":
            return DecisionActions("isolate", f"Critical rule: {rule}")

        return DecisionActions("alert", "alert only")
