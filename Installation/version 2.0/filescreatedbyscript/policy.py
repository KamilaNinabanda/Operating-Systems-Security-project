"""Decision mechanism: ignore, alert or isolate?"""
#Takes the JSON event from FALCO and verifies if it happened in a container and sends 
#which action should be taken. 
from dataclasses import dataclass

import yaml


@dataclass
class DecisionActions:
    action: str  # ignore | alert | isolate
    reason: str
#ligth structure, the final output is the action and why

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
            #it validates the event comes from a container if its from host it just ignores it.

        rule = event.get("rule", "")
        configrule = (self.cfg.get("rules") or {}).get(rule)
        if configrule is None:
            return DecisionActions("alert", "rule without a policy: alert only")
        if configrule.get("action") == "isolate":
            return DecisionActions("isolate", f"Critical rule: {rule}")

        return DecisionActions("alert", "alert only")
