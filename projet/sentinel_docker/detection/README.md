# Detection layer (Defense 1)

**CAMILLE — put your detection-layer code in this folder.**

Expected files:
- `rules_detection_falco.yaml` — the Falco detection rules (expanded version)
- `sentinel_webhook.py` — the Flask policy engine
- `responder.py` — the isolation logic (pause / network disconnect)

## What this layer does
It works at runtime (syscalls, eBPF). Falco detects suspicious behaviour (sensitive host-file access, namespace entry), sends an alert to the policy engine, and the responder quarantines the offending container (pause) within about one second.

## Mode
Driven by `sentinel.conf` → `detection.mode`:
- `enforce` → isolate the container
- `detect` → alert only

## Required settings (validated fixes)
- `json_output: true` in the Falco output config (plain text makes the webhook reject the alert).
- No keys unknown to your Falco version in the config (an unknown key makes the service crash-loop).
- The webhook normalizes the alert priority to upper-case before comparing it.
- The rules match sensitive host-file access on both the host root and container-mounted host paths.
