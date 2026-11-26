# Validation — both attacks blocked

Validation reuses the four operating modes. The attack procedures are replayed from the attack snapshots (`A1`, `A2`); this file records the **defensive outcome**.

## Results

| Attack | Before the fixes | After the fixes |
|---|---|---|
| Attack 1 — runc escape (host file read at build time) | ❌ no alert (rule only matched `/etc/passwd`); Falco crash-looped on an invalid config key | ✅ CRITICAL alert → build container paused (quarantine) |
| Attack 2 — AuthZ bypass (privileged container) | ❌ only `nsenter` was caught; the host-file read passed silently | ✅ both gestures caught → container paused within ~1 s |

## The three fixes that made detection reliable
1. **Config:** removed the key unknown to the Falco version (it caused a crash-loop) and added `json_output: true` (plain text made the webhook reject alerts).
2. **Webhook:** normalized the alert priority to upper-case before comparing.
3. **Rules:** expanded the match to sensitive host-file access on both the host root and container-mounted host paths, plus namespace entry.

## Sanity check
A legitimate container (a normal `run`) must keep working in **every** mode — no regression.

## Framing
The detection layer is a *detection/response* layer: a sensitive host file may be read just before the pause arrives. It complements the prevention layer, which denies the same request before it executes. Together: defense in depth.
