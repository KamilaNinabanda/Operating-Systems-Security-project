# Prevention layer (Defense 2)

**KENY — put your prevention-layer code in this folder.**

Expected files:
- `authz_plugin.py` — the fail-closed authorization plugin (your enhanced version)
- `docker-authz.service` — the systemd unit
- `policy.json` — the deny rules / image allow-list

## What this layer does
It works at the Docker API (request time). It denies dangerous container-creation requests, and — in fail-closed mode — denies any request whose body cannot be inspected (the fix for the oversized-body bypass).

## Mode
Driven by `sentinel.conf` → `prevention.mode`:
- `fail-closed` → block requests the plugin cannot verify (secure)
- `fail-open` → legacy behaviour (for the vulnerable-baseline demo)

Before pushing, confirm your plugin still: (1) blocks the padded bypass, (2) denies blind requests in fail-closed mode, (3) lets a legitimate container run normally.
