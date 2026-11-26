# Attack 2 — Docker AuthZ bypass (CVE-2026-34040)

An incomplete fix for CVE-2024-41110: Docker's authorization middleware
silently drops request bodies larger than 1 MB (maxBodySize) before
forwarding them to the AuthZ plugin — while still processing the full
body itself. The plugin receives RequestBody: nil and approves what it
cannot see. A single padded HTTP request creates a PRIVILEGED container
with host filesystem access.

The 2024 fix (CVE-2024-41110) added a floor (Content-Length > 0);
the ceiling (ContentLength < maxBodySize) was left untouched — which is
the incomplete-fix story: the same middleware failed again, silently.

## Files
- generate_payload.py : builds the padded create request (2 MiB inert field)
- bypass.sh           : sends the baseline (denied) then the bypass (approved)
- verify.sh           : shows the container is real, privileged, and compromises the host

## Prerequisite
Docker with the team's AuthZ plugin attached (fail-open) — see
sentinel_docker/prevention/. Baseline: privileged runs must be DENIED.
