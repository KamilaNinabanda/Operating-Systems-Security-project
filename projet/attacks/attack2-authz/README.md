# Attack 2 — Docker AuthZ plugin bypass (CVE-2024-41110 / CVE-2026-34040)

> ⚠️ Isolated, network-disconnected VM only.

## Environment
- Debian 12 (or your tested host)
- Docker Engine with an authorization plugin enabled (OPA / custom)
- Target image: alpine:3.20

## What this attack shows
When the request body sent to the authorization plugin is missing or dropped (an empty body, or a body inflated past an internal size threshold), the plugin approves a request it never fully saw, while the daemon executes the complete request. The result: a privileged container is created despite the policy, leading to host compromise.

## Contents of this folder
Put your attack-2 materials here:
- the authorization-plugin config used (fail-open baseline)
- the reproduction scripts you used
- the evidence (screenshots, audit lines showing declared vs received body length)

## Snapshot
`A2-authz-bypass` — taken with the network disconnected, after cleaning up test containers.

---
*See the full written analysis in the attack-2 report. (Placeholder — add the reproduction files and evidence here.)*
