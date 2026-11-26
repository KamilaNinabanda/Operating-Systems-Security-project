# Attack 1 — runc container escape (CVE-2024-21626)

> ⚠️ Isolated, network-disconnected VM only.

## Environment
- Ubuntu 22.04 (or your tested host)
- Docker Engine with a **vulnerable** runc (1.1.11)
- Target image: alpine:3.20

## What this attack shows
A leaked file descriptor lets a container anchor its working directory outside its own mount namespace and reach the host filesystem — leading to a read of a sensitive host file and host compromise.

## Contents of this folder
Put your attack-1 materials here:
- the reproduction scripts / Dockerfiles you used
- the evidence (screenshots, build logs showing the host file read)
- any notes on the file-descriptor probing

## Snapshot
`A1-runc-vulnerable` — taken with the network disconnected, after cleaning up test containers.

---
*(Placeholder — the team member who reproduced attack 1 adds the files and fills in the exact steps.)*
