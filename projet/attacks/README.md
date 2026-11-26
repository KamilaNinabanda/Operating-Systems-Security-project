# Attacks

Two reproduced attacks against Docker, each in its own isolated VM.

> ⚠️ For coursework in an isolated, network-disconnected VM only.

| Folder | Attack | CVE |
|---|---|---|
| `attack1-runc/` | runc container escape via a leaked file descriptor | CVE-2024-21626 |
| `attack2-authz/` | Docker authorization-plugin bypass | CVE-2024-41110 / CVE-2026-34040 |

Each subfolder has its own README with the environment, the reproduction steps, and the evidence (screenshots / logs). Add your attack code and notes into the matching folder.
