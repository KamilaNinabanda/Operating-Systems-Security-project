# Architecture — two enforcement layers

Sentinel_Docker is one application with two complementary layers.

| | Prevention | Detection |
|---|---|---|
| Module | `prevention/` | `detection/` |
| Works at | Docker API (request time) | Runtime (syscalls, eBPF) |
| Mechanism | Fail-closed AuthZ plugin | Falco rules + policy engine + responder |
| Action | Deny the request | Alert, then pause the container |
| Stops | the AuthZ bypass + dangerous configs | the escape + anything past layer 1 |

## Why two layers
Some attacks act *below* the Docker API, where the plugin cannot observe them — only the detection layer can. Others are best stopped *at the request*, before they execute — the prevention layer. Running both gives defense in depth.

## How they coexist (validated)
- **Scope:** prevention enforces only on container-creation requests; the responder's own API calls (pause, disconnect) carry no creation body and pass the plugin untouched.
- **Install order:** the plugin service starts before Docker's final restart (the daemon attaches plugins at startup); Falco and the webhook start afterwards.
- **Shared audit:** both layers log to `/var/log/sentinel/` in one line format.

## Data flow
```
client → dockerd → [prevention: AuthZ plugin] → allow/deny
                        │ (if allowed and it executes)
                        ▼
                   container runtime → syscalls → [detection: Falco] → policy engine → responder → pause
```
