# INSE 6130 — Container Security Project

This repository contains a complete container-security study: two reproduced attacks against Docker, and a single defensive application that stops both.

> ⚠️ All work runs in **isolated VMs, disconnected from the network**.
> Never run any of this on a production host or a networked machine.

---

## What's in here

```
projet/
├── attacks/
│   ├── attack1-runc/      → Attack 1: runc container escape (CVE-2024-21626)
│   └── attack2-authz/     → Attack 2: Docker AuthZ plugin bypass (CVE-2024-41110 / CVE-2026-34040)
├── sentinel_docker/       → The defense application (prevention + detection, two layers)
└── README.md              → this file
```

## The two parts

**1. Attacks** (`attacks/`) — each folder documents and reproduces one vulnerability in an isolated VM, with its own README, code, and evidence.

**2. Defense** (`sentinel_docker/`) — one security application with two complementary enforcement layers:
- a **prevention** layer (a fail-closed authorization plugin) that denies dangerous requests at the Docker API, and
- a **detection** layer (Falco + a policy engine + a responder) that catches and quarantines at runtime.

Together they form **defense in depth**: prevention narrows the attack surface, detection catches whatever gets through. See `sentinel_docker/README.md` for deployment.

## How to reproduce

1. Read `attacks/attack1-runc/README.md` and `attacks/attack2-authz/README.md` to reproduce each attack in its VM.
2. Deploy the defense from `sentinel_docker/README.md`.
3. Replay the attacks with the defense active and confirm both are blocked (see `sentinel_docker/docs/VALIDATION.md`).

## Team

| Member | Part |
|---|---|
| [name] | Attack 2 (AuthZ bypass) + integration |
| [Keny] | Defense 2 — prevention layer |
| [Camille] | Defense 1 — detection layer |
| [others] | [to complete] |

> Academic integrity: all written material is the team's own work.
