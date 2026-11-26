# Sentinel_Docker

**One security application, two enforcement layers.**
A Docker protection tool that combines request-time prevention and runtime detection into a single deployable product.

> INSE 6130 — Container Security Project
> Tested on: Debian 12 / Ubuntu 22.04, Docker Engine with an AuthZ plugin, Falco (modern eBPF).
> ⚠️ Runs in an **isolated VM, disconnected from the network**. Not for production hosts.

---

## 1. Overview

`Sentinel_Docker` ships as **one application** organized into two complementary layers:

| | Prevention layer | Detection layer |
|---|---|---|
| **Module** | `prevention/` | `detection/` |
| **Works at** | Docker API (request time) | Runtime (syscalls, eBPF) |
| **Mechanism** | Fail-closed AuthZ plugin | Falco rules + policy engine + responder |
| **Action** | **Deny** the request | **Alert, then pause** the container |
| **Owner** | Defense 2 | Defense 1 |

**Why one application, not two scripts:** some attacks act *below* the Docker API, where the plugin cannot see them — only the detection layer can observe them at runtime. Other attacks are best stopped *at the request*, before they ever execute — the prevention layer. Running both gives **defense in depth**: prevention narrows the surface, detection catches whatever gets through. The two layers coexist (validated): the prevention plugin does not block the detection layer's own isolation actions.

---

## 2. Requirements

- A Linux VM (Debian 12 or Ubuntu 22.04), **network-isolated**.
- Docker Engine with authorization-plugin support.
- `python3` with `flask` and `docker` SDK.
- Falco with the modern eBPF engine.
- Root / sudo access.

---

## 3. Repository structure

```
sentinel_docker/
├── install.sh                        # one installer for both layers
├── uninstall.sh                      # reverses the install
├── sentinel.conf                     # one configuration file
├── README.md                         # this file
├── prevention/                       # MODULE 1 — Defense 2
│   ├── authz_plugin.py               # the fail-closed AuthZ plugin
│   ├── docker-authz.service          # systemd unit
│   └── policy.json                   # deny rules / image allow-list
├── detection/                        # MODULE 2 — Defense 1
│   ├── rules_detection_falco.yaml    # the Falco detection rules
│   ├── sentinel_webhook.py           # the Flask policy engine
│   └── responder.py                  # the isolation logic
├── falco/
│   └── config.d/configfalco.yaml     # Falco output configuration
└── docs/
    ├── ARCHITECTURE.md               # the two-layer design
    └── VALIDATION.md                 # the test matrix results
```

**Where each piece comes from:**

| Repo file | Source | Author |
|---|---|---|
| `prevention/authz_plugin.py`, `policy.json` | the attack-2 defense work | Defense 2 |
| `detection/sentinel_webhook.py`, `responder.py` | the Sentinel_Falco work | Defense 1 |
| `detection/rules_detection_falco.yaml` | Falco rules (expanded version) | Defense 1 |
| `install.sh`, `sentinel.conf`, `README.md` | integration | Team |

---

## 4. Configuration — `sentinel.conf`

A single file drives both layers. The installer reads it and starts each service accordingly.

```yaml
# Sentinel_Docker configuration
prevention:
  enabled: true
  mode: fail-closed        # fail-closed = block blind requests | fail-open = legacy behaviour
detection:
  enabled: true
  mode: enforce            # enforce = isolate | detect = alert only
  webhook_port: 5000
  audit_log: /var/log/sentinel/audit.jsonl
```

### The four operating modes

The modes map one-to-one to the demonstration states. Changing one file is the only difference between them.

| Prevention | Detection | What it shows |
|---|---|---|
| fail-open | off | Vulnerable baseline — the attacks succeed |
| fail-open | enforce | Detection layer — attacks detected and quarantined |
| fail-closed | off | Prevention layer — the bypass is denied at request time |
| fail-closed | enforce | Full application — both layers active (final state) |

---

## 5. Installation

```bash
sudo ./install.sh
```

The installer deploys both layers **in the right order**:

1. **Prevention first.** Installs the plugin, its policy and its systemd unit. Reads `prevention.mode` from `sentinel.conf` and passes `--fail-closed` when set. Wires the daemon to the plugin, then restarts Docker **(the daemon attaches authorization plugins only at startup — this order matters).**
2. **Detection next.** Installs the Falco rules and output config, restarts Falco, then starts the policy engine and responder according to `detection.mode`.
3. **Sanity checks.** Confirms the plugin is attached, Falco is active, and the webhook answers.

> Adapt the service paths in `install.sh` to match your deployed file locations if they differ. The **structure and the order** are what matter.

### Detection-layer configuration notes (applied by the installer)

Three settings are required for the detection layer to work correctly:

- **`configfalco.yaml`** must set `json_output: true` (otherwise Falco sends plain text and the webhook rejects it) and must **not** contain keys unknown to your Falco version (an unknown key makes the service crash-loop and detect nothing).
- **`sentinel_webhook.py`** normalizes the alert priority to upper-case before comparing it (Falco emits `Critical`; the engine compares against `CRITICAL`).
- **`rules_detection_falco.yaml`** matches sensitive host-file access and namespace-entry behaviour, covering both the host root and container-mounted host paths.

These are documented in `docs/VALIDATION.md` as the three fixes that make the detection layer reliable.

---

## 6. Validation

Validation reuses the four modes above. The attack procedures themselves live in the **attack-side materials** and are replayed from the attack snapshots (`A1`, `A2`); this README covers only the **defensive outcome** you should observe.

Restore each state and confirm the expected behaviour:

| State | Replay (from attack snapshots) | Expected defensive outcome |
|---|---|---|
| fail-open, detection off | attack 1, attack 2 | attacks succeed — baseline only |
| fail-open, detection enforce | attack 1, attack 2 | **CRITICAL alert → container paused** within ~1 s |
| fail-closed, detection off | attack 2 | **request denied at the API** (fail-closed) |
| fail-closed, detection enforce | attack 1, attack 2 | prevention denies what it can; detection quarantines the rest |

A legitimate container (a normal `run`) must continue to work in **every** mode — no regression. Capture the webhook log, the paused-container listing, and the audit entries as the report's proof screenshots.

> **Framing:** the detection layer is a *detection/response* layer — a sensitive host file may be read just **before** the pause arrives. It complements the *prevention* layer, which denies the same request before it executes. Together they form defense in depth.

---

## 7. How the two layers coexist (validated)

- **Scope:** the prevention module enforces only on container-creation requests. The responder's own API calls (pause, network disconnect) carry no creation body, so they pass the plugin untouched.
- **Install order:** the plugin service starts before Docker's final restart; Falco and the webhook start afterwards.
- **Shared audit:** both layers log to `/var/log/sentinel/` in one line format (`layer, decision, reason, declared_len, received_len`) — one timeline for the whole story.

---

## 8. Uninstall

```bash
sudo ./uninstall.sh
```

Stops the responder, removes the plugin from `daemon.json`, restarts Docker, and restores Falco's default rules directory.

---

## 9. Snapshots (demo states)

| Snapshot | Demo |
|---|---|
| `A1-runc-vulnerable` | Attack 1 reproduced |
| `A2-authz-bypass` | Attack 2 reproduced |
| `DEF-sentinel-validated` | Both attacks detected + isolated by Sentinel_Docker |

**Golden rule:** take each snapshot with the network **disconnected**, after cleaning up the test containers.
