# Attack 1 — runc container escape (CVE-2024-21626)

A vulnerable runc (<= 1.1.11) leaks an internal file descriptor (pointing to a
host directory) into the container's first process. The OCI config lets the image
author anchor the working directory on it (/proc/self/fd/N) — the process then
runs with its working directory INSIDE the host filesystem, and relative traversal
(../../) crosses the mount boundary to the host root.

Supply-chain scenario: any developer or CI system that BUILDS this image is
compromised — no --privileged, no volumes, no unusual flags.

## Files
- downgrade-runc.sh : installs the vulnerable runc 1.1.11
- Dockerfile.escape : the malicious build — reads the host's /etc/shadow
- Dockerfile.probe  : enumerates the leaked fd (its number varies per invocation)
- build.sh          : runs the malicious build and captures the log

## Prerequisite
Docker with the vulnerable runc in its exec path (runc --version → 1.1.11).
