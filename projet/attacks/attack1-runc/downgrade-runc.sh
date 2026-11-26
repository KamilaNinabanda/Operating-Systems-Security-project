#!/bin/bash
# Installs the vulnerable runc 1.1.11 (static binary, upstream release)
curl -fsSL -o runc-vuln https://github.com/opencontainers/runc/releases/download/v1.1.11/runc.amd64
sudo install -m 755 runc-vuln /usr/local/bin/runc
sudo systemctl restart docker containerd
runc --version    # must print: 1.1.11
