#!/bin/bash
# build.sh — builds and captures the evidence
DOCKER_BUILDKIT=0 docker build --no-cache -t leaky2 . 2>&1 | tee build-escape.log
echo "--- PASS if the log shows the host's /etc/shadow (Debian accounts + your own hash)"
