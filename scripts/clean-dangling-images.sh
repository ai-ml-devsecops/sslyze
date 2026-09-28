#!/usr/bin/env bash
# Remove dangling (<none>:<none>) images left behind by multi-stage builds.
set -euo pipefail
podman image prune -f
