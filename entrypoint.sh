#!/bin/bash

set -euo pipefail

exec python3 /app/docker/configure.py "$@"
