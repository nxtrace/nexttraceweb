#!/bin/bash

set -euo pipefail

HOSTPORT="${1:-30080}"
APP_HOST="127.0.0.1"
APP_PORT="35000"
GUNICORN_PID=""
NGINX_PID=""

render_listen_directives() {
    python3 - "$HOSTPORT" <<'PY'
import ipaddress
import sys

raw = sys.argv[1].strip()

def validate_port(port_text):
    if not port_text.isdigit():
        raise SystemExit(f"Invalid port: {port_text}")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise SystemExit(f"Port out of range: {port}")
    return port

if raw.isdigit():
    port = validate_port(raw)
    print(f"listen {port};")
    print(f"listen [::]:{port};")
    raise SystemExit(0)

if raw.startswith("[") and "]:" in raw:
    host, port_text = raw[1:].split("]:", 1)
    ipaddress.IPv6Address(host)
    port = validate_port(port_text)
    print(f"listen [{host}]:{port};")
    raise SystemExit(0)

if ":" in raw:
    host, port_text = raw.rsplit(":", 1)
    port = validate_port(port_text)
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if host not in {"localhost"}:
            raise SystemExit(f"Invalid listen host: {host}")
    print(f"listen {host}:{port};")
    raise SystemExit(0)

raise SystemExit(f"Invalid listen address: {raw}")
PY
}

render_nginx_config() {
    local listen_directives
    listen_directives="$(render_listen_directives)"
    python3 - "$listen_directives" <<'PY'
from pathlib import Path
import sys

template = Path("/etc/nginx/nginx.conf.template").read_text()
rendered = template.replace("__LISTEN_DIRECTIVES__", sys.argv[1])
Path("/etc/nginx/nginx.conf").write_text(rendered)
PY
}

start_processes() {
    render_nginx_config

    gunicorn \
        --bind "${APP_HOST}:${APP_PORT}" \
        --worker-class eventlet \
        --workers 1 \
        --access-logfile - \
        --error-logfile - \
        app:app &
    GUNICORN_PID=$!

    nginx -g 'daemon off;' &
    NGINX_PID=$!
}

shutdown() {
    local exit_code="${1:-0}"

    if [[ -n "${GUNICORN_PID}" ]] && kill -0 "${GUNICORN_PID}" 2>/dev/null; then
        kill -TERM "${GUNICORN_PID}" 2>/dev/null || true
    fi
    if [[ -n "${NGINX_PID}" ]] && kill -0 "${NGINX_PID}" 2>/dev/null; then
        kill -TERM "${NGINX_PID}" 2>/dev/null || true
    fi

    wait "${GUNICORN_PID}" 2>/dev/null || true
    wait "${NGINX_PID}" 2>/dev/null || true
    exit "${exit_code}"
}

trap 'shutdown 143' SIGTERM SIGINT

start_processes

set +e
wait -n "${GUNICORN_PID}" "${NGINX_PID}"
status=$?
set -e

shutdown "${status}"
