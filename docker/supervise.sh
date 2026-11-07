#!/bin/bash

set -euo pipefail

APP_HOST="127.0.0.1"
APP_PORT="35000"
GUNICORN_PID=""
NGINX_PID=""

start_processes() {
    gunicorn \
        --config /app/gunicorn.conf.py \
        --bind "${APP_HOST}:${APP_PORT}" \
        --worker-class gevent \
        --workers 1 \
        --access-logfile - \
        --error-logfile - \
        app:app &
    GUNICORN_PID=$!

    nginx -e stderr -c /tmp/ntwa-nginx.conf -g 'daemon off;' &
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
