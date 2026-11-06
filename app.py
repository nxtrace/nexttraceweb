import os

# Tests opt out before import; production uses a single cooperative Gunicorn worker.
if os.environ.get('NTWA_ASYNC_MODE', 'gevent') == 'gevent':
    from gevent import monkey
    monkey.patch_all()

import logging
from flask import Flask
from ntwa.config import env_float, env_int, env_bool, load_secret_key, parse_trusted_hosts
from ntwa.http import register_routes

logging.basicConfig(level=os.environ.get('NTWA_LOG_LEVEL', 'INFO').upper())
app = Flask(__name__, static_folder='assets')
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=env_bool('NTWA_SESSION_COOKIE_SECURE', False),
    NTWA_NEXTTRACE_FLAVOR=os.environ.get('NTWA_NEXTTRACE_FLAVOR', 'nexttrace'),
    NTWA_NEXTTRACE_PATH=os.environ.get('NTWA_NEXTTRACE_PATH', '/usr/local/bin/nexttrace'),
    NTWA_TRUSTED_HOSTS=parse_trusted_hosts(os.environ.get('NTWA_TRUSTED_HOSTS')),
    NTWA_TRACE_IDLE_TIMEOUT_SECONDS=max(0, env_float('NTWA_TRACE_IDLE_TIMEOUT_SECONDS', 120)),
    NTWA_TRACE_MAX_DURATION_SECONDS=max(0, env_float('NTWA_TRACE_MAX_DURATION_SECONDS', 0)),
    NTWA_MAX_ACTIVE_TRACES=max(1, env_int('NTWA_MAX_ACTIVE_TRACES', 64)),
    NTWA_MIN_START_INTERVAL_SECONDS=max(0, env_float('NTWA_MIN_START_INTERVAL_SECONDS', 1)),
)
register_routes(app)
