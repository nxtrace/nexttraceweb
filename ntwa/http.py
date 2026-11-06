import atexit
import ipaddress
import json
import secrets
import shutil
import socket
import time
from pathlib import Path
from urllib.parse import urlparse
from flask import Response, jsonify, render_template, request, session, stream_with_context
from .config import PayloadError, normalize_target, build_trace_params
from .tasks import Registry, TERMINAL


def register_routes(app):
    registry = Registry(app.config)
    app.extensions['traces'] = registry
    atexit.register(registry.shutdown)

    @app.before_request
    def validate_request():
        hosts = app.config['NTWA_TRUSTED_HOSTS']
        host = request.host.split(']')[0].lstrip('[') if request.host.startswith('[') else request.host.split(':')[0]
        if hosts and host.lower() not in hosts:
            return jsonify(code='untrusted_host'), 400
        origin = request.headers.get('Origin')
        if request.method == 'POST' and origin and urlparse(origin).netloc != request.host:
            return jsonify(code='invalid_origin'), 403
        session.setdefault('trace_owner', secrets.token_hex(24))

    @app.errorhandler(PayloadError)
    def payload_error(error):
        result = dict(code=error.code, message=error.message)
        if error.retry_after_seconds is not None:
            result['retry_after_seconds'] = error.retry_after_seconds
        return jsonify(result), 429 if error.retry_after_seconds is not None else 400

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.get('/healthz')
    def healthz():
        binary = app.config['NTWA_NEXTTRACE_PATH']
        available = Path(binary).is_file() or bool(shutil.which(binary))
        with registry.lock:
            registry.prune()
            active = sum(task.state not in TERMINAL for task in registry.tasks.values())
        return jsonify(status='ok' if available else 'degraded', nexttrace_available=available, nexttrace_path=binary, active_traces=active), 200 if available else 503

    @app.get('/api/devices')
    def devices():
        from .config import DEVICE_PATTERN
        import re
        try:
            names = list(dict.fromkeys(name for _, name in socket.if_nameindex() if re.fullmatch(DEVICE_PATTERN, name)))
        except OSError:
            names = []
        return jsonify(devices=names, count=len(names))

    def body():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise PayloadError('invalid_payload', '请求必须为 JSON 对象')
        return value

    @app.post('/api/traces/resolve')
    def resolve():
        value = body()
        target = normalize_target(value.get('target'))
        family = {'ipv4': socket.AF_INET, 'ipv6': socket.AF_INET6}.get(value.get('ipVersion'), socket.AF_UNSPEC)
        try:
            from gevent import Timeout
            with Timeout(3, False):
                addresses = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(target, None, family, socket.SOCK_DGRAM)))
                return jsonify(addresses=addresses)
        except socket.gaierror:
            pass
        raise PayloadError('invalid_target', '无法解析目标')

    @app.post('/api/traces')
    def create():
        value = body()
        try:
            target = str(ipaddress.ip_address(value.get('ip', '')))
        except ValueError:
            raise PayloadError('invalid_target', '创建任务需要明确 IP')
        extra = value.get('extra', {})
        request_id = value.get('request_id')
        if not isinstance(extra, dict) or not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
            raise PayloadError('invalid_payload', '缺少有效参数或 request_id')
        extra = dict(extra)
        extra.setdefault('intervalSeconds', '1')
        params = build_trace_params(target, extra)
        task = registry.create(session['trace_owner'], request_id, params)
        return jsonify(task.snapshot()), 201

    def owned(task_id):
        task = registry.get(session['trace_owner'], task_id)
        return task

    @app.get('/api/traces/<task_id>')
    def status(task_id):
        task = owned(task_id)
        if task is None:
            return jsonify(code='trace_not_running'), 404
        return jsonify(task.snapshot()), 200, {'Cache-Control': 'no-store'}

    @app.post('/api/traces/<task_id>/lease')
    def lease(task_id):
        task = owned(task_id)
        if task is None:
            return jsonify(code='trace_not_running'), 404
        with task.condition:
            task.lease_at = time.monotonic()
        return jsonify(task.snapshot())

    @app.post('/api/traces/<task_id>/stop')
    def stop(task_id):
        task = owned(task_id)
        if task is None:
            return jsonify(code='trace_not_running'), 404
        task.stop()
        task.done.wait(2)
        snapshot = task.snapshot()
        return jsonify(snapshot), 200 if snapshot['state'] in TERMINAL else 202

    @app.get('/api/traces/<task_id>/events')
    def events(task_id):
        task = owned(task_id)
        if task is None:
            return jsonify(code='trace_not_running'), 404

        @stream_with_context
        def stream():
            sent = -1
            last_sent = 0
            while True:
                with task.condition:
                    if task.seq == sent and task.state not in TERMINAL:
                        task.condition.wait(timeout=10)
                    while task.state not in TERMINAL and time.monotonic() - last_sent < .1:
                        task.condition.wait(timeout=.1 - (time.monotonic() - last_sent))
                    snapshot = task.snapshot()
                if snapshot['seq'] != sent:
                    yield 'event: snapshot\nid: %s\ndata: %s\n\n' % (snapshot['seq'], json.dumps(snapshot, ensure_ascii=False))
                    sent = snapshot['seq']
                    last_sent = time.monotonic()
                else:
                    yield ': keepalive\n\n'
                if snapshot['state'] in TERMINAL:
                    return
        return Response(stream(), mimetype='text/event-stream', headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})
