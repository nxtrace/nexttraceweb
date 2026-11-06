import atexit
import ipaddress
import math
import json
import secrets
import shutil
import socket
import time
from pathlib import Path
from urllib.parse import urlparse
from flask import Response, g, jsonify, render_template, request, session, stream_with_context
from .config import PayloadError, normalize_target, build_trace_params
from .tasks import Registry, TERMINAL
from .public import PublicPolicy


def register_routes(app):
    public = PublicPolicy(app.config) if app.config.get('NTWA_PUBLIC_MODE') else None
    if public:
        app.config['MAX_CONTENT_LENGTH'] = 8192
    registry = Registry(app.config, public)
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
        if public and request.path.startswith('/api/'):
            g.trace_client, trusted = public.client(request)
            scheme = request.headers.get('X-Forwarded-Proto', request.scheme) if trusted else request.scheme
            if app.config['SESSION_COOKIE_SECURE'] and scheme != 'https':
                return jsonify(code='https_required'), 403
            if request.method == 'POST' and (not request.is_json or request.headers.get('Sec-Fetch-Site') == 'cross-site'
                    or origin and urlparse(origin).scheme != scheme):
                return jsonify(code='invalid_origin'), 403
            registry.limits.rates([(('api', g.trace_client), 2, 30), (('api', 'global'), 60, 120)])
            if request.method == 'POST':
                # Enforce the same body ceiling even on controls that do not parse JSON.
                request.get_data(cache=True)
        session.setdefault('trace_owner', secrets.token_hex(24))

    @app.errorhandler(PayloadError)
    def payload_error(error):
        result = dict(code=error.code, message=error.message)
        if error.retry_after_seconds is not None:
            result['retry_after_seconds'] = error.retry_after_seconds
        response = jsonify(result)
        if error.retry_after_seconds is not None:
            response.headers['Retry-After'] = str(max(1, math.ceil(error.retry_after_seconds)))
        return response, 429 if error.retry_after_seconds is not None else error.status_code

    @app.errorhandler(413)
    def payload_too_large(error):
        return jsonify(code='invalid_payload', message='请求过大'), 413

    @app.after_request
    def private_responses(response):
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.get('/healthz')
    def healthz():
        binary = app.config['NTWA_NEXTTRACE_PATH']
        available = Path(binary).is_file() or bool(shutil.which(binary))
        if public:
            return jsonify(status='ok' if available else 'degraded'), 200 if available else 503
        with registry.lock:
            registry.prune()
            active = sum(task.state not in TERMINAL for task in registry.tasks.values())
        return jsonify(status='ok' if available else 'degraded', nexttrace_available=available, nexttrace_path=binary, active_traces=active), 200 if available else 503

    @app.get('/api/devices')
    def devices():
        if public:
            names = [public.device] if public.device else []
            return jsonify(devices=names, count=len(names))
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
        version = value.get('ipVersion')
        if version not in (None, '', 'all', 'ipv4', 'ipv6'):
            raise PayloadError('invalid_payload', '地址版本无效')
        release = None
        if public:
            public.resolve_target(target)
            registry.limits.rates([(('resolve', g.trace_client), .1, 3), (('resolve', 'global'), 2, 4)])
            release = registry.limits.acquire([(('resolve', g.trace_client), 1), (('resolve', 'global'), 4)])
        family = {'ipv4': socket.AF_INET, 'ipv6': socket.AF_INET6}.get(version, socket.AF_UNSPEC)
        try:
            from gevent import Timeout
            with Timeout(3, False):
                addresses = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(target, None, family, socket.SOCK_DGRAM)))
                if public:
                    if len(addresses) > 16:
                        raise PayloadError('invalid_target', '解析结果过多')
                    addresses = list(dict.fromkeys(public.target(address) for address in addresses))
                return jsonify(addresses=addresses)
        except socket.gaierror:
            pass
        finally:
            if release:
                release()
        raise PayloadError('invalid_target', '无法解析目标')

    @app.post('/api/traces')
    def create():
        value = body()
        try:
            raw_ip = value.get('ip', '')
            if not isinstance(raw_ip, str):
                raise ValueError('IP must be a string')
            target = public.target(raw_ip) if public else str(ipaddress.ip_address(raw_ip))
        except ValueError:
            raise PayloadError('invalid_target', '创建任务需要明确 IP')
        extra = value.get('extra', {})
        request_id = value.get('request_id')
        if not isinstance(extra, dict) or not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
            raise PayloadError('invalid_payload', '缺少有效参数或 request_id')
        extra = dict(extra)
        extra.setdefault('intervalSeconds', '1')
        params = public.prepare(target, extra) if public else build_trace_params(target, extra)
        task = registry.create(session['trace_owner'], request_id, params, client=getattr(g, 'trace_client', None))
        return jsonify(task.snapshot()), 201

    def owned(task_id):
        task = registry.get(session['trace_owner'], task_id)
        return task

    @app.get('/api/traces/<task_id>')
    def status(task_id):
        task = owned(task_id)
        if task is None:
            return jsonify(code='trace_not_running'), 404
        if public:
            registry.limits.rates([(('status', g.trace_client), 2, 20)])
        return jsonify(task.snapshot()), 200, {'Cache-Control': 'no-store'}

    @app.post('/api/traces/<task_id>/lease')
    def lease(task_id):
        task = owned(task_id)
        if task is None:
            return jsonify(code='trace_not_running'), 404
        if public:
            registry.limits.rates([(('lease', g.trace_client), 1, 10)])
        with task.condition:
            task.lease_at = time.monotonic()
        return jsonify(task.snapshot())

    @app.post('/api/traces/<task_id>/stop')
    def stop(task_id):
        task = owned(task_id)
        if task is None:
            return jsonify(code='trace_not_running'), 404
        if public:
            registry.limits.rates([(('stop', g.trace_client), 1, 10)])
        task.stop()
        task.done.wait(2)
        snapshot = task.snapshot()
        return jsonify(snapshot), 200 if snapshot['state'] in TERMINAL else 202

    @app.get('/api/traces/<task_id>/events')
    def events(task_id):
        task = owned(task_id)
        if task is None:
            return jsonify(code='trace_not_running'), 404
        release = lambda: None
        if public:
            registry.limits.rates([(('events', g.trace_client), .2, 8)])
            release = registry.limits.acquire([(('events_task', task.id), 2), (('events_client', g.trace_client), 4), (('events', 'global'), 32)])

        @stream_with_context
        def stream():
            try:
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
            finally:
                release()
        response = Response(stream(), mimetype='text/event-stream', headers={'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no'})
        response.call_on_close(release)
        return response
