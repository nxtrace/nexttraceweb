"""Run inside the isolated TLS/auth/sub-path deployment container."""
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request
import uuid


PREFIX = '/tools/nexttrace'
ORIGIN = 'https://localhost:30443'
SECRETS = Path('/run/ntwa-secrets')


def check(condition, message):
    if not condition:
        raise AssertionError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def client(authenticated=True):
    context = ssl.create_default_context(cafile=str(SECRETS / 'cert.pem'))
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(jar), NoRedirect())
    if authenticated:
        password = (SECRETS / 'password').read_text().removesuffix('\n')
        authorization = base64.b64encode(('deploy:' + password).encode()).decode()
        opener.addheaders = [('Authorization', 'Basic ' + authorization)]
    return opener, jar


def request(opener, path, body=None, expected=200, headers=None, origin=ORIGIN):
    headers = dict(headers or {})
    if body is not None:
        headers['Content-Type'] = 'application/json'
    payload = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(origin + path, data=payload, headers=headers)
    try:
        response = opener.open(req, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read()
        check(response.status == expected, f'{path}: expected {expected}, got {response.status}')
        return response.headers, data


def snapshot(stream):
    while line := stream.readline():
        if line.startswith(b'data: '):
            return json.loads(line[6:])
    raise AssertionError('SSE ended before its snapshot')


def main():
    subprocess.run(['python', '/app/docker/healthcheck.py'], check=True, timeout=5)
    expected = os.environ['EXPECTED_NEXTTRACE_TAG']
    version = subprocess.run(['/usr/local/bin/nexttrace', '--version'],
                             capture_output=True, text=True, check=True, timeout=5)
    check(re.search(r'(?<![\w.])' + re.escape(expected) + r'(?![\w.])',
                    version.stdout + version.stderr), 'Native version differs from the resolved release')
    password = (SECRETS / 'password').read_text().removesuffix('\n')
    auth_file = Path('/tmp/ntwa.htpasswd')
    check(stat.S_IMODE(auth_file.stat().st_mode) == 0o600, 'Authentication file permissions differ from 0600')
    check(auth_file.read_text().startswith('deploy:$2'), 'Authentication file does not contain bcrypt')
    check(password not in auth_file.read_text() and password not in Path('/tmp/ntwa-nginx.conf').read_text(),
          'Plaintext password reached generated configuration')

    anonymous, _ = client(False)
    for suffix in ('/', '/assets/js/main.js', '/api/devices', '/api/traces/missing/events'):
        headers, _ = request(anonymous, PREFIX + suffix, expected=401)
        check(headers.get('WWW-Authenticate', '').startswith('Basic '), 'Missing Basic Auth challenge')
    opener, jar = client()
    headers, _ = request(anonymous, PREFIX + '/?trace=1.1.1.1&protocol=tcp',
                         expected=308, origin='http://localhost:30081',
                         headers={'X-Forwarded-Proto': 'https'})
    check(headers['Location'] == ORIGIN + PREFIX + '/?trace=1.1.1.1&protocol=tcp',
          'HTTPS redirect lost its configured origin, path or query')
    headers, _ = request(opener, PREFIX + '?trace=1.1.1.1', expected=301)
    check(headers['Location'] in (PREFIX + '/?trace=1.1.1.1', ORIGIN + PREFIX + '/?trace=1.1.1.1'),
          'Sub-path redirect lost its query')
    headers, page = request(opener, PREFIX + '/')
    check(b'assets/js/main.js' in page, 'Page did not load below the configured prefix')
    check(headers.get('Content-Security-Policy') and headers.get('X-Content-Type-Options') == 'nosniff',
          'Deployment lost security response headers')
    check(any(cookie.secure for cookie in jar), 'HTTPS session cookie is not secure')
    _, script = request(opener, PREFIX + '/assets/js/main.js')
    check(bool(script), 'Prefixed asset is empty')
    request(opener, '/', expected=404)
    _, devices = request(opener, PREFIX + '/api/devices', headers={
        'X-Forwarded-Proto': 'http', 'X-Forwarded-For': 'malformed', 'X-Real-IP': 'malformed'})
    check('devices' in json.loads(devices), 'Spoofed forwarding headers reached the application')
    request(opener, PREFIX + '/api/traces', body={}, expected=403,
            headers={'Origin': 'http://localhost:30443'})
    _, denied = request(opener, PREFIX + '/api/traces',
                        body=dict(ip='127.0.0.1', request_id=uuid.uuid4().hex, extra={}), expected=403,
                        headers={'Origin': ORIGIN})
    check(json.loads(denied)['code'] == 'target_not_allowed', 'Public target policy was bypassed')

    payload = dict(ip='1.1.1.1', request_id=uuid.uuid4().hex,
                   extra=dict(protocol='icmp', intervalSeconds=1, minHop=1, maxHop=1,
                              packetSize=52, port=80, dataProvider='disable-geoip'))
    _, created = request(opener, PREFIX + '/api/traces', payload, expected=201,
                         headers={'Origin': ORIGIN})
    task = json.loads(created)
    task_path = PREFIX + '/api/traces/' + task['task_id']
    with opener.open(ORIGIN + task_path + '/events', timeout=15) as stream:
        check(stream.headers.get_content_type() == 'text/event-stream', 'Prefixed SSE did not open')
        current = snapshot(stream)
        check(current['task_id'] == task['task_id'], 'Prefixed SSE returned another task')
        deadline = time.monotonic() + 12
        while not any(row['sent'] for row in current['rows']):
            check(current['state'] not in {'completed', 'failed', 'cancelled'},
                  'Native task ended before producing a probe')
            check(time.monotonic() < deadline, 'Native probe did not reach prefixed SSE')
            current = snapshot(stream)
        request(opener, task_path + '/lease', {}, headers={'Origin': ORIGIN})
        _, stopped = request(opener, task_path + '/stop', {}, headers={'Origin': ORIGIN})
        check(json.loads(stopped)['state'] == 'cancelled', 'Prefixed stop failed')
        while current['state'] not in {'completed', 'failed', 'cancelled'}:
            current = snapshot(stream)
        check(current['state'] == 'cancelled', 'Prefixed SSE missed its terminal snapshot')
    print(json.dumps(dict(check='tls_auth_subpath_deployment_passed', nexttrace_release=expected)), flush=True)


if __name__ == '__main__':
    main()
