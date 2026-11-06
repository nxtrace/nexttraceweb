"""Run inside an isolated public-mode container against the real native binary."""
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


BASE = 'http://127.0.0.1:30080'
TERMINAL = {'completed', 'cancelled', 'failed'}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def report(name, **values):
    print(json.dumps(dict(check=name, **values)), flush=True)


def client(jar=None):
    jar = jar if jar is not None else http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.cookies = jar
    return opener


def request(opener, path, body=None, expected=200):
    headers = {'Content-Type': 'application/json'} if body is not None else {}
    payload = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=payload, headers=headers)
    try:
        response = opener.open(req, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        value = json.load(response)
        check(response.status == expected, f'{path}: status={response.status}, payload={value}')
    return value


def snapshot(stream):
    while True:
        line = stream.readline()
        if not line:
            raise AssertionError('SSE ended before the expected snapshot')
        if line.startswith(b'data: '):
            return json.loads(line[6:])


def processes():
    result = {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / 'cmdline').read_bytes().split(b'\0')
            status = dict(line.split(':', 1) for line in (entry / 'status').read_text().splitlines() if ':' in line)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        result[int(entry.name)] = (args, status)
    return result


def natives():
    return {pid: status for pid, (args, status) in processes().items()
            if args and args[0] == b'/usr/local/bin/nexttrace'}


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('Timed out waiting for acceptance condition')


def total_sent(value):
    return sum(row['sent'] for row in value['rows'])


def running_native():
    running = natives()
    check(len(running) == 1, f'Expected one native process, found {list(running)}')
    pid, status = next(iter(running.items()))
    check(all(int(uid) == 10001 for uid in status['Uid'].split()), 'Native process UID changed')
    check(int(status['CapEff'], 16) == 0x2000, 'Native effective capabilities differ from NET_RAW')
    check(int(status['CapPrm'], 16) == 0x2000, 'Native permitted capabilities differ from NET_RAW')
    return pid


def infrastructure(opener):
    check(os.geteuid() == 10001, 'Acceptance process is not the image non-root user')
    for pid, (args, status) in processes().items():
        command = b' '.join(args)
        if b'gunicorn' in command or command.startswith(b'nginx:') or b'/app/entrypoint.sh' in command:
            check(all(int(uid) == 10001 for uid in status['Uid'].split()), f'Service PID {pid} runs as root')
            check(int(status['CapEff'], 16) == 0 and int(status['CapPrm'], 16) == 0,
                  f'Service PID {pid} has process capabilities')
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        pass
    else:
        raw.close()
        raise AssertionError('Web user can create raw sockets without the native executable')
    from nexttrace_mtr import build_mtr_json_command
    command = build_mtr_json_command('/usr/local/bin/nexttrace', [
        '127.0.0.1', '-q', '1', '--max-hops', '1',
        '--ttl-time', '1000', '--data-provider', 'disable-geoip', '--no-rdns',
    ], os.environ.get('NTWA_NEXTTRACE_FLAVOR', 'nexttrace'))
    probe = subprocess.run(command, capture_output=True, text=True, timeout=10, check=True)
    events = [json.loads(line) for line in probe.stdout.splitlines() if line.strip()]
    check(any(event.get('type') == 'probe' and event['record'].get('success') is True for event in events),
          'NET_RAW executable could not complete a real loopback probe')
    for directory in ('/app', '/etc'):
        check(os.statvfs(directory).f_flag & os.ST_RDONLY, f'{directory} is writable at the mount level')
    with tempfile.NamedTemporaryFile(dir='/tmp') as temporary:
        temporary.write(b'acceptance')
        temporary.flush()
    health = request(opener, '/healthz')
    check(health == {'status': 'ok'}, 'Public health response leaks internal configuration')
    request(opener, '/api/traces', dict(ip='127.0.0.1', request_id=uuid.uuid4().hex, extra={}), expected=403)
    request(opener, '/api/traces', dict(ip='1.1.1.1', request_id=uuid.uuid4().hex,
                                      extra={'intervalSeconds': .040}), expected=400)
    report('nonroot_readonly_public_policy', uid=os.geteuid(), web_raw_socket=False, native_loopback=True)


def create(opener, address):
    payload = dict(ip=address, request_id=uuid.uuid4().hex,
                   extra=dict(protocol='icmp', intervalSeconds=1, maxHop=1, minHop=1,
                              packetSize=52, port=80, dataProvider='disable-geoip'))
    first = request(opener, '/api/traces', payload, expected=201)
    path = '/api/traces/' + first['task_id']
    second = request(opener, '/api/traces', payload, expected=201)
    check(second['task_id'] == first['task_id'], 'Creation retry started another task')
    wait_for(lambda: len(natives()) == 1)
    return first['task_id'], path, running_native()


def resume_and_stop(opener):
    task_id, path, pid = create(opener, '1.1.1.1')
    other = client()
    for suffix, body in (('', None), ('/events', None), ('/stop', {}), ('/lease', {})):
        request(other, path + suffix, body, expected=404)
    with opener.open(BASE + path + '/events', timeout=15) as stream:
        check(stream.headers.get_content_type() == 'text/event-stream', 'Unexpected SSE content type')
        first = snapshot(stream)
        check(first['task_id'] == task_id, 'First SSE snapshot belongs to another task')
        deadline = time.monotonic() + 12
        while not total_sent(first) and time.monotonic() < deadline:
            first = snapshot(stream)
        check(total_sent(first) > 0, 'Real native process produced no probe records')
    # Recreate the browser transport from persisted cookies and its task ID.
    resumed = client(opener.cookies)
    request(resumed, path + '/lease', {})
    time.sleep(1.2)
    with resumed.open(BASE + path + '/events', timeout=15) as stream:
        current = snapshot(stream)
        check(current['task_id'] == task_id and current['seq'] >= first['seq'], 'Reconnect did not resume the task')
        deadline = time.monotonic() + 8
        while total_sent(current) <= total_sent(first) and time.monotonic() < deadline:
            current = snapshot(stream)
        check(total_sent(current) > total_sent(first), 'Probe statistics stopped advancing across disconnect')
        check(running_native() == pid, 'Reconnect replaced the native process')
        stopped = request(resumed, path + '/stop', {})
        if stopped['state'] not in TERMINAL:
            stopped = wait_for(lambda: (value if (value := request(resumed, path))['state'] in TERMINAL else None))
        check(stopped['state'] == 'cancelled', f'Stop returned {stopped["state"]}')
        check(total_sent(stopped) >= total_sent(current), 'Stop lost the latest received probes')
        terminal = snapshot(stream)
        while terminal['state'] not in TERMINAL:
            terminal = snapshot(stream)
        check(terminal['task_id'] == task_id and terminal['seq'] == stopped['seq'], 'SSE missed the final stopped snapshot')
    wait_for(lambda: not Path('/proc', str(pid)).exists())
    repeated = request(resumed, path + '/stop', {})
    check(repeated['state'] == stopped['state'] and repeated['seq'] == stopped['seq'], 'Repeated stop changed terminal state')
    report('sse_resume_and_idempotent_stop', pid=pid, before=total_sent(first), after=total_sent(stopped), reaped=True)


def orphan_recovery(opener):
    time.sleep(2.1)
    task_id, path, pid = create(opener, '8.8.8.8')
    started = time.monotonic()
    with opener.open(BASE + path + '/events', timeout=15) as stream:
        current = snapshot(stream)
        while current['state'] not in TERMINAL:
            check(time.monotonic() - started < 38, 'Orphan lease did not expire within the expected window')
            current = snapshot(stream)
    elapsed = time.monotonic() - started
    check(current['task_id'] == task_id and current['state'] == 'cancelled', 'Orphan did not end as cancelled')
    check(current['error'] is None, 'Orphan cleanup incorrectly produced a timeout failure')
    check(elapsed >= 25, 'Orphan stopped before its reconnect window elapsed')
    wait_for(lambda: not Path('/proc', str(pid)).exists())
    time.sleep(1.1)
    later = request(opener, path)
    check(later['seq'] == current['seq'] and later['state'] == 'cancelled' and later['error'] is None,
          'Terminal orphan task later changed or acquired an error')
    check(not natives(), 'Native process remains after orphan recovery')
    report('lease_expiry_with_open_sse', elapsed_seconds=round(elapsed, 2), pid=pid, reaped=True)


def main():
    opener = client()
    def ready():
        try:
            return request(opener, '/healthz')['status'] == 'ok'
        except (urllib.error.URLError, TimeoutError, AssertionError):
            return False
    wait_for(ready)
    infrastructure(opener)
    resume_and_stop(opener)
    orphan_recovery(opener)
    report('container_acceptance_passed')


if __name__ == '__main__':
    main()
