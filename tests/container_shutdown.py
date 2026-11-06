"""Run on the Docker host in the test container's network namespace only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import container_acceptance as acceptance


def docker(*arguments, timeout=15):
    return subprocess.check_output(['docker', *arguments], text=True, timeout=timeout).strip()


def native_in_container(init_pid):
    namespace = os.readlink(f'/proc/{init_pid}/ns/pid')
    candidates = {}
    for pid, status in acceptance.natives().items():
        try:
            if os.readlink(f'/proc/{pid}/ns/pid') == namespace:
                candidates[pid] = status
        except (FileNotFoundError, ProcessLookupError):
            pass
    if not candidates:
        return None
    acceptance.check(len(candidates) == 1, 'Container has more than one native process')
    pid, status = next(iter(candidates.items()))
    acceptance.check(all(int(uid) == 10001 for uid in status['Uid'].split()), 'Native UID changed')
    acceptance.check(int(status['CapEff'], 16) == 0x2000, 'Native capabilities differ from NET_RAW')
    return pid


def main(container, container_stop=False):
    state = json.loads(docker('inspect', '--format', '{{json .State}}', container))
    acceptance.check(state['Running'], 'Container is not running')
    init_pid = state['Pid']
    master = docker('exec', container, 'pgrep', '-o', '-f', 'gunicorn.*app:app')
    acceptance.check(master.isdigit(), 'Gunicorn master PID was not found')
    opener = acceptance.client()
    payload = dict(ip='9.9.9.9', request_id=uuid.uuid4().hex,
                   extra=dict(protocol='icmp', intervalSeconds=1, maxHop=1, minHop=1,
                              packetSize=52, port=80, dataProvider='disable-geoip'))
    first = acceptance.request(opener, '/api/traces', payload, expected=201)
    path = '/api/traces/' + first['task_id']
    native_pid = acceptance.wait_for(lambda: native_in_container(init_pid), timeout=4)
    with opener.open(acceptance.BASE + path + '/events', timeout=8) as stream:
        current = acceptance.snapshot(stream)
        deadline = time.monotonic() + 4
        while not acceptance.total_sent(current) and time.monotonic() < deadline:
            acceptance.check(current['state'] not in acceptance.TERMINAL,
                             'Native task ended before the shutdown check')
            current = acceptance.snapshot(stream)
        acceptance.check(acceptance.total_sent(current) > 0, 'No probe arrived before shutdown')
        before = acceptance.total_sent(current)
        # Signal immediately while the SSE response is open; no operator round-trip.
        started = time.monotonic()
        if container_stop:
            # PID 1 also stops Nginx, so the stream may close before its final frame.
            stopper = subprocess.Popen(['docker', 'stop', '-t', '10', container],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stopper.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                stopper.kill()
                stopper.communicate()
                raise AssertionError('Docker stop exceeded its grace period')
            acceptance.check(stopper.returncode == 0, 'Docker stop failed')
        else:
            docker('exec', container, 'kill', '-TERM', master, timeout=5)
            while current['state'] not in acceptance.TERMINAL:
                acceptance.check(time.monotonic() - started < 12, 'Shutdown did not flush a terminal snapshot')
                current = acceptance.snapshot(stream)
            acceptance.check(current['task_id'] == first['task_id'] and current['state'] == 'cancelled',
                             'Shutdown did not cancel the owned task')
            acceptance.check(current['error'] is None, 'Shutdown produced a task error')
            acceptance.check(acceptance.total_sent(current) >= before, 'Shutdown lost received probes')
    exit_code = docker('wait', container)
    state = json.loads(docker('inspect', '--format', '{{json .State}}', container))
    expected_exit = 143 if container_stop else 0
    acceptance.check(exit_code == str(expected_exit) and state['ExitCode'] == expected_exit
                     and not state['Running'] and not state['OOMKilled'],
                     f'Container did not exit cleanly: {exit_code}')
    acceptance.wait_for(lambda: not Path('/proc', str(native_pid)).exists(), timeout=3)
    logs = subprocess.check_output(['docker', 'logs', container], text=True,
                                   stderr=subprocess.STDOUT, timeout=5)
    lowered = logs.lower()
    for forbidden in ('control server', 'controlserver', 'read-only file system', 'permission denied'):
        acceptance.check(forbidden not in lowered, f'Container logs contain {forbidden!r}')
    acceptance.check('public_trace_finished state=cancelled reaped=True' in logs,
                     'No successful native reaping record in container logs')
    acceptance.report('container_stop_with_open_sse' if container_stop else 'gunicorn_shutdown_with_open_sse',
                      native_pid=native_pid,
                      elapsed_seconds=round(time.monotonic() - started, 2),
                      received_probes=acceptance.total_sent(current),
                      terminal=None if container_stop else current['state'],
                      exit_code=state['ExitCode'], reaped=True)


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3) or len(sys.argv) == 3 and sys.argv[2] != '--container-stop':
        raise SystemExit('Usage: container_shutdown.py CONTAINER_ID [--container-stop] (network namespace only)')
    main(sys.argv[1], container_stop=len(sys.argv) == 3)
