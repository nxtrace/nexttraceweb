"""Exercise shutdown while a real gevent worker still owns an SSE request."""
import http.cookiejar
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request


@unittest.skipIf(sys.platform == 'win32', 'Gunicorn requires a Unix runtime')
class GunicornShutdownTests(unittest.TestCase):
    def test_sigterm_reaps_child_before_waiting_for_open_sse_to_drain(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix='ntwa-shutdown-') as directory:
            directory = Path(directory)
            pid_file = directory / 'native.pid'
            heartbeat = directory / 'heartbeat'
            native = directory / 'native.py'
            native.write_text(
                '#!' + sys.executable + '\n'
                'import json,os,time\n'
                'open(os.environ["NTWA_TEST_PID_FILE"],"w").write(str(os.getpid()))\n'
                'print(json.dumps(dict(schema_version=1,seq=1,type="start")),flush=True)\n'
                'while True:\n'
                ' open(os.environ["NTWA_TEST_HEARTBEAT"],"w").write(str(time.monotonic()))\n'
                ' time.sleep(.02)\n'
            )
            native.chmod(0o755)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            env = os.environ.copy()
            env.update(
                NTWA_ASYNC_MODE='gevent',
                NTWA_SECRET_KEY='isolated-local-shutdown-test',
                NTWA_NEXTTRACE_PATH=str(native),
                NTWA_TEST_PID_FILE=str(pid_file),
                NTWA_TEST_HEARTBEAT=str(heartbeat),
                NTWA_MIN_START_INTERVAL_SECONDS='0',
            )
            stream = None
            child_pid = None
            with (directory / 'gunicorn.log').open('w+') as log:
                server = subprocess.Popen([
                    sys.executable, '-m', 'gunicorn', '--config', str(root / 'gunicorn.conf.py'),
                    '--worker-class', 'gevent', '--workers', '1', '--graceful-timeout', '2',
                    '--timeout', '5', '--bind', f'127.0.0.1:{port}', 'app:app',
                ], cwd=root, env=env, stdout=log, stderr=log, start_new_session=True)
                try:
                    base = f'http://127.0.0.1:{port}'
                    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            opener.open(base + '/healthz', timeout=.2).close()
                            break
                        except (urllib.error.URLError, TimeoutError):
                            if server.poll() is not None or time.monotonic() >= deadline:
                                log.flush()
                                log.seek(0)
                                self.fail('Gunicorn did not start: ' + log.read())
                            time.sleep(.05)
                    request = urllib.request.Request(
                        base + '/api/traces',
                        data=json.dumps(dict(ip='192.0.2.1', extra={}, request_id='shutdown-test')).encode(),
                        headers={'Content-Type': 'application/json'},
                    )
                    with opener.open(request, timeout=2) as response:
                        task = json.load(response)
                    stream = opener.open(base + '/api/traces/' + task['task_id'] + '/events', timeout=3)
                    self.assertEqual(stream.readline().decode().strip(), 'event: snapshot')
                    deadline = time.monotonic() + 3
                    while not pid_file.exists() or not heartbeat.exists():
                        if time.monotonic() >= deadline:
                            self.fail('Native test process did not start')
                        time.sleep(.01)
                    child_pid = int(pid_file.read_text())
                    # Keep the SSE response open while the master receives SIGTERM.
                    server.terminate()
                    self.assertEqual(server.wait(timeout=8), 0)
                    first_heartbeat = heartbeat.read_text()
                    time.sleep(.1)
                    self.assertEqual(heartbeat.read_text(), first_heartbeat)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
                finally:
                    if stream is not None:
                        stream.close()
                    if child_pid is None and pid_file.exists():
                        child_pid = int(pid_file.read_text())
                    if child_pid is not None:
                        try:
                            os.kill(child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if server.poll() is None:
                        try:
                            os.killpg(server.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        server.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()
