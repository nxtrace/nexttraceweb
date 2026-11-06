import os
os.environ.setdefault('NTWA_ASYNC_MODE', 'threading')

import io
import json
import sys
import subprocess
import tempfile
import runpy
import types
from pathlib import Path
import time
import unittest
from unittest import mock

import app as app_module
from ntwa.config import PayloadError, build_trace_params, normalize_target
from ntwa.tasks import Registry, Task, TERMINAL


def events(*items):
    return ''.join(json.dumps(dict(schema_version=1, seq=index, **item)) + '\n' for index, item in enumerate(items, 1))


class FakeProcess:
    def __init__(self, output='', stderr='', code=0):
        self.stdout = io.StringIO(output)
        self.stderr = io.StringIO(stderr)
        self.returncode = code
        self.terminate = mock.Mock()
        self.kill = mock.Mock()
        self.wait = mock.Mock(return_value=code)

    def poll(self):
        return self.returncode


class AppRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.config = self.app.config.copy()
        self.app.config.update(NTWA_NEXTTRACE_PATH=sys.executable, NTWA_MIN_START_INTERVAL_SECONDS=0, NTWA_MAX_ACTIVE_TRACES=64, NTWA_TRUSTED_HOSTS=())
        # register_routes closes over this registry, so clear its in-memory state.
        self.registry = self.app.extensions['traces']
        self.registry.tasks.clear()
        self.registry.requests.clear()
        self.registry.last_start.clear()
        self.client = self.app.test_client()
        self.start = mock.patch.object(Task, 'start').start()

    def tearDown(self):
        mock.patch.stopall()
        self.registry.tasks.clear()
        self.registry.requests.clear()
        self.registry.last_start.clear()
        self.app.config.update(self.config)

    def create(self, request_id='request-one', **kwargs):
        return self.client.post('/api/traces', json=dict(ip='192.0.2.1', request_id=request_id, extra={}, **kwargs))

    def test_parameters_keep_interval_units_and_saved_40ms(self):
        params = build_trace_params('192.0.2.1', dict(intervalSeconds='0.040', protocol='tcp', packetSize='128', device='br-test0'))
        self.assertEqual(params[params.index('--ttl-time') + 1], '40')
        self.assertIn('--tcp', params)
        self.assertEqual(normalize_target('https://example.com:443/path'), 'example.com')
        with self.assertRaises(PayloadError):
            build_trace_params('192.0.2.1', dict(device='eth0;echo bad'))

    def test_create_defaults_to_one_second_and_retries_do_not_launch_again(self):
        first = self.create()
        second = self.create()
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.get_json()['task_id'], first.get_json()['task_id'])
        self.start.assert_called_once()
        task = self.registry.tasks[first.get_json()['task_id']]
        self.assertEqual(task.params[task.params.index('--ttl-time') + 1], '1000')
        mismatch = self.client.post('/api/traces', json=dict(ip='192.0.2.2', request_id='request-one', extra={}))
        self.assertEqual(mismatch.status_code, 400)

    def test_ownership_protects_status_stop_lease_and_stream(self):
        task_id = self.create().get_json()['task_id']
        other = self.app.test_client()
        for suffix, method in [('', 'get'), ('/stop', 'post'), ('/lease', 'post'), ('/events', 'get')]:
            with self.subTest(suffix=suffix):
                self.assertEqual(getattr(other, method)('/api/traces/' + task_id + suffix).status_code, 404)
        self.assertEqual(self.client.get('/api/traces/' + task_id).status_code, 200)

    def test_lease_refresh_and_stop_before_start_does_not_spawn(self):
        task_id = self.create().get_json()['task_id']
        task = self.registry.tasks[task_id]
        task.lease_at = 0
        self.assertEqual(self.client.post('/api/traces/' + task_id + '/lease').status_code, 200)
        self.assertGreater(task.lease_at, 0)
        self.assertEqual(self.client.post('/api/traces/' + task_id + '/stop').status_code, 200)
        self.assertEqual(self.client.post('/api/traces/' + task_id + '/stop').status_code, 200)
        with mock.patch('ntwa.tasks.subprocess.Popen') as popen:
            task.run()
        popen.assert_not_called()
        self.assertEqual(task.state, 'cancelled')

    def test_limits_remain_enforced_and_capacity_releases_on_terminal(self):
        self.app.config['NTWA_MAX_ACTIVE_TRACES'] = 1
        task_id = self.create().get_json()['task_id']
        limited = self.create('request-two')
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.get_json()['code'], 'trace_capacity_exceeded')
        self.registry.tasks[task_id].change('completed')
        self.assertEqual(self.create('request-two').status_code, 201)
        self.app.config['NTWA_MIN_START_INTERVAL_SECONDS'] = 60
        self.assertEqual(self.create('request-three').get_json()['code'], 'trace_rate_limited')

    def test_resolve_returns_addresses_without_creating_process(self):
        replies = [(2, 2, 17, '', ('192.0.2.1', 0)), (2, 2, 17, '', ('192.0.2.1', 0)), (2, 2, 17, '', ('192.0.2.2', 0))]
        with mock.patch('ntwa.http.socket.getaddrinfo', return_value=replies):
            response = self.client.post('/api/traces/resolve', json=dict(target='https://example.com/path', ipVersion='ipv4'))
        self.assertEqual(response.get_json()['addresses'], ['192.0.2.1', '192.0.2.2'])
        self.assertFalse(self.registry.tasks)
        self.start.assert_not_called()

    def test_malformed_requests_and_cross_origin_controls_are_rejected(self):
        self.assertEqual(self.client.post('/api/traces', data='{bad json', content_type='application/json').status_code, 400)
        self.assertEqual(self.client.post('/api/traces', json=dict(ip='example.com', request_id='x')).status_code, 400)
        response = self.client.post('/api/traces', json={}, headers={'Origin': 'https://other.example'})
        self.assertEqual(response.status_code, 403)
        self.app.config['NTWA_TRUSTED_HOSTS'] = ('trace.example',)
        self.assertEqual(self.client.get('/healthz').status_code, 400)

    def test_health_and_devices_keep_existing_contract(self):
        self.assertTrue(self.client.get('/healthz').get_json()['nexttrace_available'])
        self.app.config['NTWA_NEXTTRACE_PATH'] = '/missing/nexttrace'
        self.assertEqual(self.client.get('/healthz').status_code, 503)
        with mock.patch('ntwa.http.socket.if_nameindex', return_value=[(1, 'lo0'), (2, 'br-test0'), (3, 'bad name')]):
            self.assertEqual(self.client.get('/api/devices').get_json(), dict(devices=['lo0', 'br-test0'], count=2))

    def test_sse_reconnect_sends_latest_terminal_snapshot_without_restarting(self):
        task_id = self.create().get_json()['task_id']
        task = self.registry.tasks[task_id]
        task.aggregate.ingest(dict(ttl=1, success=True, rtt_ms=0, ip='192.0.2.1'))
        task.change('completed')
        for _ in range(2):
            response = self.client.get('/api/traces/' + task_id + '/events', buffered=True)
            self.assertEqual(response.mimetype, 'text/event-stream')
            self.assertEqual(response.headers['X-Accel-Buffering'], 'no')
            snapshot = json.loads(next(line[6:] for line in response.get_data(as_text=True).splitlines() if line.startswith('data: ')))
            self.assertEqual(snapshot['task_id'], task_id)
            self.assertEqual(snapshot['state'], 'completed')
            self.assertEqual(snapshot['rows'][0]['sent'], 1)
        self.start.assert_called_once()

    def test_retention_removes_terminal_task_and_request_id_after_five_minutes(self):
        task_id = self.create().get_json()['task_id']
        task = self.registry.tasks[task_id]
        task.change('completed')
        task.finished_at = time.monotonic() - 301
        self.assertEqual(self.client.get('/api/traces/' + task_id).status_code, 404)
        self.assertFalse(self.registry.requests)


class TaskRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.config = dict(NTWA_NEXTTRACE_PATH='/fake/nexttrace', NTWA_TRACE_IDLE_TIMEOUT_SECONDS=120, NTWA_TRACE_MAX_DURATION_SECONDS=0)

    def task(self):
        return Task('owner-one', ['192.0.2.1'], self.config)

    def test_completion_flushes_last_probe_and_stops_watchdog(self):
        task = self.task()
        output = events(dict(type='start'), dict(type='probe', record=dict(ttl=1, success=True, rtt_ms=0)), dict(type='end', end_reason='completed'))
        process = FakeProcess(output)
        with mock.patch('ntwa.tasks.subprocess.Popen', return_value=process) as popen:
            task.run()
        self.assertEqual(task.state, 'completed')
        self.assertTrue(task.done.is_set())
        self.assertEqual(task.snapshot()['rows'][0]['successCount'], 1)
        self.assertEqual(popen.call_args.args[0][-2:], ['--mtr', '--json'])
        seq = task.seq
        task.last_output_at = 0
        task.watch()
        task.change('failed', dict(message='late error'))
        self.assertEqual(task.state, 'completed')
        self.assertEqual(task.seq, seq)
        self.assertIsNone(task.error)

    def test_native_error_keeps_partial_results_and_structured_details(self):
        task = self.task()
        output = events(dict(type='start'), dict(type='probe', record=dict(ttl=2, success=True, rtt_ms=12)), dict(type='end', end_reason='error', error=dict(stage='probe', message='probe failed')))
        with mock.patch('ntwa.tasks.subprocess.Popen', return_value=FakeProcess(output, code=1)):
            task.run()
        self.assertEqual(task.state, 'failed')
        self.assertEqual(task.error['message'], 'probe failed')
        self.assertEqual(task.snapshot()['rows'][0]['sent'], 1)

    def test_empty_stdout_uses_stderr_instead_of_false_completion(self):
        task = self.task()
        with mock.patch('ntwa.tasks.subprocess.Popen', return_value=FakeProcess(stderr='unknown argument --json\n', code=2)):
            task.run()
        self.assertEqual(task.state, 'failed')
        self.assertIn('--json', task.error['message'])

    def test_invalid_event_order_fails_instead_of_aggregating_twice(self):
        task = self.task()
        output = events(dict(type='start')) + json.dumps(dict(schema_version=1, seq=1, type='probe', record=dict(ttl=1, success=True, rtt_ms=1))) + '\n'
        with mock.patch('ntwa.tasks.subprocess.Popen', return_value=FakeProcess(output)):
            task.run()
        self.assertEqual(task.state, 'failed')
        self.assertFalse(task.snapshot()['rows'])

    def test_cleanup_error_does_not_skip_terminal_state_or_other_pipe(self):
        task = self.task()
        output = events(dict(type='start'), dict(type='end', end_reason='completed'))
        process = FakeProcess(output)
        original_close = process.stdout.close
        process.stdout.close = mock.Mock(side_effect=OSError('close failed'))
        try:
            with mock.patch('ntwa.tasks.subprocess.Popen', return_value=process):
                task.run()
        finally:
            process.stdout.close = original_close
            original_close()
        self.assertTrue(task.done.is_set())
        self.assertIn(task.state, TERMINAL)
        self.assertTrue(process.stderr.closed)

    def test_thread_start_failure_does_not_keep_active_capacity(self):
        registry = Registry(dict(self.config, NTWA_MIN_START_INTERVAL_SECONDS=0, NTWA_MAX_ACTIVE_TRACES=1))
        with mock.patch.object(Task, 'start', side_effect=RuntimeError('cannot start new thread')):
            with self.assertRaises((RuntimeError, PayloadError)):
                registry.create('owner-one', 'request-one', ['192.0.2.1'])
        self.assertFalse(any(task.state not in TERMINAL for task in registry.tasks.values()))

    def test_lease_renewal_between_watch_check_and_stop_prevents_cancellation(self):
        task = self.task()
        task.process = FakeProcess()
        task.lease_at = 0
        original_stop = task.stop

        def renew_then_stop(*args, **kwargs):
            with task.condition:
                task.lease_at = time.monotonic()
            return original_stop(*args, **kwargs)

        with mock.patch.object(task.done, 'wait', side_effect=[False, True]):
            with mock.patch.object(task, 'stop', side_effect=renew_then_stop):
                task.watch()
        self.assertFalse(task.stopping.is_set())
        task.process.terminate.assert_not_called()

    def test_worker_exit_hook_reaps_real_native_child_and_rejects_new_tasks(self):
        with tempfile.TemporaryDirectory(prefix='ntwa-native-test-') as folder:
            binary = Path(folder) / 'native.py'
            binary.write_text('import json,time\nprint(json.dumps(dict(schema_version=1, seq=1, type="start")),flush=True)\ntime.sleep(3600)\n')
            config = dict(self.config, NTWA_NEXTTRACE_PATH=sys.executable, NTWA_MIN_START_INTERVAL_SECONDS=0, NTWA_MAX_ACTIVE_TRACES=1)
            registry = Registry(config)
            task = registry.create('owner-one', 'request-one', [str(binary)])
            try:
                deadline = time.monotonic() + 3
                while task.state == 'starting' and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(task.state, 'running')
                self.assertIsNone(task.process.poll())
                hook = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'gunicorn.conf.py'))['worker_exit']
                worker = types.SimpleNamespace(wsgi=types.SimpleNamespace(extensions={'traces': registry}))
                hook(None, worker)
                self.assertIsNotNone(task.process.poll())
                self.assertTrue(task.done.wait(1))
                self.assertEqual(task.state, 'cancelled')
                with self.assertRaises(PayloadError):
                    registry.create('owner-one', 'request-two', ['192.0.2.2'])
            finally:
                registry.shutdown()
                if task.process is not None and task.process.poll() is None:
                    task.process.kill()
                    task.process.wait(timeout=2)

    def test_stop_escalates_after_two_seconds_and_reaps_process(self):
        task = self.task()
        task.process = FakeProcess()
        task.process.wait.side_effect = [subprocess.TimeoutExpired('nexttrace', 2), 0]
        task.stop()
        task.process.terminate.assert_called_once()
        task.process.kill.assert_called_once()
        self.assertEqual(task.process.wait.call_args_list, [mock.call(timeout=2), mock.call()])

    def test_expired_lease_cancels_task_and_stop_is_idempotent(self):
        task = self.task()
        task.process = FakeProcess()
        task.lease_at = 0
        with mock.patch.object(task.done, 'wait', return_value=False):
            task.watch()
        self.assertTrue(task.stopping.is_set())
        task.stop()
        task.process.terminate.assert_called_once()


if __name__ == '__main__':
    unittest.main()
