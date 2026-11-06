import os
os.environ.setdefault('NTWA_ASYNC_MODE', 'threading')

import json
import io
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from flask import Flask

import app as app_module
from ntwa.config import PayloadError
from ntwa.http import register_routes
from ntwa.public import PublicPolicy, configure_public
from ntwa.tasks import Task


class PublicModeTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(app_module.app.config)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY='test-public-secret-with-at-least-32-characters',
            SESSION_COOKIE_SECURE=False,
            NTWA_PUBLIC_MODE=True,
            NTWA_TRUSTED_HOSTS=('localhost',),
            NTWA_NEXTTRACE_PATH=sys.executable,
            NTWA_MAX_ACTIVE_TRACES=4,
            NTWA_TRACE_MAX_DURATION_SECONDS=120,
            NTWA_MIN_START_INTERVAL_SECONDS=2,
            MAX_CONTENT_LENGTH=8192,
        )
        register_routes(self.app)
        self.registry = self.app.extensions['traces']
        self.client = self.app.test_client()
        self.start = mock.patch.object(Task, 'start').start()
        self.local = mock.patch('ntwa.public.is_local_address', return_value=False).start()

    def tearDown(self):
        self.registry.shutdown()
        mock.patch.stopall()

    def create(self, ip='8.8.8.8', extra=None, request_id='public-one', client=None,
               source='198.51.100.10', headers=None):
        return (client or self.client).post(
            '/api/traces',
            json=dict(ip=ip, extra=extra or {}, request_id=request_id),
            environ_overrides={'REMOTE_ADDR': source},
            headers=headers or {},
        )

    def test_public_creation_pins_safe_defaults_and_preserves_idempotency(self):
        # The unchanged page sends the port field even when ICMP is selected.
        settings = dict(ipVersion='all', protocol='icmp', language='cn', intervalSeconds='1.000',
                        packetSize='52', maxHop='30', minHop='1', port='80', device='',
                        dataProvider='', localResolve=True)
        first = self.create(extra=settings)
        self.assertEqual(first.status_code, 201, first.get_json())
        second = self.create(extra=settings)
        self.assertEqual(second.status_code, 201, second.get_json())
        self.assertEqual(first.get_json()['task_id'], second.get_json()['task_id'])
        self.start.assert_called_once()
        task = self.registry.tasks[first.get_json()['task_id']]
        self.assertEqual(task.params[task.params.index('--ttl-time') + 1], '1000')
        self.assertEqual(task.params[task.params.index('--max-hops') + 1], '30')
        self.assertLessEqual(int(task.params[task.params.index('--psize') + 1]), 512)
        self.assertNotIn('--port', task.params)
        self.assertEqual(self.app.config['NTWA_TRACE_MAX_DURATION_SECONDS'], 120)

    def test_final_target_policy_rejects_internal_special_and_mapped_addresses(self):
        for address in ('127.0.0.1', '10.20.30.40', '169.254.169.254', '100.64.0.1',
                        '224.0.0.1', '::1', 'fd00::1', 'fe80::1%eth0',
                        '::ffff:10.20.30.40', '64:ff9b::a14:1e28', '2002:0a14:1e28::1'):
            with self.subTest(address=address):
                response = self.create(ip=address)
                self.assertIn(response.status_code, (400, 403), response.get_json())
        self.start.assert_not_called()
        self.assertFalse(self.registry.tasks)

    def test_local_public_address_is_rejected_before_process_creation(self):
        self.local.return_value = True
        response = self.create()
        self.assertIn(response.status_code, (400, 403), response.get_json())
        self.start.assert_not_called()

    def test_operator_denied_public_networks_are_enforced(self):
        policy = PublicPolicy(dict(self.app.config, NTWA_PUBLIC_DENY_CIDRS='8.8.8.0/24,2606:4700::/32'))
        for address in ('8.8.8.8', '2606:4700:4700::1111'):
            with self.subTest(address=address):
                with self.assertRaises(PayloadError) as rejected:
                    policy.target(address)
                self.assertEqual(rejected.exception.code, 'target_not_allowed')

    def test_dns_answers_cannot_bypass_destination_policy(self):
        replies = [(socket.AF_INET, socket.SOCK_DGRAM, 17, '', ('10.0.0.8', 0))]
        with mock.patch('ntwa.http.socket.getaddrinfo', return_value=replies):
            response = self.client.post('/api/traces/resolve', json=dict(target='internal.example'),
                                        environ_overrides={'REMOTE_ADDR': '198.51.100.10'})
        self.assertIn(response.status_code, (400, 403), response.get_json())
        self.start.assert_not_called()
        self.assertFalse(self.registry.tasks)

    def test_public_dns_selection_still_returns_candidates_without_starting(self):
        replies = [(socket.AF_INET, socket.SOCK_DGRAM, 17, '', (address, 0))
                   for address in ('8.8.8.8', '1.1.1.1', '8.8.8.8')]
        with mock.patch('ntwa.http.socket.getaddrinfo', return_value=replies):
            response = self.client.post('/api/traces/resolve', json=dict(target='public.example'),
                                        environ_overrides={'REMOTE_ADDR': '198.51.100.10'})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()['addresses'], ['8.8.8.8', '1.1.1.1'])
        self.start.assert_not_called()

    def test_malformed_address_version_is_rejected_without_dns_or_process(self):
        with mock.patch('ntwa.http.socket.getaddrinfo') as resolve:
            response = self.client.post('/api/traces/resolve',
                                        json=dict(target='public.example', ipVersion=[]),
                                        environ_overrides={'REMOTE_ADDR': '198.51.100.10'})
        self.assertEqual(response.status_code, 400, response.get_json())
        resolve.assert_not_called()
        self.start.assert_not_called()

    def test_saved_settings_cannot_exceed_public_probe_budget(self):
        for extra in ({'intervalSeconds': '0.040'}, {'maxHop': 31}, {'packetSize': 513},
                      {'minHop': 20, 'maxHop': 10}, {'device': 'lo'},
                      {'protocol': 'tcp', 'port': 22}, {'protocol': 'udp', 'port': 53}):
            with self.subTest(extra=extra):
                response = self.create(extra=extra)
                self.assertIn(response.status_code, (400, 403), response.get_json())
        self.start.assert_not_called()

    def test_new_cookie_and_spoofed_forwarding_headers_do_not_bypass_ip_quota(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.get_json())
        attacker = self.app.test_client()
        response = self.create(ip='1.1.1.1', client=attacker, request_id='public-two',
                               headers={'X-Forwarded-For': '203.0.113.20', 'X-Real-IP': '203.0.113.20'})
        self.assertEqual(response.status_code, 429, response.get_json())
        self.start.assert_called_once()

    def test_ipv6_privacy_addresses_share_prefix_quota(self):
        first = self.create(source='2001:4860:abcd:1::1')
        self.assertEqual(first.status_code, 201, first.get_json())
        other = self.app.test_client()
        response = self.create(ip='1.1.1.1', client=other, request_id='public-two',
                               source='2001:4860:abcd:1::dead')
        self.assertEqual(response.status_code, 429, response.get_json())
        self.start.assert_called_once()

    def test_trusted_proxy_real_ip_keeps_distinct_visitors_separate(self):
        first = self.create(source='127.0.0.1', headers={'X-Real-IP': '198.51.100.10'})
        self.assertEqual(first.status_code, 201, first.get_json())
        other = self.app.test_client()
        second = self.create(ip='1.1.1.1', client=other, request_id='public-two', source='127.0.0.1',
                             headers={'X-Real-IP': '203.0.113.20'})
        self.assertEqual(second.status_code, 201, second.get_json())
        self.assertEqual(self.start.call_count, 2)

    def test_public_https_rejection_has_message_and_trusted_termination_is_accepted(self):
        self.app.config['SESSION_COOKIE_SECURE'] = True
        rejected = self.create()
        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(rejected.get_json()['code'], 'https_required')
        self.assertTrue(rejected.get_json()['message'])
        self.start.assert_not_called()
        accepted = self.create(source='127.0.0.1', headers={
            'X-Real-IP': '198.51.100.10', 'X-Forwarded-Proto': 'https', 'Origin': 'https://localhost',
        })
        self.assertEqual(accepted.status_code, 201, accepted.get_json())
        self.start.assert_called_once()

    def test_session_quota_survives_source_address_change(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.get_json())
        # The creation cooldown is independent of the active-session quota.
        self.registry.last_start.clear()
        response = self.create(ip='1.1.1.1', request_id='public-two', source='203.0.113.20')
        self.assertEqual(response.status_code, 429, response.get_json())
        self.start.assert_called_once()

    def test_public_task_ownership_still_protects_all_controls(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.get_json())
        path = '/api/traces/' + first.get_json()['task_id']
        other = self.app.test_client()
        for suffix, method in [('', 'get'), ('/events', 'get'), ('/stop', 'post'), ('/lease', 'post')]:
            with self.subTest(suffix=suffix):
                args = dict(environ_overrides={'REMOTE_ADDR': '203.0.113.20'})
                if method == 'post':
                    args['json'] = {}
                response = getattr(other, method)(path + suffix, **args)
                self.assertEqual(response.status_code, 404, response.get_json())

    def test_sse_limit_releases_reservation_on_disconnect_and_reconnects_same_task(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.get_json())
        path = '/api/traces/' + first.get_json()['task_id'] + '/events'
        streams = []
        try:
            for _ in range(2):
                stream = self.client.get(path, buffered=False,
                                         environ_overrides={'REMOTE_ADDR': '198.51.100.10'})
                streams.append(stream)
                self.assertEqual(stream.status_code, 200)
                snapshot = json.loads(next(line[6:] for line in next(iter(stream.response)).decode().splitlines()
                                           if line.startswith('data: ')))
                self.assertEqual(snapshot['task_id'], first.get_json()['task_id'])
            reserved = self.registry.limits.connections.copy()
            blocked = self.client.get(path, environ_overrides={'REMOTE_ADDR': '198.51.100.10'})
            self.assertEqual(blocked.status_code, 429, blocked.get_json())
            self.assertEqual(self.registry.limits.connections, reserved)
            streams.pop().close()
            replacement = self.client.get(path, buffered=False,
                                           environ_overrides={'REMOTE_ADDR': '198.51.100.10'})
            streams.append(replacement)
            self.assertEqual(replacement.status_code, 200)
            self.start.assert_called_once()
        finally:
            while streams:
                streams.pop().close()
        self.assertFalse(self.registry.limits.connections)

    def test_api_rate_limit_survives_new_cookie_and_returns_retry_after(self):
        source = dict(REMOTE_ADDR='198.51.100.10')
        with mock.patch('ntwa.limits.time.monotonic', return_value=10000):
            for _ in range(30):
                self.assertEqual(self.client.get('/api/devices', environ_overrides=source).status_code, 200)
            other = self.app.test_client()
            response = other.get('/api/devices', environ_overrides=source)
        self.assertEqual(response.status_code, 429, response.get_json())
        self.assertEqual(response.get_json()['code'], 'trace_rate_limited')
        self.assertGreaterEqual(int(response.headers['Retry-After']), 1)
        self.start.assert_not_called()

    def test_retention_count_cap_prunes_dedupe_records_without_evicting_active_tasks(self):
        active = Task('active-owner', ['1.1.1.1'], self.app.config)
        self.registry.tasks[active.id] = active
        self.registry.requests[(active.owner, 'active-request')] = active
        oldest = None
        base = time.monotonic() - 1
        for index in range(257):
            task = Task('owner-' + str(index), ['8.8.8.8'], self.app.config)
            task.change('completed')
            task.finished_at = base + index / 1000
            self.registry.tasks[task.id] = task
            self.registry.requests[(task.owner, 'finished-request')] = task
            if oldest is None:
                oldest = task
        self.registry.prune()
        self.assertEqual(len(self.registry.tasks), 257)
        self.assertEqual(len(self.registry.requests), 257)
        self.assertIs(self.registry.tasks[active.id], active)
        self.assertIs(self.registry.requests[(active.owner, 'active-request')], active)
        self.assertNotIn(oldest.id, self.registry.tasks)
        self.assertNotIn((oldest.owner, 'finished-request'), self.registry.requests)
        self.start.assert_not_called()

    def test_public_responses_hide_host_details_and_json_size_is_bounded(self):
        health = self.client.get('/healthz')
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json(), {'status': 'ok'})
        devices = self.client.get('/api/devices')
        self.assertEqual(devices.get_json(), dict(devices=[], count=0))
        response = self.client.post('/api/traces', data=json.dumps(dict(padding='x' * 8192)),
                                    content_type='application/json',
                                    environ_overrides={'REMOTE_ADDR': '198.51.100.10'})
        self.assertEqual(response.status_code, 413)
        self.start.assert_not_called()

    def test_snapshot_bounds_untrusted_metadata_without_filtering_private_hops(self):
        first = self.create()
        self.assertEqual(first.status_code, 201, first.get_json())
        task = self.registry.tasks[first.get_json()['task_id']]
        task.aggregate.ingest(dict(ttl=1, success=True, rtt_ms=0, ip='10.0.0.1',
                                   host='untrusted-ptr-' * 200, owner='x' * 2000))
        task.change('failed', dict(code='nexttrace_error', message='internal diagnostic path /private/file'))
        snapshot = self.client.get('/api/traces/' + task.id,
                                   environ_overrides={'REMOTE_ADDR': '198.51.100.10'}).get_json()
        self.assertEqual(snapshot['rows'][0]['ip'], '10.0.0.1')
        self.assertLessEqual(len(snapshot['rows'][0]['ptr']), 512)
        self.assertLessEqual(len(snapshot['rows'][0]['owner']), 512)
        self.assertEqual(snapshot['rows'][0]['successCount'], 1)
        self.assertNotIn('/private/file', snapshot['error']['message'])

    def test_public_startup_requires_explicit_secret_and_hosts_and_caps_unsafe_defaults(self):
        config = dict(self.app.config, NTWA_MAX_ACTIVE_TRACES=64,
                      NTWA_TRACE_MAX_DURATION_SECONDS=0, NTWA_MIN_START_INTERVAL_SECONDS=0)
        with mock.patch.dict(os.environ, {'NTWA_PUBLIC_MODE': 'true', 'NTWA_SECRET_KEY': '',
                                          'NTWA_SESSION_COOKIE_SECURE': 'true'}):
            with self.assertRaises(RuntimeError):
                configure_public(config)
        with mock.patch.dict(os.environ, {'NTWA_PUBLIC_MODE': 'true',
                                          'NTWA_SECRET_KEY': 'test-public-secret-with-at-least-32-characters',
                                          'NTWA_SESSION_COOKIE_SECURE': 'true'}):
            with self.assertRaises(RuntimeError):
                configure_public(dict(config, NTWA_TRUSTED_HOSTS=()))
            configure_public(config)
        self.assertEqual(config['NTWA_MAX_ACTIVE_TRACES'], 4)
        self.assertEqual(config['NTWA_TRACE_MAX_DURATION_SECONDS'], 120)
        self.assertGreaterEqual(config['NTWA_MIN_START_INTERVAL_SECONDS'], 2)
        self.assertTrue(config['SESSION_COOKIE_SECURE'])

    def test_oversized_native_event_reaps_child_and_child_env_excludes_service_secrets(self):
        process = types.SimpleNamespace(
            stdout=io.StringIO('x' * 65537 + '\n'), stderr=io.StringIO(''),
            poll=mock.Mock(side_effect=[None, 0]), terminate=mock.Mock(),
            wait=mock.Mock(return_value=0), kill=mock.Mock(),
        )
        task = Task('public-owner', ['8.8.8.8'], self.app.config)
        with mock.patch.dict(os.environ, {'NTWA_SECRET_KEY': 'isolated-test-service-secret',
                                          'UNRELATED_SERVICE_TOKEN': 'isolated-test-token',
                                          'NEXTTRACE_TOKEN': 'isolated-test-provider-token'}):
            with mock.patch('ntwa.tasks.subprocess.Popen', return_value=process) as popen:
                task.run()
        child_env = popen.call_args.kwargs['env']
        self.assertNotIn('NTWA_SECRET_KEY', child_env)
        self.assertNotIn('UNRELATED_SERVICE_TOKEN', child_env)
        self.assertEqual(child_env['NEXTTRACE_TOKEN'], 'isolated-test-provider-token')
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=2)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertTrue(task.done.is_set())
        self.assertEqual(task.state, 'failed')
        self.assertIn('size limit', task.error['message'])
        self.assertEqual(task.snapshot()['error'], dict(code='nexttrace_error', message='探测失败'))

    def test_native_probe_outside_configured_ttl_range_cannot_expand_snapshot(self):
        records = [dict(type='start'),
                   dict(type='probe', record=dict(ttl=1, success=True, rtt_ms=0, ip='10.0.0.1')),
                   dict(type='probe', record=dict(ttl=31, success=True, rtt_ms=1, ip='8.8.8.8'))]
        output = ''.join(json.dumps(dict(schema_version=1, seq=index, **item)) + '\n'
                         for index, item in enumerate(records, 1))
        process = types.SimpleNamespace(stdout=io.StringIO(output), stderr=io.StringIO(''),
                                        poll=mock.Mock(return_value=0))
        task = Task('public-owner', self.registry.public.prepare('8.8.8.8', {}), self.app.config)
        with mock.patch('ntwa.tasks.subprocess.Popen', return_value=process):
            task.run()
        self.assertEqual(task.state, 'failed')
        self.assertIn('TTL exceeds', task.error['message'])
        self.assertEqual([row['ttl'] for row in task.snapshot()['rows']], [1])
        self.assertEqual(task.snapshot()['rows'][0]['ip'], '10.0.0.1')
        self.assertTrue(task.done.is_set())

    def test_max_duration_stops_and_reaps_a_real_child_even_with_fresh_lease(self):
        with tempfile.TemporaryDirectory(prefix='ntwa-public-duration-') as directory:
            native = Path(directory) / 'native.py'
            native.write_text('import json,time\nprint(json.dumps(dict(schema_version=1,seq=1,type="start")),flush=True)\ntime.sleep(3600)\n')
            task = Task('public-owner', [str(native)], self.app.config)
            runner = threading.Thread(target=task.run, daemon=True)
            runner.start()
            try:
                deadline = time.monotonic() + 3
                while task.state == 'starting' and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(task.state, 'running')
                self.assertIsNone(task.process.poll())
                # Advance the task's age, keeping its lease fresh: duration is an independent bound.
                task.created_at = time.monotonic() - 121
                task.lease_at = time.monotonic()
                with mock.patch.object(task.done, 'wait', return_value=False):
                    task.watch()
                runner.join(timeout=3)
                self.assertFalse(runner.is_alive())
                self.assertIsNotNone(task.process.poll())
                self.assertTrue(task.done.is_set())
                self.assertEqual(task.state, 'failed')
                self.assertEqual(task.error['code'], 'trace_max_duration_reached')
            finally:
                if task.process is not None and task.process.poll() is None:
                    task.process.kill()
                    task.process.wait(timeout=2)
                runner.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
