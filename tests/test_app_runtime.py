import os

os.environ.setdefault("NTWA_SOCKETIO_ASYNC_MODE", "threading")

import sys
import time
import types
import unittest
from unittest import mock

import app as app_module


class FakePipe:
    def __init__(self, lines=None):
        self.lines = list(lines or [])
        self.closed = False

    def readline(self):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if not self.lines:
            return ""
        return self.lines.pop(0)

    def close(self):
        self.closed = True


class FakeStdin:
    def __init__(self):
        self.buffer = []
        self.closed = False

    def write(self, data):
        if self.closed:
            raise OSError("stdin is closed")
        self.buffer.append(data)

    def flush(self):
        if self.closed:
            raise OSError("stdin is closed")

    def close(self):
        self.closed = True


class FakePopen:
    stdout_lines = []
    stderr_lines = []
    returncode = 0
    instances = []

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.stdout = FakePipe(type(self).stdout_lines)
        self.stderr = FakePipe(type(self).stderr_lines)
        self.stdin = FakeStdin()
        self.returncode = type(self).returncode
        type(self).instances.append(self)

    @classmethod
    def configure(cls, stdout_lines=None, stderr_lines=None, returncode=0):
        cls.stdout_lines = list(stdout_lines or [])
        cls.stderr_lines = list(stderr_lines or [])
        cls.returncode = returncode
        cls.instances = []

    def wait(self, timeout=None):
        self.stdout.close()
        self.stderr.close()
        return self.returncode

    def terminate(self):
        self.stdout.close()
        self.stderr.close()

    def kill(self):
        self.returncode = -9
        self.stdout.close()
        self.stderr.close()


class AppRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.pending_packets = []
        self.original_config = {
            "NTWA_NEXTTRACE_PATH": app_module.app.config["NTWA_NEXTTRACE_PATH"],
            "NTWA_TRACE_IDLE_TIMEOUT_SECONDS": app_module.app.config["NTWA_TRACE_IDLE_TIMEOUT_SECONDS"],
            "NTWA_TRACE_MAX_DURATION_SECONDS": app_module.app.config["NTWA_TRACE_MAX_DURATION_SECONDS"],
            "NTWA_MAX_ACTIVE_TRACES": app_module.app.config["NTWA_MAX_ACTIVE_TRACES"],
            "NTWA_MIN_START_INTERVAL_SECONDS": app_module.app.config["NTWA_MIN_START_INTERVAL_SECONDS"],
            "NTWA_TRUSTED_HOSTS": app_module.app.config["NTWA_TRUSTED_HOSTS"],
        }
        with app_module.clients_lock:
            app_module.clients.clear()
            app_module.client_last_start.clear()
        app_module.app.config.update(
            NTWA_NEXTTRACE_PATH="/usr/local/bin/nexttrace",
            NTWA_TRACE_IDLE_TIMEOUT_SECONDS=120.0,
            NTWA_TRACE_MAX_DURATION_SECONDS=0.0,
            NTWA_MAX_ACTIVE_TRACES=64,
            NTWA_MIN_START_INTERVAL_SECONDS=0.0,
            NTWA_TRUSTED_HOSTS=(),
        )
        self.flask_client = app_module.app.test_client()
        self.socket_client = app_module.socketio.test_client(
            app_module.app, flask_test_client=self.flask_client
        )

    def tearDown(self):
        if self.socket_client.is_connected():
            self.socket_client.disconnect()
        app_module.app.config.update(**self.original_config)
        with app_module.clients_lock:
            app_module.clients.clear()
            app_module.client_last_start.clear()

    def _get_event(self, event_name, timeout=1.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.pending_packets.extend(self.socket_client.get_received())
            for index, packet in enumerate(self.pending_packets):
                if packet["name"] == event_name:
                    return self.pending_packets.pop(index)
            time.sleep(0.01)
        self.fail(f"Timed out waiting for {event_name}")

    def test_parse_client_payload_accepts_url_and_empty_extra(self):
        target, extra = app_module.parse_client_payload(
            {"ip": "https://example.com:443/path", "extra": ""}
        )

        self.assertEqual(target, "example.com")
        self.assertEqual(extra, {})

    def test_parse_client_payload_accepts_ipv6_literal(self):
        target, extra = app_module.parse_client_payload({"ip": "2001:db8::1", "extra": {}})

        self.assertEqual(target, "2001:db8::1")
        self.assertEqual(extra, {})

    def test_build_trace_params_maps_supported_fields(self):
        params = app_module.build_trace_params(
            "example.com",
            {
                "ipVersion": "ipv6",
                "protocol": "tcp",
                "language": "en",
                "intervalSeconds": "0.04",
                "packetSize": "128",
                "maxHop": "8",
                "minHop": "2",
                "port": "443",
                "device": "en0",
                "dataProvider": "LeoMoeAPI",
            },
        )

        self.assertEqual(
            params,
            [
                "example.com",
                "--ipv6",
                "--tcp",
                "--language",
                "en",
                "--ttl-time",
                "40",
                "--psize",
                "128",
                "--max-hops",
                "8",
                "--first",
                "2",
                "--port",
                "443",
                "--dev",
                "en0",
                "--data-provider",
                "LeoMoeAPI",
            ],
        )

    def test_build_trace_params_rejects_invalid_device(self):
        with self.assertRaises(app_module.PayloadError) as ctx:
            app_module.build_trace_params("example.com", {"device": "en0;rm -rf /"})

        self.assertEqual(ctx.exception.code, "invalid_payload")

    def test_healthz_reports_ok_when_binary_exists(self):
        app_module.app.config["NTWA_NEXTTRACE_PATH"] = sys.executable

        response = self.flask_client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["nexttrace_available"])

    def test_healthz_reports_degraded_when_binary_missing(self):
        app_module.app.config["NTWA_NEXTTRACE_PATH"] = "/definitely/missing/nexttrace"

        response = self.flask_client.get("/healthz")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "degraded")

    def test_start_nexttrace_invalid_json_emits_structured_error(self):
        self.socket_client.emit("start_nexttrace", "{bad json")

        packet = self._get_event("nexttrace_error")
        self.assertEqual(packet["args"][0]["code"], "invalid_payload")

    def test_start_nexttrace_missing_ip_emits_structured_error(self):
        self.socket_client.emit("start_nexttrace", {"extra": {}})

        packet = self._get_event("nexttrace_error")
        self.assertEqual(packet["args"][0]["code"], "invalid_payload")

    def test_start_nexttrace_rate_limit_emits_retry_after(self):
        with mock.patch.object(app_module.TraceTask, "start", autospec=True, return_value=None):
            self.socket_client.emit("start_nexttrace", {"ip": "1.1.1.1", "extra": {}})
            app_module.app.config["NTWA_MIN_START_INTERVAL_SECONDS"] = 60.0
            self.socket_client.emit("start_nexttrace", {"ip": "1.1.1.1", "extra": {}})

        packet = self._get_event("nexttrace_error")
        self.assertEqual(packet["args"][0]["code"], "trace_rate_limited")
        self.assertIn("retry_after_seconds", packet["args"][0])

    def test_start_nexttrace_capacity_limit_emits_error(self):
        app_module.app.config["NTWA_MAX_ACTIVE_TRACES"] = 1
        with app_module.clients_lock:
            app_module.clients["another-sid"] = object()

        self.socket_client.emit("start_nexttrace", {"ip": "1.1.1.1", "extra": {}})

        packet = self._get_event("nexttrace_error")
        self.assertEqual(packet["args"][0]["code"], "trace_capacity_exceeded")

    def test_start_nexttrace_emits_mtr_raw_and_complete(self):
        FakePopen.configure(
            stdout_lines=[
                "1|1.1.1.1|one.one.one.one|10.50|13335|Australia|Queensland|South Brisbane||Cloudflare|0|0\n",
                "2|*||||||||||\n",
            ]
        )

        with mock.patch.object(app_module.subprocess, "Popen", FakePopen):
            self.socket_client.emit(
                "start_nexttrace",
                {
                    "ip": "1.1.1.1",
                    "extra": {"ipVersion": "ipv4", "protocol": "udp", "intervalSeconds": "0.04"},
                },
            )
            raw_packet = self._get_event("mtr_raw")
            complete_packet = self._get_event("nexttrace_complete")

        self.assertEqual(raw_packet["args"][0]["ttl"], 1)
        self.assertEqual(raw_packet["args"][0]["ip"], "1.1.1.1")
        self.assertEqual(complete_packet["name"], "nexttrace_complete")
        self.assertTrue(FakePopen.instances)
        self.assertIn("--raw", FakePopen.instances[0].cmd)
        self.assertNotIn("-q", FakePopen.instances[0].cmd)
        self.assertNotIn("--send-time", FakePopen.instances[0].cmd)
        self.assertNotIn("--mtr", FakePopen.instances[0].cmd)
        self.assertNotIn("--map", FakePopen.instances[0].cmd)

    def test_start_nexttrace_emits_error_for_stdout_usage_failure(self):
        FakePopen.configure(
            stdout_lines=[
                "usage: ntr [TARGET]\n",
            ]
        )

        with mock.patch.object(app_module.subprocess, "Popen", FakePopen):
            self.socket_client.emit("start_nexttrace", {"ip": "1.1.1.1", "extra": {}})
            error_packet = self._get_event("nexttrace_error")
            complete_packet = self._get_event("nexttrace_complete")

        self.assertEqual(error_packet["args"][0]["code"], "nexttrace_invalid_args")
        self.assertEqual(error_packet["args"][0]["message"], "usage: ntr [TARGET]")
        self.assertEqual(complete_packet["name"], "nexttrace_complete")

    def test_stop_nexttrace_calls_request_stop(self):
        with mock.patch.object(app_module.TraceTask, "start", autospec=True, return_value=None):
            self.socket_client.emit("start_nexttrace", {"ip": "1.1.1.1", "extra": {}})
        sid, task = next(iter(app_module.clients.items()))
        task.request_stop = mock.Mock()

        self.socket_client.emit("stop_nexttrace")

        task.request_stop.assert_called_once_with()
        self.assertEqual(sid, next(iter(app_module.clients)))

    def test_nexttrace_options_choice_without_running_task_emits_error(self):
        self.socket_client.emit("nexttrace_options_choice", {"choice": 1})

        packet = self._get_event("nexttrace_error")
        self.assertEqual(packet["args"][0]["code"], "trace_not_running")

    def test_nexttrace_options_choice_writes_to_task_stdin(self):
        with mock.patch.object(app_module.TraceTask, "start", autospec=True, return_value=None):
            self.socket_client.emit("start_nexttrace", {"ip": "1.1.1.1", "extra": {}})

        _, task = next(iter(app_module.clients.items()))
        task.process = types.SimpleNamespace(stdin=FakeStdin())

        self.socket_client.emit("nexttrace_options_choice", {"choice": 2})

        self.assertEqual(task.process.stdin.buffer, ["2\n"])

    def test_emit_complete_is_idempotent(self):
        with mock.patch.object(app_module.socketio, "emit") as emit_mock:
            task = app_module.TraceTask("sid-1", ["1.1.1.1"], "/usr/local/bin/nexttrace")
            with app_module.clients_lock:
                app_module.clients["sid-1"] = task
            task.emit_complete()
            task.emit_complete()

        self.assertEqual(
            emit_mock.call_args_list,
            [mock.call("nexttrace_complete", room="sid-1")],
        )


if __name__ == "__main__":
    unittest.main()
