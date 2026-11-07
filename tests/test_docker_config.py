import contextlib
import importlib.util
import io
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('docker_configure', ROOT / 'docker' / 'configure.py')
configure = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = configure
SPEC.loader.exec_module(configure)


class DockerConfigTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ntwa-config-test-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.cert = self.directory / 'certificate.pem'
        self.key = self.directory / 'private-key.pem'
        self.password = self.directory / 'password'
        for path in (self.cert, self.key, self.password):
            path.write_text('test fixture\n')
        self.tls = ['--tls-cert', str(self.cert), '--tls-key', str(self.key)]

    def parse(self, *arguments, environ=None):
        return configure.parse_config(list(arguments), {} if environ is None else environ)

    def test_legacy_listeners_and_default_remain_supported(self):
        cases = (
            ((), ['0.0.0.0:30080', '[::]:30080']),
            (('30081',), ['0.0.0.0:30081', '[::]:30081']),
            (('127.0.0.1:30082',), ['127.0.0.1:30082']),
            (('[::1]:30083',), ['[::1]:30083']),
            (('localhost:30084',), ['127.0.0.1:30084']),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                config = self.parse(*arguments)
                self.assertEqual(config.http_listens, expected)
                self.assertEqual(config.https_listens, [])
                self.assertEqual(config.base_path, '/')

    def test_cli_lists_replace_environment_and_duplicates_are_removed(self):
        config = self.parse(
            '--listen', '127.0.0.1:31000', '--listen', 'localhost:31000',
            '--listen', '[::1]:31000', '--server-name', 'trace.example.com',
            environ={'NTWA_LISTEN': '32000', 'NTWA_SERVER_NAME': 'old.example.com'},
        )
        self.assertEqual(config.http_listens, ['127.0.0.1:31000', '[::1]:31000'])
        self.assertEqual(config.server_names, ['trace.example.com'])
        self.assertEqual(config.trusted_hosts, ['trace.example.com'])

    def test_environment_supports_comma_lists_and_existing_application_settings(self):
        environment = {
            'NTWA_LISTEN': '127.0.0.1:31000,[::1]:31000',
            'NTWA_SERVER_NAME': 'one.example.com,two.example.com',
            'NTWA_TRUSTED_HOSTS': 'other.example.com',
            'NTWA_TRUSTED_PROXIES': '192.0.2.1,2001:db8::/64',
            'NTWA_SECRET_KEY': 'unchanged-secret',
            'NTWA_PUBLIC_DEVICE': 'eth0',
        }
        config = self.parse(environ=environment)
        self.assertEqual(config.http_listens, ['127.0.0.1:31000', '[::1]:31000'])
        self.assertEqual(config.server_names, ['one.example.com', 'two.example.com'])
        self.assertEqual(config.trusted_hosts, ['other.example.com'])
        forwarded = config.environment(environment)
        self.assertEqual(forwarded['NTWA_SECRET_KEY'], 'unchanged-secret')
        self.assertEqual(forwarded['NTWA_PUBLIC_DEVICE'], 'eth0')
        self.assertEqual(forwarded['NTWA_TRUSTED_PROXIES'], '192.0.2.1/32,2001:db8::/64')

    def test_scalar_and_public_mode_flags_override_environment(self):
        config = self.parse(
            '--base-path', '/tools/trace', '--no-public-mode',
            '--trusted-hosts', 'trace.example.com', '--trusted-proxies', '127.0.0.1',
            environ={'NTWA_BASE_PATH': '/old/', 'NTWA_PUBLIC_MODE': 'true',
                     'NTWA_TRUSTED_HOSTS': 'old.example.com', 'NTWA_TRUSTED_PROXIES': '192.0.2.1'},
        )
        self.assertEqual(config.base_path, '/tools/trace/')
        self.assertFalse(config.public_mode)
        forwarded = config.environment({})
        self.assertEqual(forwarded['NTWA_PUBLIC_MODE'], 'false')
        self.assertEqual(forwarded['NTWA_TRUSTED_HOSTS'], 'trace.example.com')
        self.assertEqual(forwarded['NTWA_TRUSTED_PROXIES'], '127.0.0.1/32')
        self.assertTrue(self.parse('--public-mode').public_mode)

    def test_legacy_listener_conflicts_with_named_listener(self):
        with self.assertRaises(ValueError):
            self.parse('30080', '--listen', '30081')

    def test_unknown_options_and_missing_values_fail(self):
        for arguments in (['--unknown'], ['--listen'], ['--lis', '30080'], ['30080', '30081']):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.parse(*arguments)

    def test_conflicting_listeners_and_app_upstream_are_rejected(self):
        for arguments in (
            ['--listen', '30080', '--listen', '127.0.0.1:30080'],
            ['--listen', '127.0.0.1:35000'],
            ['--listen', '35000'],
            [*self.tls, '--https-listen', '30080'],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                self.parse(*arguments)

    def test_tls_requires_readable_pair_and_has_default_or_explicit_listeners(self):
        config = self.parse(*self.tls)
        self.assertEqual(config.https_listens, ['0.0.0.0:30443', '[::]:30443'])
        config = self.parse(*self.tls, '--https-listen', '[::1]:31443')
        self.assertEqual(config.https_listens, ['[::1]:31443'])
        for arguments in (
            ['--tls-cert', str(self.cert)],
            ['--tls-key', str(self.key)],
            ['--https-listen', '31443'],
            ['--tls-cert', str(self.directory / 'missing'), '--tls-key', str(self.key)],
            ['--tls-cert', str(self.directory), '--tls-key', str(self.key)],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                self.parse(*arguments)

    def test_redirect_accepts_only_https_origin_with_tls(self):
        origin = 'https://trace.example.com:31443'
        self.assertEqual(self.parse(*self.tls, '--redirect-http-to', origin).redirect_http_to, origin)
        with self.assertRaises(ValueError):
            self.parse('--redirect-http-to', origin)
        for invalid in ('http://trace.example.com', 'https://user:pass@trace.example.com',
                        'https://trace.example.com/tools/', 'https://trace.example.com?next=1',
                        'https://trace.example.com#fragment'):
            with self.subTest(origin=invalid), self.assertRaises(ValueError):
                self.parse(*self.tls, '--redirect-http-to', invalid)

    def test_authentication_requires_username_and_password_file_together(self):
        config = self.parse('--auth-user', 'viewer', '--auth-password-file', str(self.password))
        self.assertEqual(config.auth_user, 'viewer')
        self.assertEqual(config.auth_password_file, str(self.password.resolve()))
        for arguments in (
            ['--auth-user', 'viewer'],
            ['--auth-password-file', str(self.password)],
            ['--auth-user', 'viewer', '--auth-password-file', str(self.directory / 'missing')],
            ['--auth-user', 'bad:user', '--auth-password-file', str(self.password)],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                self.parse(*arguments)

    @unittest.skipUnless(shutil.which('htpasswd'), 'htpasswd is not installed')
    def test_password_hash_is_generated_via_stdin_and_stored_privately(self):
        password = 'private test password'
        self.password.write_text(password + '\n')
        config = self.parse('--auth-user', 'viewer', '--auth-password-file', str(self.password))
        auth_path = self.directory / 'htpasswd'
        with mock.patch.object(configure, 'AUTH_PATH', str(auth_path)):
            with mock.patch.object(configure.subprocess, 'run', wraps=subprocess.run) as run:
                configure.write_auth(config)
        command = run.call_args.args[0]
        self.assertNotIn(password, ' '.join(command))
        self.assertEqual(run.call_args.kwargs['input'], password + '\n')
        self.assertEqual(stat.S_IMODE(auth_path.stat().st_mode), 0o600)
        self.assertNotIn(password, auth_path.read_text())
        self.assertRegex(auth_path.read_text(), r'^viewer:\$2[aby]\$')
        verified = subprocess.run(['htpasswd', '-vi', str(auth_path), 'viewer'],
                                  input=password + '\n', text=True, capture_output=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_invalid_password_is_rejected_before_running_hash_tool(self):
        self.password.write_text('first line\nsecond line\n')
        config = self.parse('--auth-user', 'viewer', '--auth-password-file', str(self.password))
        with mock.patch.object(configure.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                configure.write_auth(config)
        run.assert_not_called()

    def test_invalid_or_injected_configuration_is_rejected(self):
        for option, value in (
            ('--listen', '0'), ('--listen', '65536'), ('--listen', 'example.com:30080'),
            ('--listen', '30080; include /tmp/other;'),
            ('--server-name', 'trace.example.com; root /tmp;'),
            ('--base-path', '/trace/../admin'), ('--base-path', '/trace?x=1'),
            ('--base-path', '/trace/"; return 200;'),
            ('--trusted-hosts', 'trace.example.com\nother'),
            ('--trusted-proxies', 'not-a-network'),
        ):
            with self.subTest(option=option, value=value), self.assertRaises(ValueError):
                self.parse(option, value)

    def test_scoped_ipv6_cannot_inject_nginx_directives(self):
        for zone in ('eth0;return 200;', 'eth0\nreturn 200;'):
            address = 'fe80::1%' + zone
            for option, value in (
                ('--listen', '[' + address + ']:30080'),
                ('--server-name', address),
                ('--trusted-hosts', address),
                ('--trusted-proxies', address + '/128'),
            ):
                with self.subTest(option=option, zone=zone), self.assertRaises(ValueError):
                    self.parse(option, value)

    def test_tls_paths_reject_variables_and_controls_before_and_after_resolution(self):
        for name in ('$ssl_server_name.pem', 'certificate\n.pem'):
            target = self.directory / name
            target.write_text('test fixture\n')
            link = self.directory / 'certificate-link.pem'
            link.symlink_to(target)
            for path in (target, link):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'Invalid TLS certificate path'):
                    self.parse('--tls-cert', str(path), '--tls-key', str(self.key))
            link.unlink()

    def test_public_check_requires_secret_and_hosts_before_any_output_or_process(self):
        for environment, hosts in (({}, ['--server-name', 'trace.example.com']),
                                   ({'NTWA_SECRET_KEY': 'too-short'}, ['--server-name', 'trace.example.com']),
                                   ({'NTWA_SECRET_KEY': 's' * 32}, [])):
            with self.subTest(environment=environment, hosts=hosts):
                with mock.patch.dict(configure.os.environ, environment, clear=True), \
                        mock.patch.object(configure.sys, 'argv', ['configure.py', '--public-mode', '--check-config', *hosts]), \
                        mock.patch.object(configure, 'write_auth') as write_auth, \
                        mock.patch.object(configure.Path, 'write_text') as write_text, \
                        mock.patch.object(configure.subprocess, 'run') as run, \
                        mock.patch.object(configure.os, 'execvpe') as execute:
                    with self.assertRaisesRegex(SystemExit, 'Public mode requires'):
                        configure.main()
                    write_auth.assert_not_called()
                    write_text.assert_not_called()
                    run.assert_not_called()
                    execute.assert_not_called()

    def test_rendered_subpath_keeps_authentication_limits_and_private_health(self):
        config = self.parse(
            *self.tls, '--server-name', 'trace.example.com', '--base-path', '/tools/trace',
            '--auth-user', 'viewer', '--auth-password-file', str(self.password), '--public-mode',
            '--redirect-http-to', 'https://trace.example.com:30443',
            '--trusted-proxies', '192.0.2.1',
        )
        rendered = configure.render_nginx(config, (ROOT / 'nginx.conf').read_text())
        self.assertNotRegex(rendered, r'__[A-Z_]+__')
        self.assertIn('unix:/tmp/ntwa-health.sock', rendered)
        self.assertIn('/tmp/ntwa.htpasswd', rendered)
        self.assertIn('auth_basic', rendered)
        self.assertIn('set_real_ip_from 192.0.2.1/32;', rendered)
        self.assertIn('limit_req zone=api_ip', rendered)
        self.assertIn('limit_conn sse_ip', rendered)
        self.assertIn('proxy_buffering off;', rendered)
        self.assertIn('$is_args$args', rendered)
        self.assertIn('https://trace.example.com:30443$request_uri', rendered)
        self.assertIn('return 404;', rendered)
        self.assertIn('Content-Security-Policy', rendered)


if __name__ == '__main__':
    unittest.main()
