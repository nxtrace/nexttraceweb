import unittest

from nexttrace_mtr import build_mtr_raw_command, build_process_env, parse_mtr_raw_line


class BuildMTRRawCommandTests(unittest.TestCase):
    def test_builds_mtr_raw_command_without_legacy_flags(self):
        command = build_mtr_raw_command('/usr/local/bin/nexttrace', '1.1.1.1 --ipv4 --tcp')

        self.assertEqual(
            command,
            [
                '/usr/local/bin/nexttrace',
                '1.1.1.1',
                '--ipv4',
                '--tcp',
                '--mtr',
                '--raw',
                '--map',
            ],
        )
        self.assertNotIn('-q', command)
        self.assertNotIn('--send-time', command)

    def test_accepts_pre_split_parameter_list(self):
        command = build_mtr_raw_command('/usr/local/bin/nexttrace', ['1.1.1.1', '--udp'])

        self.assertEqual(
            command,
            [
                '/usr/local/bin/nexttrace',
                '1.1.1.1',
                '--udp',
                '--mtr',
                '--raw',
                '--map',
            ],
        )

    def test_process_env_drops_uninterrupted_flag(self):
        env = build_process_env({'NEXTTRACE_UNINTERRUPTED': '1', 'PATH': '/usr/bin'})

        self.assertEqual(env, {'PATH': '/usr/bin'})


class ParseMTRRawLineTests(unittest.TestCase):
    def test_parses_success_record(self):
        record = parse_mtr_raw_line(
            '4|84.17.33.106|po66-3518.cr01.nrt04.jp.misaka.io|0.27|60068|Japan|Tokyo|Tokyo||cdn77.com|35.6804|139.7690'
        )

        self.assertEqual(
            record,
            {
                'ttl': 4,
                'success': True,
                'ip': '84.17.33.106',
                'host': 'po66-3518.cr01.nrt04.jp.misaka.io',
                'rtt_ms': 0.27,
                'asn': '60068',
                'country': 'Japan',
                'prov': 'Tokyo',
                'city': 'Tokyo',
                'district': '',
                'owner': 'cdn77.com',
                'lat': 35.6804,
                'lng': 139.769,
            },
        )

    def test_parses_timeout_record(self):
        record = parse_mtr_raw_line('7|*||||||||||')

        self.assertEqual(
            record,
            {
                'ttl': 7,
                'success': False,
                'ip': '',
                'host': '',
                'rtt_ms': 0.0,
                'asn': '',
                'country': '',
                'prov': '',
                'city': '',
                'district': '',
                'owner': '',
                'lat': 0.0,
                'lng': 0.0,
            },
        )

    def test_ignores_preamble_banner_and_dirty_lines(self):
        ignored_lines = (
            '',
            '[NextTrace API] preferred API IP - [198.18.22.171] - 698.45ms - Misaka.BER',
            'NextTrace v0.0.0.alpha',
            'IP Geo Data Provider: LeoMoeAPI',
            'not-a-record',
            '2|*||||||',
        )

        for line in ignored_lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_mtr_raw_line(line))


if __name__ == '__main__':
    unittest.main()
