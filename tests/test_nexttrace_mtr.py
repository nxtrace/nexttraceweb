import math
import unittest

from nexttrace_mtr import build_mtr_json_command, build_process_env
from ntwa.mtr import Aggregator


class MTRContractTests(unittest.TestCase):
    def test_command_selects_explicit_mtr_json_without_report_or_raw(self):
        command = build_mtr_json_command('/usr/local/bin/nexttrace', ['192.0.2.1', '--udp'])
        self.assertEqual(command, ['/usr/local/bin/nexttrace', '192.0.2.1', '--udp', '--mtr', '--json'])
        self.assertNotIn('--raw', command)
        self.assertNotIn('-q', command)

    def test_flavor_selects_the_supported_mtr_switch(self):
        for flavor in ('nexttrace', 'nexttrace-tiny'):
            self.assertEqual(build_mtr_json_command('/bin/native', ['127.0.0.1'], flavor)[-2:], ['--mtr', '--json'])
        command = build_mtr_json_command('/bin/native', ['127.0.0.1'], 'ntr')
        self.assertEqual(command, ['/bin/native', '127.0.0.1', '--json'])
        with self.assertRaises(ValueError):
            build_mtr_json_command('/bin/native', [], 'unknown')

    def test_process_env_drops_uninterrupted_flag_without_mutating_input(self):
        source = {'NEXTTRACE_UNINTERRUPTED': '1', 'PATH': '/usr/bin'}
        self.assertEqual(build_process_env(source), {'PATH': '/usr/bin'})
        self.assertEqual(source['NEXTTRACE_UNINTERRUPTED'], '1')

    def test_online_statistics_include_successful_zero_rtt_and_timeouts(self):
        agg = Aggregator()
        for rtt in [0, 10, 20]:
            agg.ingest(dict(ttl=1, success=True, ip='192.0.2.1', host='edge.example', rtt_ms=rtt))
        agg.ingest(dict(ttl=1, success=False))
        row, = agg.snapshot()
        self.assertEqual((row['sent'], row['successCount'], row['lossCount']), (4, 3, 1))
        self.assertEqual(row['lossPercent'], 25)
        self.assertEqual(row['avgMs'], 10)
        self.assertEqual(row['bestMs'], 0)
        self.assertEqual(row['worstMs'], 20)
        self.assertAlmostEqual(row['stdevMs'], math.sqrt(200 / 3))
        self.assertTrue(row['lastIsTimeout'])
        self.assertEqual(row['ip'], '192.0.2.1')
        self.assertNotIn('latencies', agg.rows[1])

    def test_destination_truncation_and_reopened_path(self):
        agg = Aggregator()
        for ttl in [3, 1, 2]:
            agg.ingest(dict(ttl=ttl, success=True, rtt_ms=ttl))
        agg.path(dict(reason='destination_reached', hop=2))
        agg.ingest(dict(ttl=3, success=True, rtt_ms=3))
        self.assertEqual([row['ttl'] for row in agg.snapshot()], [1, 2])
        agg.path(None)
        agg.ingest(dict(ttl=3, success=True, rtt_ms=4))
        self.assertEqual([row['ttl'] for row in agg.snapshot()], [1, 2, 3])
        self.assertEqual(agg.snapshot()[-1]['sent'], 1)

    def test_metadata_updates_preserve_existing_fields_and_snapshot_is_detached(self):
        agg = Aggregator()
        agg.ingest(dict(ttl=1, success=True, rtt_ms=3, ip='192.0.2.1', country='Japan', city='Tokyo'))
        first = agg.snapshot()
        agg.ingest(dict(ttl=1, success=True, rtt_ms=5, ip='', host='edge.example', owner='Example'))
        row, = agg.snapshot()
        self.assertEqual(row['location'], 'Japan / Tokyo')
        self.assertEqual(row['ip'], '192.0.2.1')
        self.assertEqual(row['ptr'], 'edge.example')
        self.assertEqual(first[0]['sent'], 1)
        self.assertEqual(row['sent'], 2)


if __name__ == '__main__':
    unittest.main()
