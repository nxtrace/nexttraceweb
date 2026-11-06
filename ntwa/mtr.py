"""Bounded per-TTL statistics for the existing table, not native responder rows."""
import math


class Aggregator:
    def __init__(self):
        self.rows = {}
        self.path_end = None

    def path(self, conclusion):
        self.path_end = conclusion
        if conclusion and conclusion.get('reason') == 'destination_reached':
            hop = conclusion['hop']
            self.rows = {ttl: row for ttl, row in self.rows.items() if ttl <= hop}

    def ingest(self, record):
        ttl = record.get('ttl')
        if not isinstance(ttl, int) or not 1 <= ttl <= 255:
            raise ValueError('Invalid probe TTL')
        if self.path_end and self.path_end.get('reason') == 'destination_reached' and ttl > self.path_end['hop']:
            return
        row = self.rows.setdefault(ttl, dict(ttl=ttl, ip='', ptr='', asn='', country='', prov='', city='', district='', owner='', sent=0, successCount=0, lossCount=0, lossPercent=0, lastMs=0, lastIsTimeout=True, avgMs=0, bestMs=0, worstMs=0, stdevMs=0, m2=0))
        row['sent'] += 1
        for source, dest in [('host', 'ptr'), *[(k, k) for k in ('ip', 'asn', 'country', 'prov', 'city', 'district', 'owner')]]:
            if record.get(source) is not None and str(record[source]).strip():
                row[dest] = str(record[source]).strip()
        rtt = record.get('rtt_ms', 0)
        success = record.get('success') is True and isinstance(rtt, (float, int)) and math.isfinite(rtt) and rtt >= 0
        row['lastIsTimeout'] = not success
        if success:
            row['successCount'] += 1
            count = row['successCount']
            delta = rtt - row['avgMs']
            row['avgMs'] += delta / count
            row['m2'] += delta * (rtt - row['avgMs'])
            row['stdevMs'] = math.sqrt(max(0, row['m2'] / count))
            row['lastMs'] = rtt
            row['bestMs'] = min(row['bestMs'], rtt) if count > 1 else rtt
            row['worstMs'] = max(row['worstMs'], rtt)
        row['lossCount'] = row['sent'] - row['successCount']
        row['lossPercent'] = row['lossCount'] / row['sent'] * 100

    def snapshot(self):
        return [dict({k: v for k, v in row.items() if k not in ('m2', 'country', 'prov', 'city', 'district')}, location=' / '.join(row[k] for k in ('country', 'prov', 'city', 'district') if row[k])) for _, row in sorted(self.rows.items())]
