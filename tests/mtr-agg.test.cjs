const test = require('node:test');
const assert = require('node:assert/strict');

const {
  beginTraceIntent,
  buildRenderableRows,
  cancelTraceIntent,
  createMTRAggregator,
  createTraceViewState,
  escapeHTML,
  formatLastValue,
  formatLocation,
  ingestMTRRawRecord,
  isCurrentTraceIntent,
  renderRowHtml,
  renderTableHtml,
  resetMTRAggregator,
} = require('../assets/js/mtr-agg.js');

test('aggregates repeated success probes on the same ttl', () => {
  const aggregator = createMTRAggregator();

  ingestMTRRawRecord(aggregator, { ttl: 3, success: true, ip: '1.1.1.1', host: 'edge-a', rtt_ms: 10 });
  ingestMTRRawRecord(aggregator, { ttl: 3, success: true, rtt_ms: 20 });
  ingestMTRRawRecord(aggregator, { ttl: 3, success: true, owner: 'ExampleNet', rtt_ms: 30 });

  const [row] = buildRenderableRows(aggregator);
  assert.equal(row.ttl, 3);
  assert.equal(row.sent, 3);
  assert.equal(row.successCount, 3);
  assert.equal(row.lossCount, 0);
  assert.equal(row.lastMs, 30);
  assert.equal(row.avgMs, 20);
  assert.equal(row.bestMs, 10);
  assert.equal(row.worstMs, 30);
  assert.equal(row.ip, '1.1.1.1');
  assert.equal(row.ptr, 'edge-a');
  assert.equal(row.owner, 'ExampleNet');
  assert.ok(Math.abs(row.stdevMs - 8.1649658093) < 1e-9);
});

test('accounts for timeout probes in sent and loss rate', () => {
  const aggregator = createMTRAggregator();

  ingestMTRRawRecord(aggregator, { ttl: 5, success: true, ip: '2.2.2.2', rtt_ms: 12 });
  ingestMTRRawRecord(aggregator, { ttl: 5, success: false });
  ingestMTRRawRecord(aggregator, { ttl: 5, success: true, rtt_ms: 18 });

  const [row] = buildRenderableRows(aggregator);
  assert.equal(row.sent, 3);
  assert.equal(row.successCount, 2);
  assert.equal(row.lossCount, 1);
  assert.equal(row.lastMs, 18);
  assert.equal(row.lastIsTimeout, false);
  assert.ok(Math.abs(row.lossPercent - 33.3333333333) < 1e-9);
});

test('timeout row renders last latency as a dash', () => {
  const aggregator = createMTRAggregator();

  ingestMTRRawRecord(aggregator, { ttl: 7, success: true, rtt_ms: 9 });
  ingestMTRRawRecord(aggregator, { ttl: 7, success: false });

  const [row] = buildRenderableRows(aggregator);
  assert.equal(formatLastValue(row), '-');
});

test('formatLocation omits empty segments', () => {
  assert.equal(formatLocation('Japan', '', 'Tokyo', ''), 'Japan / Tokyo');
});

test('render helpers escape html-sensitive content', () => {
  const html = renderRowHtml({
    ttl: 1,
    ip: '<script>alert(1)</script>',
    asn: 'AS1',
    location: 'x',
    owner: 'y',
    lossPercent: 0,
    sent: 1,
    successCount: 1,
    lastMs: 1,
    lastIsTimeout: false,
    avgMs: 1,
    bestMs: 1,
    worstMs: 1,
    stdevMs: 0,
    ptr: 'ptr'
  });

  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.equal(escapeHTML('"\'&<>'), '&quot;&#39;&amp;&lt;&gt;');
});

test('trace view state rejects stale start token after cancel', () => {
  const state = createTraceViewState();
  const token = beginTraceIntent(state);

  assert.equal(isCurrentTraceIntent(state, token), true);
  cancelTraceIntent(state);
  assert.equal(isCurrentTraceIntent(state, token), false);
});

test('renderTableHtml preserves owner header', () => {
  const tableHtml = renderTableHtml([]);
  assert.ok(tableHtml.includes('<th>OWNER</th>'));
});

test('reset clears all aggregated rows', () => {
  const aggregator = createMTRAggregator();

  ingestMTRRawRecord(aggregator, { ttl: 1, success: true, rtt_ms: 1 });
  resetMTRAggregator(aggregator);

  assert.deepEqual(buildRenderableRows(aggregator), []);
});
