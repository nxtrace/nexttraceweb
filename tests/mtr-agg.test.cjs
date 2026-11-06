const test = require('node:test');
const assert = require('node:assert/strict');
const { escapeHTML, formatLastValue, renderRowHtml, renderTableHtml, buildTableHeaderHtml } = require('../assets/js/mtr-agg.js');
const row = { ttl: 1, ip: '192.0.2.1', asn: 'AS64512', location: 'Example', owner: 'ExampleNet', lossPercent: 0, sent: 3, successCount: 3, lastMs: 0, lastIsTimeout: false, avgMs: 0, bestMs: 0, worstMs: 0, stdevMs: 0, ptr: 'hop.example' };

test('backend snapshots render the same thirteen columns including zero RTT', () => {
  const html = renderRowHtml(row);
  assert.equal((html.match(/<td\b/g) || []).length, 13);
  assert.ok(html.includes('ExampleNet'));
  assert.ok(html.includes('hop.example'));
  assert.equal(formatLastValue(row), '0.00');
  assert.match(html, /class="latency_avg"[^>]*>0\.00<\/td>/);
  assert.match(html, /class="latency_best"[^>]*>0\.00<\/td>/);
});

test('timeouts retain previous statistics but render last latency as a dash', () => {
  assert.equal(formatLastValue({ ...row, lastIsTimeout: true, lastMs: 2 }), '-');
  assert.equal(formatLastValue({ ...row, successCount: 0 }), '-');
});

test('render helpers escape snapshot content and translated headers', () => {
  const html = renderRowHtml({ ...row, ip: '<script>alert(1)</script>' });
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.equal(escapeHTML('"\'&<>'), '&quot;&#39;&amp;&lt;&gt;');
  assert.ok(buildTableHeaderHtml(Array(13).fill('<header>')).includes('&lt;header&gt;'));
});

test('snapshot rendering replaces rows and retains the existing headers', () => {
  const html = renderTableHtml([row]);
  assert.equal((html.match(/<tr>/g) || []).length, 2);
  assert.ok(html.includes('<th>OWNER</th>'));
  assert.ok(!renderTableHtml([]).includes('192.0.2.1'));
});
