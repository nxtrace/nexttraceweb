const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildSettingsSummary,
  buildShareUrl,
  deriveActionState,
  deriveEmptyState,
  deriveTaskMeta,
  formatTargetSummary,
  loadRecentQueries,
  upsertRecentQuery,
} = require('../assets/js/ui-state.js');

test('upsertRecentQuery deduplicates values and keeps newest first', () => {
  const queries = upsertRecentQuery(['1.1.1.1', 'example.com'], 'Example.com');
  assert.deepEqual(queries, ['Example.com', '1.1.1.1']);
});

test('loadRecentQueries ignores invalid payloads and truncates to the limit', () => {
  const queries = loadRecentQueries('["a","b","A","c","d","e","f"]', 4);
  assert.deepEqual(queries, ['a', 'b', 'c', 'd']);
  assert.deepEqual(loadRecentQueries('{bad json'), []);
});

test('buildShareUrl preserves the path and encodes the trace query', () => {
  const shareUrl = buildShareUrl('https://trace.example', '/tool', 'example.com/hello');
  assert.equal(shareUrl, 'https://trace.example/tool?trace=example.com%2Fhello');
});

test('deriveActionState enables stop during resolving and disables start while busy', () => {
  const resolvingState = deriveActionState('connected', 'resolving', 'example.com');
  const idleState = deriveActionState('connected', 'idle', 'example.com');
  const disconnectedState = deriveActionState('disconnected', 'idle', 'example.com');

  assert.equal(resolvingState.startDisabled, true);
  assert.equal(resolvingState.stopDisabled, false);
  assert.equal(idleState.startDisabled, false);
  assert.equal(disconnectedState.startDisabled, true);
});

test('deriveEmptyState returns waiting copy while the trace has no rows yet', () => {
  const state = deriveEmptyState('waiting', 'connected', false);
  assert.equal(state.visible, true);
  assert.equal(state.title, 'Waiting for first hop');
});

test('deriveTaskMeta surfaces retained-results copy for completed traces', () => {
  const meta = deriveTaskMeta('complete', 'connected', 3);
  assert.equal(meta.label, 'Complete');
  assert.equal(meta.tone, 'success');
  assert.match(meta.detail, /retained/i);
});

test('formatTargetSummary shows resolved targets when local resolve changes the value', () => {
  assert.equal(formatTargetSummary('example.com', '1.1.1.1'), 'example.com -> 1.1.1.1');
  assert.equal(formatTargetSummary('', ''), 'Not set');
});

test('buildSettingsSummary emits concise status chips', () => {
  const summary = buildSettingsSummary({
    language: 'en',
    intervalSeconds: '0.04',
    packetSize: '128',
    dataProvider: 'LeoMoeAPI',
    localResolve: true
  });

  assert.deepEqual(summary, ['EN', 'Local Resolve', '40 ms', '128 B', 'LeoMoeAPI']);
});
