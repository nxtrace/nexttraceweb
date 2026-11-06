const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function storage() {
  const values = new Map();
  return { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key) };
}
function controller(options = {}) {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, { value: '', textContent: '', innerHTML: '', classList: { contains: () => false, remove() {}, add() {} }, addEventListener() {}, focus() {} });
    return elements.get(id);
  };
  const timers = new Map();
  const context = {
    AbortController, console,
    localStorage: storage(), sessionStorage: storage(),
    document: { getElementById: element }, navigator: { languages: ['en'] },
    setTimeout: callback => { const id = timers.size + 1; timers.set(id, callback); return id; },
    clearTimeout: id => timers.delete(id),
    readSettings: () => ({ localResolve: true }),
    resolveTarget: options.resolve || (async input => input),
    request: options.request || (async () => ({})),
    createView: () => Object.fromEntries(['renderTable', 'initTable', 'renderUi', 'renderStatusStrip', 'renderStatusSummary', 'renderNotice', 'renderEmptyState', 'renderRecentQueries', 'renderSettingsSummaryPanel', 'renderActionButtons'].map(name => [name, () => {}])),
    TraceClient: class {
      constructor(onSnapshot) { this.onSnapshot = onSnapshot; this.id = 'task-old'; this.creates = []; this.stopCalls = []; }
      detach() {}
      stop(id = this.id) { this.stopCalls.push(id); return options.stop ? options.stop(id) : Promise.resolve(); }
      async create(ip) { this.creates.push(ip); return options.create ? options.create(ip) : { task_id: 'task-new', seq: 1, state: 'running', rows: [], target: ip }; }
      attach(snapshot) { this.id = snapshot.task_id; context.sessionStorage.setItem('ntwaTaskId', this.id); this.onSnapshot(snapshot); }
      resume() { return options.resume ? options.resume(this) : Promise.resolve(false); }
    }
  };
  context.window = {
    nextTraceMTRAgg: { TABLE_HEADER_HTML: '' },
    nextTraceUIState: { normalizeQuery: value => value.trim(), upsertRecentQuery: (_old, query) => [query] },
    nextTraceI18n: { DEFAULT_LOCALE: 'en', translate: (_locale, key) => key },
    nextTracePaths: {}, addEventListener() {}
  };
  const source = fs.readFileSync(path.join(__dirname, '../assets/js/main.js'), 'utf8').replace(/^import .*;\s*$/gm, '').replace(/^initializePage\(\);$/m, '');
  vm.createContext(context);
  vm.runInContext(source, context, { filename: 'assets/js/main.js' });
  context.uiState.connectionStatus = 'connected';
  element('params').value = '192.0.2.1';
  return { context, element, timers };
}

test('a delayed stop cannot clear the busy state of a subsequent start', async () => {
  const old = deferred();
  let stops = 0;
  const h = controller({ stop: () => ++stops === 1 ? old.promise : Promise.resolve() });
  const stopped = h.context.stopNexttrace();
  h.element('params').value = '192.0.2.2';
  await h.context.startNexttrace();
  const started = h.context.traceClient.creates.length;
  old.resolve();
  await stopped;
  if (started) {
    assert.equal(h.context.traceClient.id, 'task-new');
    assert.equal(h.context.uiState.taskStatus, 'running');
    assert.equal(h.context.busy, true);
  } else {
    assert.equal(h.context.busy, false);
    assert.equal(h.context.traceClient.creates.length, 0);
  }
});

test('a delayed reset cannot detach and erase a subsequent task', async () => {
  const old = deferred();
  let stops = 0;
  const h = controller({ stop: () => ++stops === 1 ? old.promise : Promise.resolve() });
  const reset = h.context.resetForm();
  h.element('params').value = '192.0.2.2';
  await h.context.startNexttrace();
  const started = h.context.traceClient.creates.length;
  old.resolve();
  await reset;
  if (started) {
    assert.equal(h.context.traceClient.id, 'task-new');
    assert.equal(h.element('params').value, '192.0.2.2');
    assert.equal(h.context.uiState.taskStatus, 'running');
  } else {
    assert.equal(h.context.uiState.taskStatus, 'idle');
    assert.equal(h.context.traceClient.creates.length, 0);
  }
});

test('a failed initial resume must not schedule a retry after a new start supersedes it', async () => {
  const initial = deferred();
  const h = controller({ request: () => initial.promise });
  h.context.sessionStorage.setItem('ntwaTaskId', 'task-old');
  const resume = h.context.resumeTrace();
  h.element('params').value = '192.0.2.2';
  await h.context.startNexttrace();
  initial.reject(new TypeError('connection lost'));
  await resume;
  assert.equal(h.context.uiState.connectionStatus, 'connected');
  assert.equal(h.context.traceClient.id, 'task-new');
  assert.equal(h.timers.size, 0);
});


test('reset clears expired task references even when stop returns 404', async () => {
  const h = controller({ stop: async () => { throw Object.assign(new Error('expired'), { status: 404 }); } });
  h.context.sessionStorage.setItem('ntwaTaskId', 'task-old');
  h.context.sessionStorage.setItem('ntwaTaskQuery', 'old.example');
  h.context.snapshotRows = [{ ttl: 1, sent: 8 }];
  h.context.busy = true;
  h.context.uiState.taskStatus = 'running';
  await h.context.resetForm();
  assert.equal(h.context.traceClient.id, null);
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskId'), null);
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskQuery'), null);
  assert.equal(h.context.snapshotRows.length, 0);
  assert.equal(h.element('params').value, '');
  assert.equal(h.context.busy, false);
  assert.equal(h.context.uiState.taskStatus, 'idle');
});

test('expired resume releases a restored busy state and retains rendered results', async () => {
  const h = controller({ resume: async () => { throw Object.assign(new Error('expired'), { status: 404 }); } });
  h.context.snapshotRows = [{ ttl: 1, sent: 8 }];
  h.context.busy = true;
  h.context.uiState.taskStatus = 'running';
  // true means the resume intent was handled, so ?trace must not auto-start again.
  const handled = await h.context.resumeTrace();
  assert.equal(handled, true);
  assert.equal(h.context.traceClient.creates.length, 0);
  assert.equal(h.context.traceClient.id, null);
  assert.equal(h.context.busy, false);
  assert.equal(h.context.uiState.connectionStatus, 'connected');
  assert.equal(h.context.uiState.taskStatus, 'complete');
  assert.equal(h.context.snapshotRows[0].sent, 8);
  assert.equal(h.timers.size, 0);
});

test('stop during pending resume addresses the saved task and keeps its final snapshot', async () => {
  const pending = deferred();
  const final = { task_id: 'saved-task', seq: 9, state: 'cancelled', rows: [{ ttl: 1, sent: 12 }], target: '192.0.2.7' };
  const h = controller({ resume: () => pending.promise, stop: async () => final });
  h.context.traceClient.id = null;
  h.context.sessionStorage.setItem('ntwaTaskId', 'saved-task');
  const resume = h.context.resumeTrace();
  await Promise.resolve();
  assert.equal(await h.context.stopNexttrace(), true);
  assert.equal(h.context.traceClient.stopCalls[0], 'saved-task');
  assert.equal(h.context.snapshotRows[0].sent, 12);
  assert.equal(h.context.uiState.resolvedTarget, '192.0.2.7');
  assert.equal(h.context.busy, false);
  pending.resolve(false);
  await resume;
  assert.equal(h.context.snapshotRows[0].sent, 12);
  assert.equal(h.context.uiState.taskStatus, 'complete');
});


test('the original query is saved before an unresolved creation request can be interrupted by refresh', async () => {
  const creation = deferred();
  const h = controller({ create: () => creation.promise, resolve: async () => '192.0.2.9' });
  h.context.sessionStorage.setItem('ntwaTaskQuery', 'old.example');
  h.element('params').value = 'new.example';
  const start = h.context.startNexttrace();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.context.traceClient.creates.length, 1);
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskQuery'), 'new.example');
  creation.resolve({ task_id: 'task-new', seq: 1, state: 'running', rows: [], target: '192.0.2.9' });
  await start;
});

test('a creation response from before pagehide must not stop its already resumed task', async () => {
  const response = deferred();
  const h = controller({ create: () => response.promise });
  const create = h.context.startNexttrace();
  await new Promise(resolve => setImmediate(resolve));
  h.context.activeIntent++;
  h.context.traceClient.attach({ task_id: 'task-new', seq: 2, state: 'running', rows: [], target: '192.0.2.1' });
  response.resolve({ task_id: 'task-new', seq: 1, state: 'starting', rows: [] });
  await create;
  assert.equal(h.context.traceClient.stopCalls.includes('task-new'), false);
  assert.equal(h.context.traceClient.id, 'task-new');
  assert.equal(h.context.uiState.taskStatus, 'running');
});
