const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const { joinBasePath } = require('../assets/js/paths.js');
const root = path.resolve(__dirname, '..');

function storage(values = {}) {
  const map = new Map(Object.entries(values));
  return { getItem: key => map.has(key) ? map.get(key) : null, setItem: (key, value) => map.set(key, String(value)), removeItem: key => map.delete(key) };
}
function load(relative, names, context) {
  const source = fs.readFileSync(path.join(root, relative), 'utf8')
    .replace(/^import .*;\s*$/gm, '').replace(/\bexport\s+/g, '');
  return vm.runInNewContext(`${source}\n({${names.join(',')}})`, context, { filename: relative });
}
function harness(options = {}) {
  const calls = [], streams = [], timers = new Map(), snapshots = [], connections = [];
  let nextTimer = 0;
  const context = {
    location: { pathname: '/tools/nexttrace/' }, joinBasePath,
    sessionStorage: options.storage || storage(options.saved),
    crypto: { randomUUID: () => typeof options.uuid === 'function' ? options.uuid() : options.uuid || 'request-one' },
    setInterval: (callback, delay) => { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearInterval: id => timers.delete(id),
    setTimeout: options.delay || setTimeout,
    EventSource: class {
      constructor(url) { this.url = url; this.closed = false; this.handlers = {}; streams.push(this); }
      addEventListener(name, handler) { this.handlers[name] = handler; }
      close() { this.closed = true; }
      snapshot(value) { this.handlers.snapshot({ data: JSON.stringify(value) }); }
    },
    fetch: async (url, config) => {
      calls.push({ url, config });
      const value = await options.respond?.(url, config, calls.length) || { task_id: 'task-one', seq: 1, state: 'running', rows: [] };
      return { ok: value.status === undefined || value.status < 400, status: value.status || 200, json: async () => value };
    }
  };
  const { TraceClient } = load('assets/js/trace-client.js', ['TraceClient'], context);
  return { client: new TraceClient(value => snapshots.push(value), value => connections.push(value)), context, calls, streams, timers, snapshots, connections };
}
const active = { task_id: 'task-one', seq: 1, state: 'running', rows: [] };
const tick = () => new Promise(resolve => setImmediate(resolve));

test('SSE snapshots replace current state and reject another task or repeated sequence', async () => {
  const h = harness();
  h.client.attach(active);
  await tick();
  assert.equal(h.streams[0].url, '/tools/nexttrace/api/traces/task-one/events');
  h.streams[0].snapshot({ ...active, task_id: 'old-task', seq: 9 });
  h.streams[0].snapshot(active);
  h.streams[0].snapshot({ ...active, seq: 2, rows: [{ ttl: 1, sent: 7 }] });
  assert.equal(h.snapshots.length, 2);
  assert.equal(h.snapshots[1].rows[0].sent, 7);
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskId'), 'task-one');
  assert.equal([...h.timers.values()][0].delay, 10000);
  h.client.detach();
});

test('transport reconnect keeps the task and never creates a second process', async () => {
  const h = harness();
  h.client.attach(active);
  await tick();
  h.streams[0].onerror();
  h.streams[0].onopen();
  assert.deepEqual(h.connections.slice(-2), [false, true]);
  assert.equal(h.streams.length, 1);
  assert.equal(h.calls.some(call => call.url.endsWith('/api/traces')), false);
  assert.equal(h.client.id, 'task-one');
  h.client.detach();
});

test('terminal snapshot retains final data and closes lease and event stream', async () => {
  const h = harness();
  h.client.attach(active);
  await tick();
  h.streams[0].snapshot({ ...active, seq: 2, state: 'cancelled', rows: [{ ttl: 1, sent: 3 }] });
  assert.equal(h.snapshots.at(-1).rows[0].sent, 3);
  assert.equal(h.streams[0].closed, true);
  assert.equal(h.timers.size, 0);
});

test('network retry reuses the same creation request id and payload', async () => {
  const h = harness({ respond: (_url, _config, count) => { if (count === 1) throw new TypeError('connection lost'); return active; } });
  await h.client.create('192.0.2.1', { intervalSeconds: '1.000' });
  assert.equal(h.calls.length, 2);
  assert.equal(h.calls[0].config.body, h.calls[1].config.body);
  assert.equal(JSON.parse(h.calls[0].config.body).request_id, 'request-one');
});

test('server rejection is not retried as a new task', async () => {
  const h = harness({ respond: () => ({ status: 429, code: 'trace_capacity_exceeded', message: 'capacity' }) });
  await assert.rejects(h.client.create('192.0.2.1', {}), error => error.status === 429);
  assert.equal(h.calls.length, 1);
});

test('refresh resumes saved task without creating it again', async () => {
  const h = harness({ saved: { ntwaTaskId: 'task-one' } });
  assert.equal(await h.client.resume(), true);
  await tick();
  assert.equal(h.calls[0].url, '/tools/nexttrace/api/traces/task-one');
  assert.equal(h.calls[0].config.method, 'GET');
  assert.equal(h.streams.length, 1);
  assert.equal(h.calls.some(call => call.url.endsWith('/api/traces')), false);
  h.client.detach();
});

test('expired saved task is cleared and does not silently create another', async () => {
  const h = harness({ saved: { ntwaTaskId: 'expired' }, respond: () => ({ status: 404, code: 'trace_not_running' }) });
  await assert.rejects(h.client.resume(), error => error.status === 404);
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskId'), null);
  assert.equal(h.calls.length, 1);
  assert.equal(h.streams.length, 0);
});

test('stop is addressed to its task and an old task cannot overwrite the current display', async () => {
  const h = harness({ respond: url => url.endsWith('/stop') ? { task_id: 'old-task', seq: 8, state: 'cancelled', rows: [] } : active });
  h.client.attach(active);
  await tick();
  await h.client.stop('old-task');
  assert.equal(h.calls.at(-1).url, '/tools/nexttrace/api/traces/old-task/stop');
  assert.equal(h.snapshots.length, 1);
  assert.equal(h.client.id, 'task-one');
  h.client.detach();
});

test('new default and persisted 40ms use one settings model and preserve language separation', () => {
  for (const [saved, expected] of [[{}, '1.000'], [{ intervalSeconds: '0.040', language: 'en', uiLanguage: 'zh' }, '0.040']]) {
    const context = { localStorage: storage(saved), document: { getElementById: id => ({ value: id === 'protocol' ? 'tcp' : 'ipv6' }) } };
    const { readSettings, saveSettings } = load('assets/js/settings-store.js', ['readSettings', 'saveSettings'], context);
    const values = readSettings();
    assert.equal(values.intervalSeconds, expected);
    assert.equal(values.protocol, 'tcp');
    assert.equal(values.ipVersion, 'ipv6');
    saveSettings(values);
    assert.equal(context.localStorage.getItem('intervalSeconds'), expected);
    assert.equal(context.localStorage.getItem('uiLanguage'), saved.uiLanguage || null);
  }
});

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

test('detaching invalidates queued callbacks from the old SSE connection', async () => {
  const h = harness();
  h.client.attach(active);
  await tick();
  const old = h.streams[0];
  const connections = h.connections.length;
  h.client.detach();
  old.snapshot({ ...active, seq: 2, state: 'completed', rows: [{ ttl: 9 }] });
  old.onopen();
  old.onerror();
  assert.equal(h.snapshots.length, 1);
  assert.equal(h.connections.length, connections);
});

test('detaching invalidates an in-flight lease response for the same task', async () => {
  const response = deferred();
  const h = harness({ respond: () => response.promise });
  h.client.attach(active);
  h.client.detach();
  response.resolve({ ...active, seq: 2, rows: [{ ttl: 9 }] });
  await tick();
  assert.equal(h.snapshots.length, 1);
  assert.equal(h.connections.length, 0);
});

test('a delayed resume cannot replace a newly attached task', async () => {
  const response = deferred();
  const h = harness({ saved: { ntwaTaskId: active.task_id }, respond: url => url.endsWith('/task-one') ? response.promise : { ...active, task_id: 'task-new' } });
  const resume = h.client.resume();
  h.client.attach({ ...active, task_id: 'task-new' });
  response.resolve(active);
  await resume;
  await tick();
  assert.equal(h.client.id, 'task-new');
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskId'), 'task-new');
  assert.equal(h.snapshots.at(-1).task_id, 'task-new');
  h.client.detach();
});

test('a delayed resume cannot resurrect a detached and reset task', async () => {
  const response = deferred();
  const h = harness({ saved: { ntwaTaskId: active.task_id }, respond: () => response.promise });
  const resume = h.client.resume();
  h.client.detach();
  h.client.id = null;
  h.context.sessionStorage.removeItem('ntwaTaskId');
  response.resolve(active);
  await resume;
  assert.equal(h.client.id, null);
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskId'), null);
  assert.equal(h.streams.length, 0);
});

test('a delayed 404 from resume cannot clear the new task reference', async () => {
  const response = deferred();
  const h = harness({ saved: { ntwaTaskId: active.task_id }, respond: url => url.endsWith('/task-one') ? response.promise : { ...active, task_id: 'task-new' } });
  const resume = h.client.resume().catch(() => false);
  h.client.attach({ ...active, task_id: 'task-new' });
  response.resolve({ status: 404, code: 'trace_not_running' });
  await resume;
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskId'), 'task-new');
  h.client.detach();
});


test('stop remains pending until polling observes a terminal task snapshot', async () => {
  let releasePoll;
  const h = harness({
    delay: (callback, milliseconds) => { assert.equal(milliseconds, 100); releasePoll = callback; },
    respond: url => {
      if (url.endsWith('/stop')) return { ...active, seq: 2, state: 'stopping' };
      if (url.endsWith('/lease')) return active;
      return { ...active, seq: 3, state: 'cancelled', rows: [{ ttl: 1, sent: 4 }] };
    }
  });
  h.client.attach(active);
  await tick();
  let settled = false;
  const stop = h.client.stop().then(snapshot => { settled = true; return snapshot; });
  await tick();
  assert.equal(settled, false);
  assert.equal(h.snapshots.at(-1).state, 'running');
  assert.equal(h.calls.filter(call => call.url.endsWith('/stop')).length, 1);
  releasePoll();
  const final = await stop;
  assert.equal(final.state, 'cancelled');
  assert.equal(h.calls.at(-1).config.method, 'GET');
  assert.equal(h.calls.at(-1).url, '/tools/nexttrace/api/traces/task-one');
  assert.equal(h.snapshots.at(-1).rows[0].sent, 4);
  assert.equal(h.timers.size, 0);
  assert.equal(h.streams[0].closed, true);
});

test('lease expiry retains final rows but releases the task and restores usable connection state', async () => {
  const h = harness({ respond: () => ({ status: 404, code: 'trace_not_running' }) });
  h.client.attach({ ...active, rows: [{ ttl: 1, sent: 7 }] });
  await tick();
  assert.equal(h.snapshots.at(-1).state, 'failed');
  assert.equal(h.snapshots.at(-1).error.code, 'trace_not_running');
  assert.equal(h.snapshots.at(-1).rows[0].sent, 7);
  assert.equal(h.client.id, null);
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskId'), null);
  assert.equal(h.timers.size, 0);
  assert.equal(h.streams[0].closed, true);
  assert.equal(h.connections.at(-1), true);
});


test('refresh before the creation response resumes the same accepted request instead of starting another process', async () => {
  const sharedStorage = storage();
  const firstResponse = deferred();
  const accepted = new Set();
  const original = harness({
    storage: sharedStorage, uuid: 'request-before-refresh',
    respond: (_url, config) => {
      accepted.add(JSON.parse(config.body).request_id);
      return firstResponse.promise;
    }
  });
  const create = original.client.create('192.0.2.9', { intervalSeconds: '0.040' });
  await tick();
  assert.equal(accepted.size, 1);
  original.client.detach();
  const refreshed = harness({
    storage: sharedStorage, uuid: 'request-after-refresh',
    respond: (url, config) => {
      if (url.endsWith('/api/traces')) accepted.add(JSON.parse(config.body).request_id);
      return active;
    }
  });
  try {
    assert.equal(await refreshed.client.resume(), true);
    await tick();
    const retry = refreshed.calls.find(call => call.url.endsWith('/api/traces'));
    assert.ok(retry, 'the accepted create must be recovered with its original request_id');
    assert.equal(retry.config.body, original.calls[0].config.body);
    assert.equal(JSON.parse(retry.config.body).request_id, 'request-before-refresh');
    assert.equal(accepted.size, 1);
    assert.equal(refreshed.client.id, active.task_id);
  } finally {
    firstResponse.resolve(active);
    await create;
    refreshed.client.detach();
  }
});


test('an expired pending request is cleared without automatic recreation after the deduplication window', async () => {
  const payload = { ip: '192.0.2.9', extra: { intervalSeconds: '1.000' }, request_id: 'expired-request' };
  const h = harness({ saved: { ntwaPendingTrace: JSON.stringify(payload), ntwaPendingTraceAt: String(Date.now() - 300001) } });
  assert.equal(await h.client.resume(), true);
  assert.equal(h.calls.length, 0);
  assert.equal(h.context.sessionStorage.getItem('ntwaPendingTrace'), null);
  assert.equal(h.context.sessionStorage.getItem('ntwaPendingTraceAt'), null);
  assert.equal(h.client.id, null);
  assert.equal(h.streams.length, 0);
});

test('manual retry of unchanged parameters reuses the unexpired pending request id', async () => {
  let attempt = 0;
  const h = harness({
    uuid: () => `request-${++attempt}`,
    respond: (_url, _config, count) => {
      if (count <= 2) throw new TypeError('creation response lost');
      return active;
    }
  });
  const parameters = { intervalSeconds: '0.040', protocol: 'icmp' };
  await assert.rejects(h.client.create('192.0.2.9', parameters), /creation response lost/);
  const pending = h.context.sessionStorage.getItem('ntwaPendingTrace');
  assert.equal(JSON.parse(pending).request_id, 'request-1');
  await h.client.create('192.0.2.9', parameters);
  assert.equal(h.calls.length, 3);
  assert.equal(h.calls[2].config.body, pending);
  assert.equal(JSON.parse(h.calls[2].config.body).request_id, 'request-1');
  assert.equal(h.context.sessionStorage.getItem('ntwaPendingTrace'), null);
  assert.equal(h.context.sessionStorage.getItem('ntwaTaskId'), active.task_id);
});

test('resume tolerates the original create saving its task ID before the retry response arrives', async () => {
  const shared = storage();
  const response = deferred();
  const original = harness({ storage: shared, respond: () => response.promise });
  const create = original.client.create('192.0.2.1', {});
  await tick();
  const retry = deferred();
  const refreshed = harness({ storage: shared, respond: () => retry.promise });
  const resume = refreshed.client.resume();
  await tick();
  response.resolve(active);
  await create;
  retry.resolve(active);
  assert.equal(await resume, true);
  assert.equal(refreshed.client.id, active.task_id);
  refreshed.client.detach();
});
