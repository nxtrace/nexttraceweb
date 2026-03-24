const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { setTimeout: delay } = require('node:timers/promises');

const { createBrowserHarness } = require('./browser-harness.cjs');

const repoRoot = path.resolve(__dirname, '..');
const quietConsole = {
  log() {},
  error() {},
  warn() {},
  info() {},
  debug() {}
};

async function main() {
  const checks = [
    checkSettingsOverlayMarkup,
    checkSettingsDrawerControls,
    checkSettingsInputSync,
    checkSettingsPersistenceAndSummary,
    checkSettingsValidation,
    checkPrimaryControls,
    checkShareControl,
    checkIpSelectorControl,
    checkTraceQueryAutostart
  ];

  for (const check of checks) {
    await check();
    process.stdout.write(`ok - ${check.name}\n`);
  }

  process.stdout.write(`ok - ${checks.length} browser control checks passed\n`);
}

async function checkSettingsOverlayMarkup() {
  const html = fs.readFileSync(path.join(repoRoot, 'templates/index.html'), 'utf8');
  const controlPanel = html.match(/<section class="control-panel">([\s\S]*?)<\/section>/);

  assert.ok(controlPanel, 'control panel section should exist');
  assert.equal(controlPanel[1].includes('id="settingMenu"'), false);
  assert.equal(controlPanel[1].includes('id="settingsBackdrop"'), false);
  assert.ok(html.includes('<aside\n    id="settingMenu"'));
}

async function checkSettingsDrawerControls() {
  const harness = createBrowserHarness({ console: quietConsole });
  const { document, elements } = harness;

  elements.settingBtn.click();
  assert.equal(elements.settingMenu.classList.contains('is-open'), true);
  assert.equal(elements.settingBtn.getAttribute('aria-expanded'), 'true');
  assert.equal(document.activeElement && document.activeElement.id, 'language');

  elements.settingCloseBtn.click();
  assert.equal(elements.settingMenu.classList.contains('is-open'), false);
  assert.equal(elements.settingBtn.getAttribute('aria-expanded'), 'false');
  assert.equal(document.activeElement && document.activeElement.id, 'settingBtn');

  elements.settingBtn.click();
  elements.settingsBackdrop.click();
  assert.equal(elements.settingMenu.classList.contains('is-open'), false);

  elements.settingBtn.click();
  const outside = document.createElement('div');
  document.body.appendChild(outside);
  outside.click();
  assert.equal(elements.settingMenu.classList.contains('is-open'), false);

  elements.settingBtn.click();
  harness.dispatchKeydown(document, 'Escape');
  await harness.flushPromises();
  assert.equal(elements.settingMenu.classList.contains('is-open'), false);
}

async function checkSettingsInputSync() {
  const harness = createBrowserHarness({ console: quietConsole });
  const { elements } = harness;

  elements.intervalTimeRange.value = '0.125';
  harness.dispatchInput(elements.intervalTimeRange);
  assert.equal(elements.intervalTimeInput.value, '0.125');

  elements.intervalTimeInput.value = '0.255';
  harness.dispatchInput(elements.intervalTimeInput);
  assert.equal(elements.intervalTimeRange.value, '0.255');

  elements.packetSizeRange.value = '128';
  harness.dispatchInput(elements.packetSizeRange);
  assert.equal(elements.packetSizeInput.value, '128');

  elements.packetSizeInput.value = '256';
  harness.dispatchInput(elements.packetSizeInput);
  assert.equal(elements.packetSizeRange.value, '256');
}

async function checkSettingsPersistenceAndSummary() {
  const harness = createBrowserHarness({ console: quietConsole });
  const { localStorage, elements } = harness;

  elements.ipVersion.value = 'ipv6';
  harness.dispatchChange(elements.ipVersion);
  elements.protocol.value = 'udp';
  harness.dispatchChange(elements.protocol);
  elements.settingBtn.click();

  elements.language.value = 'en';
  elements.localResolveCheckbox.checked = false;
  elements.intervalTimeInput.value = '0.125';
  harness.dispatchInput(elements.intervalTimeInput);
  elements.packetSizeInput.value = '256';
  harness.dispatchInput(elements.packetSizeInput);
  elements.maxHopInput.value = '12';
  elements.minHopInput.value = '2';
  elements.portInput.value = '443';
  elements.devInput.value = 'en0';
  elements.dataProvider.value = 'IP.SB';

  elements.saveBtn.click();
  await harness.flushPromises();

  assert.equal(localStorage.getItem('language'), 'en');
  assert.equal(localStorage.getItem('localResolve'), 'false');
  assert.equal(localStorage.getItem('intervalSeconds'), '0.125');
  assert.equal(localStorage.getItem('packetSize'), '256');
  assert.equal(localStorage.getItem('maxHop'), '12');
  assert.equal(localStorage.getItem('minHop'), '2');
  assert.equal(localStorage.getItem('port'), '443');
  assert.equal(localStorage.getItem('device'), 'en0');
  assert.equal(localStorage.getItem('dataProvider'), 'IP.SB');
  assert.equal(elements.settingMenu.classList.contains('is-open'), false);
  assert.match(elements.settingsSummaryInline.textContent, /EN/);
  assert.match(elements.settingsSummaryInline.textContent, /Server Resolve/);
  assert.match(elements.settingsSummaryInline.textContent, /125 ms/);
  assert.equal(elements.settingsSummaryPanel.children.length, 7);
  assert.equal(elements.settingsSummaryPanel.children[0].textContent, 'IPV6');
  assert.equal(elements.settingsSummaryPanel.children[1].textContent, 'UDP');
}

async function checkSettingsValidation() {
  const harness = createBrowserHarness({ console: quietConsole });
  const { localStorage, elements } = harness;

  elements.settingBtn.click();
  elements.devInput.value = 'en0;';
  elements.saveBtn.click();
  await harness.flushPromises();

  assert.equal(elements.devError.style.display, 'inline');
  assert.equal(elements.devInput.value, '');
  assert.equal(localStorage.getItem('device'), null);
  assert.equal(elements.settingMenu.classList.contains('is-open'), true);

  elements.devInput.value = 'en0';
  elements.dataProvider.value = 'not-valid';
  elements.saveBtn.click();
  await harness.flushPromises();

  assert.equal(elements.dpError.style.display, 'inline');
  assert.equal(elements.dataProvider.value, '');
  assert.equal(localStorage.getItem('dataProvider'), null);
  assert.equal(elements.settingMenu.classList.contains('is-open'), true);
}

async function checkPrimaryControls() {
  const harness = createBrowserHarness({ console: quietConsole });
  const { socket, elements } = harness;

  assert.equal(elements.startBtn.disabled, true);

  elements.examples[5].click();
  assert.equal(elements.params.value, 'github.com');
  assert.equal(elements.startBtn.disabled, false);
  assert.equal(elements.shareBtn.disabled, false);

  elements.params.value = '1.1.1.1';
  harness.dispatchInput(elements.params);
  elements.startBtn.click();
  await harness.flushPromises();

  assert.deepEqual(
    socket.emitted.slice(0, 2).map((packet) => packet.name),
    ['stop_nexttrace', 'start_nexttrace']
  );
  assert.equal(socket.emitted[1].payload.ip, '1.1.1.1');
  assert.ok(elements.recentQueries.children.length >= 1);

  socket.trigger('mtr_raw', { ttl: 1, success: true, ip: '1.1.1.1', rtt_ms: 1.2 });
  await delay(140);
  elements.stopBtn.click();

  assert.match(elements.taskStatusBadge.textContent, /complete/i);
  assert.match(elements.noticeBanner.textContent, /retained/i);

  elements.params.value = '';
  harness.dispatchInput(elements.params);
  elements.recentQueries.children[0].click();
  assert.equal(elements.params.value, '1.1.1.1');

  elements.resetBtn.click();
  assert.equal(elements.params.value, '');
  assert.equal(elements.startBtn.disabled, true);
  assert.equal(elements.noticeBanner.hidden, true);
  assert.ok(elements.tbody.innerHTML.includes('<th>HOP</th>'));
}

async function checkShareControl() {
  const harness = createBrowserHarness({
    console: quietConsole,
    url: 'https://trace.example/tool'
  });
  const { clipboardWrites, elements } = harness;

  elements.params.value = 'example.com';
  harness.dispatchInput(elements.params);
  elements.shareBtn.click();
  await harness.flushPromises();

  assert.deepEqual(clipboardWrites, ['https://trace.example/tool?trace=example.com']);
  assert.equal(elements.shareBtn.textContent, 'Link Copied');
  assert.match(elements.noticeBanner.textContent, /copied/i);
}

async function checkIpSelectorControl() {
  const harness = createBrowserHarness({ console: quietConsole });
  const { socket, document, elements } = harness;

  socket.trigger('nexttrace_options', ['1.1.1.1', '1.0.0.1']);
  assert.equal(elements.ipSelector.classList.contains('is-open'), true);
  assert.equal(elements.ipList.children.length, 2);

  elements.ipList.children[1].click();
  assert.equal(socket.emitted.at(-1).name, 'nexttrace_options_choice');
  assert.equal(socket.emitted.at(-1).payload.choice, 2);
  assert.equal(elements.ipSelector.classList.contains('is-open'), false);

  socket.trigger('nexttrace_options', ['9.9.9.9']);
  harness.dispatchKeydown(document, 'Escape');
  await harness.flushPromises();
  assert.equal(elements.ipSelector.classList.contains('is-open'), false);
  assert.match(elements.noticeBanner.textContent, /cancelled/i);
}

async function checkTraceQueryAutostart() {
  const harness = createBrowserHarness({
    console: quietConsole,
    url: 'https://trace.example/?trace=8.8.8.8',
    storage: {
      language: 'en',
      ipVersion: 'ipv4',
      protocol: 'tcp',
      localResolve: 'false'
    }
  });
  const { socket, elements } = harness;

  await harness.dispatchDOMContentLoaded();
  await harness.flushPromises();

  assert.equal(elements.params.value, '8.8.8.8');
  assert.equal(elements.ipVersion.value, 'ipv4');
  assert.equal(elements.protocol.value, 'tcp');
  assert.equal(socket.emitted.some((packet) => packet.name === 'start_nexttrace'), true);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
