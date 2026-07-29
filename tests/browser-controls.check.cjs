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
    checkHarnessMirrorsTemplate,
    checkSettingsDrawerControls,
    checkSettingsInputSync,
    checkSettingsPersistenceAndSummary,
    checkSettingsValidation,
    checkPrimaryControls,
    checkShareControl,
    checkIpSelectorControl,
    checkTraceQueryAutostart,
    checkAutomaticLanguageDetection,
    checkLanguageSwitcher,
    checkNoticeFollowsLanguageSwitch,
    checkSubPathDeployment
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

// The harness hand-builds its DOM instead of parsing templates/index.html, so every check
// below would keep passing if an element were dropped from the real page. This ties the two
// together: anything the harness drives must actually exist in the template.
async function checkHarnessMirrorsTemplate() {
  const html = fs.readFileSync(path.join(repoRoot, 'templates/index.html'), 'utf8');
  const templateIds = new Set();
  const idPattern = /id="([^"]+)"/g;
  let match = idPattern.exec(html);

  while (match !== null) {
    templateIds.add(match[1]);
    match = idPattern.exec(html);
  }

  const harness = createBrowserHarness({ console: quietConsole });
  // Containers the harness invents only to parent its fixtures; the real template groups
  // the same elements without needing an id on the wrapper.
  const harnessOnlyContainers = new Set(['appHeader', 'exampleTargets']);
  const missingFromTemplate = Array.from(harness.document.elementsById.keys())
    .filter((id) => !harnessOnlyContainers.has(id) && !templateIds.has(id))
    .sort();

  assert.deepEqual(
    missingFromTemplate,
    [],
    'the harness drives elements the real template does not ship'
  );

  // The language switcher is the newest of these, and its options carry behaviour the id
  // check alone cannot see.
  assert.match(html, /<select id="uiLanguage"/);
  assert.match(html, /<option value="auto"[^>]*data-i18n="language\.auto"/);
  assert.match(html, /<option value="en">English<\/option>/);
  assert.match(html, /<option value="zh">中文<\/option>/);
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
  const harness = createBrowserHarness({
    console: quietConsole,
    devices: ['en0', 'br-test0']
  });
  const { localStorage, elements } = harness;
  await harness.flushPromises();

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
  assert.equal(elements.devInput.getAttribute('list'), 'deviceOptions');
  assert.equal(elements.deviceOptions.children.length, 2);
  assert.equal(elements.deviceOptions.children[1].value, 'br-test0');
  elements.devInput.value = 'br-test0';
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
  assert.equal(localStorage.getItem('device'), 'br-test0');
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

async function checkAutomaticLanguageDetection() {
  const englishHarness = createBrowserHarness({
    console: quietConsole,
    languages: ['en-GB', 'fr-FR']
  });

  assert.equal(englishHarness.elements.uiLanguage.value, 'auto');
  assert.equal(englishHarness.elements.startBtn.textContent, 'Start');
  assert.equal(englishHarness.localStorage.getItem('uiLanguage'), null);

  const chineseHarness = createBrowserHarness({
    console: quietConsole,
    languages: ['zh-CN', 'en-US']
  });

  assert.equal(chineseHarness.elements.uiLanguage.value, 'auto');
  assert.equal(chineseHarness.elements.startBtn.textContent, '开始');
  assert.equal(chineseHarness.document.documentElement.getAttribute('lang'), 'zh-CN');
  assert.ok(chineseHarness.elements.tbody.innerHTML.includes('<th>跳数</th>'));

  const overriddenHarness = createBrowserHarness({
    console: quietConsole,
    languages: ['zh-CN'],
    storage: { uiLanguage: 'en' }
  });

  assert.equal(overriddenHarness.elements.uiLanguage.value, 'en');
  assert.equal(overriddenHarness.elements.startBtn.textContent, 'Start');
}

async function checkLanguageSwitcher() {
  const harness = createBrowserHarness({ console: quietConsole });
  const { document, localStorage, elements } = harness;

  assert.equal(elements.uiLanguage.value, 'auto');
  assert.equal(elements.startBtn.textContent, 'Start');
  assert.equal(elements.taskStatusBadge.textContent, 'Idle');
  assert.equal(elements.resultStateTitle.textContent, 'Ready for a new trace');
  assert.equal(document.documentElement.getAttribute('lang'), 'en');

  elements.uiLanguage.value = 'zh';
  harness.dispatchChange(elements.uiLanguage);
  await harness.flushPromises();

  assert.equal(localStorage.getItem('uiLanguage'), 'zh');
  assert.equal(document.documentElement.getAttribute('lang'), 'zh-CN');
  assert.equal(elements.startBtn.textContent, '开始');
  assert.equal(elements.stopBtn.textContent, '停止');
  assert.equal(elements.saveBtn.textContent, '保存设置');
  assert.equal(elements.shareBtn.textContent, '复制分享链接');
  assert.equal(elements.params.getAttribute('placeholder'), 'IP / 域名 / URL');
  assert.equal(elements.taskStatusBadge.textContent, '空闲');
  assert.equal(elements.resultStateTitle.textContent, '已就绪，可以开始新的追踪');
  assert.equal(elements.targetSummary.textContent, '未设置');
  assert.equal(elements.resolveModeSummary.textContent, '本地解析');
  assert.match(elements.settingsSummaryInline.textContent, /本地解析/);
  assert.ok(elements.tbody.innerHTML.includes('<th>跳数</th>'));
  assert.equal(elements.tbody.innerHTML.includes('<th>HOP</th>'), false);

  harness.socket.trigger('nexttrace_error', {});
  assert.equal(elements.noticeBanner.textContent, '任务执行失败。');
  assert.equal(elements.taskStatusBadge.textContent, '出错');

  harness.socket.trigger('disconnect');
  assert.equal(elements.taskStatusBadge.textContent, '已断开');
  assert.match(elements.noticeBanner.textContent, /连接已断开/);
  assert.equal(elements.connectionSummary.textContent, '已断开');

  elements.uiLanguage.value = 'auto';
  harness.dispatchChange(elements.uiLanguage);
  await harness.flushPromises();

  assert.equal(localStorage.getItem('uiLanguage'), 'auto');
  assert.equal(elements.startBtn.textContent, 'Start');
  assert.equal(elements.taskStatusBadge.textContent, 'Disconnected');
  assert.ok(elements.tbody.innerHTML.includes('<th>HOP</th>'));
}

async function checkNoticeFollowsLanguageSwitch() {
  const harness = createBrowserHarness({ console: quietConsole });
  const { elements } = harness;

  // nexttrace's own diagnostic output has no translation key and must survive verbatim.
  harness.socket.trigger('nexttrace_error', {
    code: 'nexttrace_exit_nonzero',
    message: 'nexttrace: operation not permitted'
  });
  assert.equal(elements.noticeBanner.textContent, 'nexttrace: operation not permitted');
  assert.equal(elements.taskStatusBadge.textContent, 'Error');

  elements.uiLanguage.value = 'zh';
  harness.dispatchChange(elements.uiLanguage);
  await harness.flushPromises();

  assert.equal(elements.noticeBanner.textContent, 'nexttrace: operation not permitted');
  assert.equal(elements.taskStatusBadge.textContent, '出错');

  // A known backend code is replaced with localized copy, not the Chinese server string.
  harness.socket.trigger('nexttrace_error', {
    code: 'trace_rate_limited',
    message: '操作过于频繁，请稍后再试',
    retry_after_seconds: 1
  });
  assert.equal(elements.noticeBanner.textContent, '操作过于频繁，请稍后再试。');

  elements.uiLanguage.value = 'en';
  harness.dispatchChange(elements.uiLanguage);
  await harness.flushPromises();

  assert.match(elements.noticeBanner.textContent, /Too many requests/);

  elements.uiLanguage.value = 'zh';
  harness.dispatchChange(elements.uiLanguage);
  await harness.flushPromises();

  // A keyed notice re-renders in whichever language is active.
  harness.socket.trigger('nexttrace_error', {});
  assert.equal(elements.noticeBanner.textContent, '任务执行失败。');

  elements.uiLanguage.value = 'en';
  harness.dispatchChange(elements.uiLanguage);
  await harness.flushPromises();

  assert.equal(elements.noticeBanner.textContent, 'The trace task failed.');

  // The regression this guards: a notice raised while English must turn Chinese on switch,
  // so the banner state cannot hold already-translated text.
  harness.socket.trigger('disconnect');
  assert.match(elements.noticeBanner.textContent, /Connection to the trace service was lost/);

  elements.uiLanguage.value = 'zh';
  harness.dispatchChange(elements.uiLanguage);
  await harness.flushPromises();

  assert.match(elements.noticeBanner.textContent, /与追踪服务的连接已断开/);
  assert.equal(elements.taskStatusBadge.textContent, '已断开');
}

async function checkSubPathDeployment() {
  const requestedUrls = [];
  const harness = createBrowserHarness({
    console: quietConsole,
    url: 'https://trace.example/tools/nexttrace/',
    fetch(url) {
      requestedUrls.push(url);
      return Promise.resolve({
        ok: true,
        json() {
          return Promise.resolve({ devices: ['en0'], count: 1 });
        }
      });
    }
  });
  await harness.flushPromises();

  assert.deepEqual(requestedUrls, ['/tools/nexttrace/api/devices']);
  assert.equal(harness.socketConnections.length, 1);
  assert.equal(harness.socketConnections[0].options.path, '/tools/nexttrace/socket.io');

  const rootHarness = createBrowserHarness({ console: quietConsole });
  assert.equal(rootHarness.socketConnections[0].options.path, '/socket.io');

  harness.elements.params.value = 'example.com';
  harness.dispatchInput(harness.elements.params);
  harness.elements.shareBtn.click();
  await harness.flushPromises();

  assert.deepEqual(harness.clipboardWrites, [
    'https://trace.example/tools/nexttrace/?trace=example.com'
  ]);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
