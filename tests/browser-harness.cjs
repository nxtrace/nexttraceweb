const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const repoRoot = path.resolve(__dirname, '..');

class FakeEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = init.bubbles !== undefined ? init.bubbles : true;
    this.cancelBubble = false;
    this.defaultPrevented = false;
    this.detail = init.detail;
    this.key = init.key || '';
    this.target = init.target || null;
    this.currentTarget = null;
  }

  preventDefault() {
    this.defaultPrevented = true;
  }

  stopPropagation() {
    this.cancelBubble = true;
  }
}

class FakeCustomEvent extends FakeEvent {}

class FakeClassList {
  constructor(owner) {
    this.owner = owner;
    this.values = new Set();
  }

  add(...tokens) {
    tokens.forEach((token) => this.values.add(token));
  }

  remove(...tokens) {
    tokens.forEach((token) => this.values.delete(token));
  }

  contains(token) {
    return this.values.has(token);
  }
}

class FakeEventTarget {
  constructor() {
    this.listeners = new Map();
    this.parentNode = null;
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, []);
    }
    this.listeners.get(type).push(listener);
  }

  dispatchEvent(event) {
    if (!event.target) {
      event.target = this;
    }

    let current = this;
    while (current) {
      event.currentTarget = current;
      const listeners = (current.listeners.get(event.type) || []).slice();
      listeners.forEach((listener) => listener.call(current, event));
      if (!event.bubbles || event.cancelBubble) {
        break;
      }
      current = current.parentNode;
    }

    return !event.defaultPrevented;
  }
}

class FakeElement extends FakeEventTarget {
  constructor(document, tagName, id = '') {
    super();
    this.ownerDocument = document;
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.children = [];
    this.attributes = {};
    this.dataset = {};
    this.classList = new FakeClassList(this);
    this.style = {};
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.textContent = '';
    this.type = '';
    this._innerHTML = '';
    this._focused = false;
  }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index !== -1) {
      this.children.splice(index, 1);
      child.parentNode = null;
    }
    return child;
  }

  contains(node) {
    if (!node) {
      return false;
    }
    if (node === this) {
      return true;
    }
    return this.children.some((child) => child.contains(node));
  }

  setAttribute(name, value) {
    const stringValue = String(value);
    this.attributes[name] = stringValue;
    if (name === 'id') {
      this.id = stringValue;
      this.ownerDocument.elementsById.set(stringValue, this);
      return;
    }
    if (name === 'class') {
      this.classList = new FakeClassList(this);
      stringValue.split(/\s+/).filter(Boolean).forEach((token) => this.classList.add(token));
      return;
    }
    if (name.indexOf('data-') === 0) {
      this.dataset[toCamelCase(name.slice(5))] = stringValue;
    }
  }

  getAttribute(name) {
    if (name === 'id') {
      return this.id;
    }
    if (name === 'class') {
      return Array.from(this.classList.values).join(' ');
    }
    if (name.indexOf('data-') === 0) {
      return this.dataset[toCamelCase(name.slice(5))];
    }
    return this.attributes[name];
  }

  focus() {
    this.ownerDocument.activeElement = this;
    this._focused = true;
  }

  click() {
    if (this.disabled) {
      return;
    }
    if (['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA'].includes(this.tagName)) {
      this.focus();
    }
    this.dispatchEvent(new FakeEvent('click'));
  }

  closest(selector) {
    let current = this;
    while (current) {
      if (matchesSelector(current, selector)) {
        return current;
      }
      current = current.parentNode instanceof FakeElement ? current.parentNode : null;
    }
    return null;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  querySelectorAll(selector) {
    const results = [];
    walkChildren(this, (child) => {
      if (matchesSelector(child, selector)) {
        results.push(child);
      }
    });
    return results;
  }

  select() {
    this._selected = true;
  }

  get innerHTML() {
    return this._innerHTML;
  }

  set innerHTML(value) {
    this._innerHTML = String(value);
    this.children = [];
  }
}

class FakeDocument extends FakeEventTarget {
  constructor(url) {
    super();
    this.location = new URL(url);
    this.elementsById = new Map();
    this.documentElement = new FakeElement(this, 'html');
    this.body = new FakeElement(this, 'body');
    this.documentElement.appendChild(this.body);
    this.documentElement.parentNode = this;
    this.body.parentNode = this.documentElement;
    this.activeElement = this.body;
  }

  createElement(tagName) {
    return new FakeElement(this, tagName);
  }

  getElementById(id) {
    return this.elementsById.get(id) || null;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  querySelectorAll(selector) {
    return this.documentElement.querySelectorAll(selector);
  }

  execCommand(command) {
    return command === 'copy';
  }
}

class FakeStorage {
  constructor(initialValues = {}) {
    this.map = new Map();
    Object.entries(initialValues).forEach(([key, value]) => {
      this.setItem(key, value);
    });
  }

  getItem(key) {
    return this.map.has(key) ? this.map.get(key) : null;
  }

  setItem(key, value) {
    this.map.set(String(key), String(value));
  }

  removeItem(key) {
    this.map.delete(String(key));
  }
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_match, char) => char.toUpperCase());
}

function walkChildren(root, visitor) {
  root.children.forEach((child) => {
    visitor(child);
    walkChildren(child, visitor);
  });
}

function matchesSelector(element, selector) {
  if (!(element instanceof FakeElement)) {
    return false;
  }
  if (selector.startsWith('#')) {
    return element.id === selector.slice(1);
  }
  if (selector.startsWith('.')) {
    return element.classList.contains(selector.slice(1));
  }
  const dataSelector = selector.match(/^\[data-([a-z-]+)\]$/);
  if (dataSelector) {
    return Object.prototype.hasOwnProperty.call(element.dataset, toCamelCase(dataSelector[1]));
  }
  return element.tagName.toLowerCase() === selector.toLowerCase();
}

function createSocket() {
  const handlers = new Map();
  return {
    emitted: [],
    on(name, handler) {
      handlers.set(name, handler);
    },
    emit(name, payload) {
      this.emitted.push({ name, payload });
    },
    trigger(name, payload) {
      const handler = handlers.get(name);
      if (handler) {
        handler(payload);
      }
    }
  };
}

function appendElement(document, parent, tagName, id, options = {}) {
  const element = new FakeElement(document, tagName, id);
  if (id) {
    document.elementsById.set(id, element);
  }
  if (options.className) {
    element.setAttribute('class', options.className);
  }
  if (options.value !== undefined) {
    element.value = String(options.value);
  }
  if (options.textContent !== undefined) {
    element.textContent = String(options.textContent);
  }
  if (options.type !== undefined) {
    element.type = options.type;
  }
  if (options.checked !== undefined) {
    element.checked = Boolean(options.checked);
  }
  if (options.hidden !== undefined) {
    element.hidden = Boolean(options.hidden);
  }
  if (options.attributes) {
    Object.entries(options.attributes).forEach(([name, value]) => element.setAttribute(name, value));
  }
  parent.appendChild(element);
  return element;
}

function loadScript(relativePath, context) {
  const scriptPath = path.join(repoRoot, relativePath);
  const source = fs.readFileSync(scriptPath, 'utf8');
  vm.runInNewContext(source, context, { filename: scriptPath });
}

function flushPromises() {
  return new Promise((resolve) => setImmediate(resolve));
}

function createDefaultFetch(devices) {
  const deviceList = Array.isArray(devices) ? devices : ['en0', 'utun0'];
  return function fetch(url) {
    if (url === '/api/devices') {
      return Promise.resolve({
        ok: true,
        json() {
          return Promise.resolve({ devices: deviceList, count: deviceList.length });
        }
      });
    }
    return Promise.reject(new Error(`fetch not mocked for ${url}`));
  };
}

function createBrowserHarness(options = {}) {
  const document = new FakeDocument(options.url || 'https://example.test/');
  const localStorage = new FakeStorage(options.storage || {});
  const socket = createSocket();
  const clipboardWrites = [];
  const consoleObject = options.console || console;
  const windowObject = {
    document,
    localStorage,
    location: document.location,
    navigator: {
      clipboard: {
        writeText(text) {
          clipboardWrites.push(text);
          return Promise.resolve();
        }
      }
    }
  };

  const body = document.body;
  const traceForm = appendElement(document, body, 'form', 'traceForm');
  const params = appendElement(document, traceForm, 'input', 'params', { type: 'text' });
  const ipVersion = appendElement(document, traceForm, 'select', 'ipVersion', { value: 'all' });
  const protocol = appendElement(document, traceForm, 'select', 'protocol', { value: 'icmp' });
  const startBtn = appendElement(document, traceForm, 'button', 'startBtn', { textContent: 'Start' });
  const stopBtn = appendElement(document, traceForm, 'button', 'stopBtn', { textContent: 'Stop' });
  const resetBtn = appendElement(document, traceForm, 'button', 'resetBtn', { textContent: 'Reset' });
  const settingBtn = appendElement(document, traceForm, 'button', 'settingBtn', {
    textContent: 'Settings',
    attributes: {
      'aria-controls': 'settingMenu',
      'aria-expanded': 'false'
    }
  });
  const shareBtn = appendElement(document, traceForm, 'button', 'shareBtn', { textContent: 'Copy Share Link' });

  appendElement(document, traceForm, 'span', 'taskStatusBadge');
  appendElement(document, traceForm, 'p', 'taskStatusDetail');
  appendElement(document, traceForm, 'span', 'targetSummary');
  appendElement(document, traceForm, 'span', 'connectionSummary');
  appendElement(document, traceForm, 'span', 'resolveModeSummary');
  appendElement(document, traceForm, 'span', 'settingsSummaryInline');

  appendElement(document, body, 'div', 'noticeBanner', { hidden: true });
  appendElement(document, body, 'section', 'resultEmptyState', { hidden: false });
  appendElement(document, body, 'h2', 'resultStateTitle');
  appendElement(document, body, 'p', 'resultStateText');

  const output = appendElement(document, body, 'table', 'output');
  const tbody = appendElement(document, output, 'tbody', '');
  const recentQueries = appendElement(document, body, 'div', 'recentQueries', { className: 'chip-list chip-list-empty' });
  const settingsSummaryPanel = appendElement(document, body, 'div', 'settingsSummaryPanel');

  const examples = appendElement(document, body, 'div', 'exampleTargets');
  ['1.1.1.1', '8.8.8.8', 'example.com', 'openai.com', '2606:4700:4700::1111', 'github.com'].forEach((value) => {
    appendElement(document, examples, 'button', '', {
      textContent: value,
      attributes: { 'data-example-query': value }
    });
  });

  const settingsBackdrop = appendElement(document, body, 'div', 'settingsBackdrop', {
    attributes: { 'aria-hidden': 'true' }
  });
  const settingMenu = appendElement(document, body, 'aside', 'settingMenu', {
    attributes: { 'aria-hidden': 'true' },
    className: 'settings-drawer'
  });
  appendElement(document, settingMenu, 'button', 'settingCloseBtn', { textContent: 'x' });
  appendElement(document, settingMenu, 'select', 'language', { value: 'cn' });
  appendElement(document, settingMenu, 'input', 'localResolveCheckbox', { type: 'checkbox', checked: true });
  appendElement(document, settingMenu, 'input', 'intervalTimeRange', { type: 'range', value: '0.040' });
  appendElement(document, settingMenu, 'input', 'intervalTimeInput', { type: 'number', value: '0.040' });
  appendElement(document, settingMenu, 'input', 'packetSizeRange', { type: 'range', value: '52' });
  appendElement(document, settingMenu, 'input', 'packetSizeInput', { type: 'number', value: '52' });
  appendElement(document, settingMenu, 'input', 'maxHopInput', { type: 'number', value: '30' });
  appendElement(document, settingMenu, 'input', 'minHopInput', { type: 'number', value: '1' });
  appendElement(document, settingMenu, 'input', 'portInput', { type: 'number', value: '80' });
  appendElement(document, settingMenu, 'input', 'devInput', {
    type: 'text',
    value: '',
    attributes: { list: 'deviceOptions' }
  });
  appendElement(document, settingMenu, 'datalist', 'deviceOptions');
  appendElement(document, settingMenu, 'span', 'dev-error-message');
  appendElement(document, settingMenu, 'input', 'dataProvider', { type: 'text', value: '' });
  appendElement(document, settingMenu, 'span', 'dp-error-message');
  appendElement(document, settingMenu, 'button', 'saveBtn', { textContent: 'Save Settings' });

  const ipSelector = appendElement(document, body, 'div', 'ipSelector');
  appendElement(document, ipSelector, 'h2', 'ipSelectorTitle');
  appendElement(document, ipSelector, 'button', 'ipSelectorClose', { textContent: 'Close' });
  appendElement(document, ipSelector, 'div', 'ip-list');

  const context = {
    window: windowObject,
    document,
    localStorage,
    navigator: windowObject.navigator,
    location: document.location,
    console: consoleObject,
    setTimeout,
    clearTimeout,
    URL,
    URLSearchParams,
    CustomEvent: FakeCustomEvent,
    Event: FakeEvent,
    fetch: options.fetch || createDefaultFetch(options.devices),
    io: {
      connect() {
        return socket;
      }
    }
  };

  windowObject.window = windowObject;
  windowObject.console = consoleObject;
  windowObject.setTimeout = setTimeout;
  windowObject.clearTimeout = clearTimeout;
  windowObject.URL = URL;
  windowObject.URLSearchParams = URLSearchParams;
  windowObject.CustomEvent = FakeCustomEvent;
  windowObject.Event = FakeEvent;
  windowObject.fetch = context.fetch;
  windowObject.io = context.io;
  windowObject.nextTraceUIState = require(path.join(repoRoot, 'assets/js/ui-state.js'));
  windowObject.nextTraceMTRAgg = require(path.join(repoRoot, 'assets/js/mtr-agg.js'));

  loadScript('assets/js/main.js', context);
  loadScript('assets/js/settingsmenu.js', context);
  socket.trigger('connect');

  return {
    context,
    window: windowObject,
    document,
    socket,
    localStorage,
    clipboardWrites,
    elements: {
      params,
      ipVersion,
      protocol,
      startBtn,
      stopBtn,
      resetBtn,
      settingBtn,
      shareBtn,
      recentQueries,
      settingsSummaryPanel,
      settingsBackdrop,
      settingMenu,
      settingCloseBtn: document.getElementById('settingCloseBtn'),
      language: document.getElementById('language'),
      localResolveCheckbox: document.getElementById('localResolveCheckbox'),
      intervalTimeRange: document.getElementById('intervalTimeRange'),
      intervalTimeInput: document.getElementById('intervalTimeInput'),
      packetSizeRange: document.getElementById('packetSizeRange'),
      packetSizeInput: document.getElementById('packetSizeInput'),
      maxHopInput: document.getElementById('maxHopInput'),
      minHopInput: document.getElementById('minHopInput'),
      portInput: document.getElementById('portInput'),
      devInput: document.getElementById('devInput'),
      deviceOptions: document.getElementById('deviceOptions'),
      devError: document.getElementById('dev-error-message'),
      dataProvider: document.getElementById('dataProvider'),
      dpError: document.getElementById('dp-error-message'),
      saveBtn: document.getElementById('saveBtn'),
      noticeBanner: document.getElementById('noticeBanner'),
      taskStatusBadge: document.getElementById('taskStatusBadge'),
      settingsSummaryInline: document.getElementById('settingsSummaryInline'),
      output,
      tbody,
      ipSelector,
      ipList: document.getElementById('ip-list'),
      ipSelectorClose: document.getElementById('ipSelectorClose'),
      examples: document.querySelectorAll('[data-example-query]')
    },
    dispatchInput(element) {
      element.dispatchEvent(new FakeEvent('input'));
    },
    dispatchChange(element) {
      element.dispatchEvent(new FakeEvent('change'));
    },
    dispatchKeydown(target, key) {
      target.dispatchEvent(new FakeEvent('keydown', { key }));
    },
    dispatchDOMContentLoaded() {
      document.dispatchEvent(new FakeEvent('DOMContentLoaded'));
      return flushPromises();
    },
    flushPromises
  };
}

module.exports = {
  FakeEvent,
  createBrowserHarness,
  flushPromises
};
