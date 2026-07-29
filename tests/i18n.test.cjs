const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const {
  DEFAULT_LOCALE,
  SUPPORTED_LOCALES,
  SUPPORTED_PREFERENCES,
  TABLE_HEADER_KEYS,
  applyDocumentTranslations,
  createTranslator,
  detectLocale,
  getDictionary,
  getHtmlLang,
  getTableHeaderLabels,
  listKeys,
  normalizeLocale,
  normalizePreference,
  translate,
} = require('../assets/js/i18n.js');

const repoRoot = path.resolve(__dirname, '..');

function createStubElement(attributes) {
  return {
    attributes: Object.assign({}, attributes),
    textContent: '',
    getAttribute(name) {
      return this.attributes[name];
    },
    setAttribute(name, value) {
      this.attributes[name] = value;
    }
  };
}

function createStubDocument(elements) {
  return {
    documentElement: createStubElement({}),
    querySelectorAll(selector) {
      const attribute = selector.slice(1, -1);
      return elements.filter((element) =>
        Object.prototype.hasOwnProperty.call(element.attributes, attribute));
    }
  };
}

function collectTemplateKeys() {
  const html = fs.readFileSync(path.join(repoRoot, 'templates/index.html'), 'utf8');
  const pattern = /data-i18n(?:-placeholder|-aria-label|-title)?="([^"]+)"/g;
  const keys = new Set();
  let match = pattern.exec(html);

  while (match !== null) {
    keys.add(match[1]);
    match = pattern.exec(html);
  }

  return keys;
}

test('supported locales and preferences stay in sync', () => {
  assert.deepEqual(SUPPORTED_LOCALES, ['en', 'zh']);
  assert.deepEqual(SUPPORTED_PREFERENCES, ['auto', 'en', 'zh']);
  assert.equal(DEFAULT_LOCALE, 'en');
});

test('locale dictionaries define exactly the same keys', () => {
  const englishKeys = listKeys('en').slice().sort();
  const chineseKeys = listKeys('zh').slice().sort();

  assert.deepEqual(chineseKeys, englishKeys);
});

test('no dictionary entry is blank', () => {
  SUPPORTED_LOCALES.forEach((locale) => {
    const dictionary = getDictionary(locale);
    Object.keys(dictionary).forEach((key) => {
      assert.equal(typeof dictionary[key], 'string', `${locale}.${key} must be a string`);
      assert.notEqual(dictionary[key].trim(), '', `${locale}.${key} must not be blank`);
    });
  });
});

test('normalizeLocale accepts browser tags and the legacy cn value', () => {
  assert.equal(normalizeLocale('cn'), 'zh');
  assert.equal(normalizeLocale('zh'), 'zh');
  assert.equal(normalizeLocale('zh-Hans-CN'), 'zh');
  assert.equal(normalizeLocale('EN'), 'en');
  assert.equal(normalizeLocale('en_GB'), 'en');
  assert.equal(normalizeLocale('de-DE'), null);
  assert.equal(normalizeLocale(''), null);
  assert.equal(normalizeLocale(42), null);
});

test('normalizePreference defaults to auto for unknown or missing values', () => {
  assert.equal(normalizePreference('auto'), 'auto');
  assert.equal(normalizePreference('AUTO'), 'auto');
  assert.equal(normalizePreference('zh-CN'), 'zh');
  assert.equal(normalizePreference('en'), 'en');
  assert.equal(normalizePreference('de'), 'auto');
  assert.equal(normalizePreference(null), 'auto');
  assert.equal(normalizePreference(undefined), 'auto');
});

test('detectLocale honours an explicit preference before browser languages', () => {
  assert.equal(detectLocale('zh', ['en-US']), 'zh');
  assert.equal(detectLocale('en', ['zh-CN']), 'en');
});

test('detectLocale follows the browser when the preference is auto', () => {
  assert.equal(detectLocale('auto', ['zh-CN', 'en-US']), 'zh');
  assert.equal(detectLocale('auto', ['en-US', 'zh-CN']), 'en');
  assert.equal(detectLocale(null, ['de-DE', 'zh-TW']), 'zh');
  assert.equal(detectLocale('auto', 'zh-Hans'), 'zh');
});

test('detectLocale falls back to the default locale without usable candidates', () => {
  assert.equal(detectLocale('auto', []), 'en');
  assert.equal(detectLocale('auto', ['de-DE']), 'en');
  assert.equal(detectLocale(undefined, undefined), 'en');
});

test('translate falls back to English and then to the raw key', () => {
  assert.equal(translate('en', 'action.start'), 'Start');
  assert.equal(translate('zh', 'action.start'), '开始');
  assert.equal(translate('de', 'action.start'), 'Start');
  assert.equal(translate('zh', 'missing.key'), 'missing.key');
  assert.equal(translate('zh', ''), '');
  assert.equal(translate('zh', null), '');
});

test('createTranslator binds a locale', () => {
  assert.equal(createTranslator('zh')('action.stop'), '停止');
  assert.equal(createTranslator('en')('action.stop'), 'Stop');
});

test('getHtmlLang maps locales to document language tags', () => {
  assert.equal(getHtmlLang('en'), 'en');
  assert.equal(getHtmlLang('zh'), 'zh-CN');
  assert.equal(getHtmlLang('de'), 'en');
});

test('getTableHeaderLabels returns one label per column', () => {
  assert.equal(TABLE_HEADER_KEYS.length, 13);
  assert.equal(getTableHeaderLabels('en').length, TABLE_HEADER_KEYS.length);
  assert.deepEqual(getTableHeaderLabels('en').slice(0, 3), ['HOP', 'IP', 'ASN']);
  assert.deepEqual(getTableHeaderLabels('zh').slice(0, 3), ['跳数', 'IP', 'ASN']);
});

test('applyDocumentTranslations rewrites text, attributes, and the html lang', () => {
  const button = createStubElement({ 'data-i18n': 'action.start' });
  const input = createStubElement({ 'data-i18n-placeholder': 'form.target.placeholder' });
  const closeButton = createStubElement({ 'data-i18n-aria-label': 'settings.close' });
  const stubDocument = createStubDocument([button, input, closeButton]);

  const appliedCount = applyDocumentTranslations(stubDocument, 'zh');

  assert.equal(button.textContent, '开始');
  assert.equal(input.getAttribute('placeholder'), 'IP / 域名 / URL');
  assert.equal(closeButton.getAttribute('aria-label'), '关闭设置');
  assert.equal(stubDocument.documentElement.getAttribute('lang'), 'zh-CN');
  assert.equal(appliedCount, 3);
});

test('applyDocumentTranslations tolerates a missing document', () => {
  assert.equal(applyDocumentTranslations(null, 'zh'), 0);
  assert.equal(applyDocumentTranslations({}, 'zh'), 0);
});

test('every data-i18n key in the template exists in both dictionaries', () => {
  const templateKeys = collectTemplateKeys();
  const missing = [];

  assert.ok(templateKeys.size >= 40, `expected an annotated template, found ${templateKeys.size} keys`);

  SUPPORTED_LOCALES.forEach((locale) => {
    const dictionary = getDictionary(locale);
    templateKeys.forEach((key) => {
      if (!Object.prototype.hasOwnProperty.call(dictionary, key)) {
        missing.push(`${locale}: ${key}`);
      }
    });
  });

  assert.deepEqual(missing, []);
});

// The template scan below only covers data-i18n markup. These keys live in JS: main.js
// passes them to t(), ui-state.js returns them bare. A typo in either renders the raw key.
test('every translation key used by the browser scripts exists in the dictionaries', () => {
  const dictionary = getDictionary('en');
  const namespaces = Array.from(new Set(listKeys('en').map((key) => key.split('.')[0])));
  const namespacePattern = new RegExp(`'((?:${namespaces.join('|')})\\.[A-Za-z0-9_.]+)'`, 'g');
  const unknown = [];
  let inspectedCount = 0;

  ['assets/js/main.js', 'assets/js/ui-state.js', 'assets/js/settingsmenu.js'].forEach((relativePath) => {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');

    [/\bt\('([^']*)'\)/g, namespacePattern].forEach((pattern) => {
      pattern.lastIndex = 0;
      let match = pattern.exec(source);
      while (match !== null) {
        inspectedCount += 1;
        if (!Object.prototype.hasOwnProperty.call(dictionary, match[1])) {
          unknown.push(`${relativePath}: ${match[1]}`);
        }
        match = pattern.exec(source);
      }
    });
  });

  assert.ok(inspectedCount >= 30, `expected to find the in-script keys, inspected ${inspectedCount}`);
  assert.deepEqual(unknown, []);
});

test('every backend error code is either localized or deliberately passed through', () => {
  const appSource = fs.readFileSync(path.join(repoRoot, 'app.py'), 'utf8');
  const codePattern = /(?:PayloadError\(\s*|emit_error\(\s*|emit_nexttrace_error\([^,]+,\s*)"([a-z_]+)"/g;
  const codes = new Set();
  let match = codePattern.exec(appSource);

  while (match !== null) {
    codes.add(match[1]);
    match = codePattern.exec(appSource);
  }

  // These two put nexttrace's own stdout/stderr in `message`; translating them would
  // discard the diagnostic, so main.js shows them verbatim on purpose.
  const passthroughCodes = new Set(['nexttrace_exit_nonzero', 'nexttrace_invalid_args']);
  const dictionary = getDictionary('en');

  assert.ok(codes.size >= 8, `expected to find the backend error codes, found ${codes.size}`);

  const unhandled = Array.from(codes).filter((code) =>
    !passthroughCodes.has(code) &&
    !Object.prototype.hasOwnProperty.call(dictionary, `serverError.${code}`)).sort();

  assert.deepEqual(unhandled, []);
});

test('the template ships the English copy that matches the dictionary defaults', () => {
  const html = fs.readFileSync(path.join(repoRoot, 'templates/index.html'), 'utf8');
  const pattern = /data-i18n="([^"]+)"[^>]*>([^<]*)</g;
  const dictionary = getDictionary('en');
  const mismatched = [];
  let match = pattern.exec(html);

  while (match !== null) {
    const key = match[1];
    const markupCopy = match[2].trim();
    if (markupCopy !== '' && dictionary[key] !== markupCopy) {
      mismatched.push(`${key}: ${JSON.stringify(markupCopy)} != ${JSON.stringify(dictionary[key])}`);
    }
    match = pattern.exec(html);
  }

  assert.deepEqual(mismatched, []);
});
