const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const { joinBasePath, resolveBasePath } = require('../assets/js/paths.js');

const repoRoot = path.resolve(__dirname, '..');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test('resolveBasePath keeps the directory portion of the current path', () => {
  assert.equal(resolveBasePath('/'), '/');
  assert.equal(resolveBasePath('/trace/'), '/trace/');
  assert.equal(resolveBasePath('/a/b/'), '/a/b/');
  assert.equal(resolveBasePath('/trace/index.html'), '/trace/');
});

test('resolveBasePath drops the trailing segment of a file-like path', () => {
  assert.equal(resolveBasePath('/trace'), '/');
  assert.equal(resolveBasePath('/a/b'), '/a/');
});

test('resolveBasePath ignores the query string and fragment', () => {
  assert.equal(resolveBasePath('/trace/?trace=1.1.1.1'), '/trace/');
  assert.equal(resolveBasePath('/trace/#hash'), '/trace/');
});

test('resolveBasePath normalizes missing or relative input', () => {
  assert.equal(resolveBasePath(''), '/');
  assert.equal(resolveBasePath(undefined), '/');
  assert.equal(resolveBasePath(null), '/');
  assert.equal(resolveBasePath('trace/'), '/trace/');
});

test('joinBasePath builds sub-path aware endpoints', () => {
  assert.equal(joinBasePath('/', 'socket.io'), '/socket.io');
  assert.equal(joinBasePath('/', 'api/devices'), '/api/devices');
  assert.equal(joinBasePath('/trace/', 'socket.io'), '/trace/socket.io');
  assert.equal(joinBasePath('/trace/', 'api/devices'), '/trace/api/devices');
  assert.equal(joinBasePath('/trace/', '/api/devices'), '/trace/api/devices');
  assert.equal(joinBasePath('/trace/', ''), '/trace/');
  assert.equal(joinBasePath('/trace/', undefined), '/trace/');
});

test('documented sub-path redirects preserve query strings', () => {
  ['README.md', 'README.zh-CN.md'].forEach((relativePath) => {
    const readme = readRepoFile(relativePath);
    const locationBlock = readme.match(/location = \/tools\/nexttrace\s*\{([\s\S]*?)\}/);

    assert.ok(locationBlock, `${relativePath} should document the no-slash redirect`);
    assert.match(
      locationBlock[1],
      /^\s*return 301 \/tools\/nexttrace\/\$is_args\$args;\s*$/m,
      `${relativePath} should preserve the original query string`
    );
  });
});

test('the template references every asset with a relative path', () => {
  const html = readRepoFile('templates/index.html');
  const referencePattern = /(?:src|href)="([^"]+)"/g;
  const rootRelative = [];
  let match = referencePattern.exec(html);

  while (match !== null) {
    const reference = match[1];
    if (reference.startsWith('/')) {
      rootRelative.push(reference);
    }
    match = referencePattern.exec(html);
  }

  assert.deepEqual(rootRelative, []);
  assert.ok(html.includes('href="assets/css/m.css"'));
  assert.ok(html.includes('src="assets/js/main.js"'));
});

test('the stylesheet resolves its font relative to itself', () => {
  const css = readRepoFile('assets/css/m.css');

  assert.ok(css.includes('url(../font/roboto-mono-latin.woff2)'));
  assert.equal(/url\(\/\S/.test(css), false, 'no stylesheet url() may start at the site root');
});

// The regex scans above only prove the absence of a leading slash. These two resolve the
// references the way a browser does, so they also prove the references land somewhere real.
test('template asset references resolve under both root and sub-path deployments', () => {
  const html = readRepoFile('templates/index.html');
  const pattern = /(?:src|href)="([^"]+)"/g;
  const references = [];
  let match = pattern.exec(html);

  while (match !== null) {
    if (!match[1].startsWith('data:')) {
      references.push(match[1]);
    }
    match = pattern.exec(html);
  }

  assert.ok(references.length >= 7, `expected the asset references, found ${references.length}`);

  references.forEach((reference) => {
    assert.equal(
      new URL(reference, 'https://example.com/tools/nexttrace/').href,
      `https://example.com/tools/nexttrace/${reference}`
    );
    assert.equal(
      new URL(reference, 'https://example.com/').href,
      `https://example.com/${reference}`
    );
  });
});

// A relative reference passes the scans above even when it points at nothing, and a
// missing script leaves its global undefined and breaks the page on load.
test('every template asset reference points at a file that exists', () => {
  const html = readRepoFile('templates/index.html');
  const pattern = /(?:src|href)="([^"]+)"/g;
  const missing = [];
  let referenceCount = 0;
  let match = pattern.exec(html);

  while (match !== null) {
    const reference = match[1];
    if (!reference.startsWith('data:')) {
      referenceCount += 1;
      if (!fs.existsSync(path.join(repoRoot, reference))) {
        missing.push(reference);
      }
    }
    match = pattern.exec(html);
  }

  assert.ok(referenceCount >= 7, `expected the asset references, found ${referenceCount}`);
  assert.deepEqual(missing, []);
});

test('every script the page needs at parse time is loaded before its consumers', () => {
  const html = readRepoFile('templates/index.html');
  const scriptPattern = /<script src="([^"]+)"/g;
  const order = [];
  let match = scriptPattern.exec(html);

  while (match !== null) {
    order.push(match[1]);
    match = scriptPattern.exec(html);
  }

  // main.js reads window.nextTracePaths/nextTraceI18n/nextTraceMTRAgg/nextTraceUIState at
  // its top level, and settingsmenu.js reads window.nextTracePaths, so both must come last.
  const providers = [
    'assets/js/socket.io.js',
    'assets/js/paths.js',
    'assets/js/i18n.js',
    'assets/js/mtr-agg.js',
    'assets/js/ui-state.js'
  ];

  providers.forEach((provider) => {
    const providerIndex = order.indexOf(provider);
    assert.notEqual(providerIndex, -1, `${provider} should be loaded by the template`);
    assert.ok(
      providerIndex < order.indexOf('assets/js/main.js'),
      `${provider} must load before main.js`
    );
    assert.ok(
      providerIndex < order.indexOf('assets/js/settingsmenu.js'),
      `${provider} must load before settingsmenu.js`
    );
  });
});

test('the stylesheet font url resolves next to the stylesheet, not at the site root', () => {
  const css = readRepoFile('assets/css/m.css');
  const fontMatch = css.match(/url\(([^)]+)\)/);

  assert.ok(fontMatch, 'the stylesheet should declare a font url');
  assert.equal(
    new URL(fontMatch[1], 'https://example.com/tools/nexttrace/assets/css/m.css').href,
    'https://example.com/tools/nexttrace/assets/font/roboto-mono-latin.woff2'
  );
});

test('browser scripts do not hardcode root-anchored endpoints', () => {
  ['assets/js/main.js', 'assets/js/settingsmenu.js', 'assets/js/ui-state.js', 'assets/js/i18n.js']
    .forEach((relativePath) => {
      const source = readRepoFile(relativePath);
      assert.equal(
        /['"]\/(?:assets|api|socket\.io)\//.test(source),
        false,
        `${relativePath} must build request paths from the current base path`
      );
    });
});
