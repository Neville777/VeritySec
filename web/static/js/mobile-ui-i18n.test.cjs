const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

/* Copy-key contract for the mobile injection layer: every i18n key referenced by mobile-ui.js must exist in all three languages,
   otherwise internal key names like "mobile.openNav" would leak to the user on the phone when tapping a switch.
   Traversal scope = propagation scope: every entry point that can write data-i18n must be scanned; missing one entry point would miss a violation. */

const LOCALES = ['zh-CN', 'en-US', 'ru-RU'];
const js = fs.readFileSync('web/static/js/mobile-ui.js', 'utf8');

function lookup(dict, key) {
    return key.split('.').reduce((acc, part) => (acc && typeof acc === 'object' ? acc[part] : undefined), dict);
}

function referencedKeys(source) {
    const patterns = [
        /label\(\s*[A-Za-z_$][\w$]*\s*,\s*'([^']+)'/g,
        /ariaLabel\(\s*[A-Za-z_$][\w$]*\s*,\s*'([^']+)'/g,
        /setAttrI18n\(\s*[A-Za-z_$][\w$]*\s*,\s*'[^']+'\s*,\s*'([^']+)'/g,
        /translate\(\s*'([^']+)'/g,
        /buildSheetItem\(\s*'([^']+)'/g,
        /labelKey:\s*'([^']+)'/g,
    ];
    const keys = new Set();
    for (const re of patterns) {
        let m;
        while ((m = re.exec(source))) keys.add(m[1]);
    }
    return keys;
}

const keys = referencedKeys(js);

test('at least a batch of keys is extracted, to prevent an empty set from passing after the regex entirely fails to match', () => {
    assert.ok(keys.size >= 16, `expected >=20 referenced keys, got ${keys.size}`);
    assert.ok(keys.has('mobile.conversations'), 'tab labels must go through i18n');
});

for (const locale of LOCALES) {
    test(`${locale} covers every key referenced by mobile`, () => {
        const dict = JSON.parse(fs.readFileSync(`web/static/i18n/${locale}.json`, 'utf8'));
        const missing = [...keys].filter(k => typeof lookup(dict, k) !== 'string' || !lookup(dict, k).trim());
        assert.deepEqual(missing, [], `${locale} is missing usable translations: ${missing.join(', ')}`);
    });
}

test('the mobile namespace key sets are identical across all three languages', () => {
    const sets = LOCALES.map(l => Object.keys(JSON.parse(fs.readFileSync(`web/static/i18n/${l}.json`, 'utf8')).mobile).sort());
    assert.deepEqual(sets[1], sets[0], 'en-US and zh-CN key sets differ');
    assert.deepEqual(sets[2], sets[0], 'ru-RU and zh-CN key sets differ');
});

test('interpolated copy keeps its placeholders in all three languages', () => {
    for (const locale of LOCALES) {
        const dict = JSON.parse(fs.readFileSync(`web/static/i18n/${locale}.json`, 'utf8'));
        assert.match(lookup(dict, 'mobile.themeNow'), /\{\{\s*name\s*\}\}/, `${locale}'s themeNow lost {{name}}`);
    }
});

test('language and theme actions reuse existing desktop keys instead of introducing a new set', () => {
    assert.ok(keys.has('header.apiDocs'), 'API Docs should reuse header.apiDocs');
    assert.ok(keys.has('header.github'), 'GitHub should reuse header.github instead of introducing a new key');
    assert.ok(keys.has('nav.dashboard'), 'bottom tabs should reuse the nav.* group names');
});

test('the injection layer no longer retains hard-coded Chinese that would be shown directly to the user', () => {
    /* The criterion is independent of function names: outside the helper section, no API may "bare-write user-visible text".
       Helper section = from the copy comment block to the definition before toast; the four helpers label/translate/setAttrI18n/ariaLabel are all inside. */
    const from = js.indexOf('/* Copy for injected nodes');
    const to = js.indexOf('function toast(msg, ms)');
    assert.ok(from !== -1 && to > from, 'Copy helper section not found; the helpers may have been moved apart or renamed');
    const outside = js.slice(0, from) + js.slice(to);

    const bypasses = [
        /toast\(\s*'[^']*[\u4e00-\u9fff][^']*'/,
        /setAttribute\(\s*'aria-label'\s*,/,
        /setAttribute\(\s*'placeholder'\s*,/,
        /\.placeholder\s*=\s*'[^']*[\u4e00-\u9fff]/,
        /\.textContent\s*=\s*'[^']*[\u4e00-\u9fff]/,
        /el\(\s*'[a-zA-Z]+'\s*,\s*'[^']*'\s*,\s*'[^']*[\u4e00-\u9fff]/,
    ];
    for (const re of bypasses) {
        const hit = outside.match(re);
        assert.equal(hit, null, `bypass of the i18n channel: ${hit && hit[0]}`);
    }
});
