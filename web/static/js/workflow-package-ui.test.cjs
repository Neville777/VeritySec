const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

test('workflow provides import, export and overwrite confirmation containers', () => {
    const html = fs.readFileSync('web/templates/index.html', 'utf8');
    assert.match(html, /onclick="openWorkflowPackageImportModal\(\)"/);
    assert.match(html, /onclick="[^"]*exportCurrentWorkflowPackage\(\)"/);
    assert.match(html, /id="workflow-package-import-modal"/);
    assert.match(html, /id="workflow-package-overwrite-modal"/);
    // zh-CN removed
});

test('local package upload supports drag-and-drop, keyboard selection and selected-file feedback', () => {
    const html = fs.readFileSync('web/templates/index.html', 'utf8');
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const css = fs.readFileSync('web/static/css/style.css', 'utf8');
    assert.match(html, /id="workflow-package-dropzone"[\s\S]*?ondrop="onWorkflowPackageDrop\(event\)"/);
    assert.match(html, /onkeydown="onWorkflowPackageDropzoneKeydown\(event\)"/);
    assert.match(html, /id="workflow-package-selected-file"/);
    assert.match(workflows, /window\.onWorkflowPackageDrop = function \(event\)/);
    assert.match(workflows, /endsWith\('\.csapkg\.zip'\)/);
    assert.match(css, /\.workflow-package-dropzone\.is-dragging/);
});

test('workflow script invokes all package contract endpoints and conflict error codes', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const client = fs.readFileSync('web/static/js/workflow-package-client.js', 'utf8');
    assert.match(workflows, /\/api\/workflows\/\$\{encodeURIComponent\(id\)\}\/package/);
    assert.match(client, /\/api\/workflow-package-inspections/);
    assert.match(client, /\/api\/workflow-package-imports/);
    assert.match(workflows, /WFPKG_CONFLICT_CHANGED/);
    assert.match(workflows, /WFPKG_INSPECTION_EXPIRED/);
});

test('pre-check invalid package contract error codes all have localized status branches', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    [
        'WFPKG_INVALID_ARCHIVE',
        'WFPKG_UNSUPPORTED_FORMAT',
        'WFPKG_INVALID_MANIFEST',
        'WFPKG_CHECKSUM_MISMATCH',
        'WFPKG_MULTIPLE_WORKFLOWS',
        'WFPKG_WORKFLOW_INVALID'
    ].forEach((code) => assert.match(workflows, new RegExp(code)));
});

test('import request ID generation failure enters localized error handling', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    assert.match(workflows, /async function performWorkflowPackageImport\(request\)[\s\S]*?try\s*\{[\s\S]*?client\.createIdempotencyKey\(\)[\s\S]*?catch \(error\) \{\s*displayWorkflowPackageError\(error\)/);
});

test('workflow package dynamic status provides both Chinese and English entries', () => {
    const en = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));
    const keys = [
        ['errors', 'invalidArchive'],
        ['conflict', 'idConflict'],
        ['summary', 'workflowName'],
        ['resolution', 'keepExisting'],
        ['result', 'overwritten']
    ];
    keys.forEach(([section, key]) => {
        assert.equal(typeof zh.workflows.package[section][key], 'string');
        assert.equal(typeof en.workflows.package[section][key], 'string');
    });
});

test('language switch refreshes workflow package modal and its dynamic status', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    assert.match(workflows, /function refreshWorkflowsI18n\(\)[\s\S]*?workflow-package-import-modal[\s\S]*?workflow-package-overwrite-modal[\s\S]*?renderWorkflowPackageInspection\(\)[\s\S]*?renderWorkflowPackageResolution\(\)/);
});

test('opening the import dialog starts a new import session each time', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const start = workflows.indexOf('window.openWorkflowPackageImportModal = async function ()');
    const end = workflows.indexOf('window.closeWorkflowPackageImportModal = function ()', start);
    const openHandler = workflows.slice(start, end);
    assert.match(openHandler, /resetWorkflowPackageImport\(\);/);
    assert.doesNotMatch(openHandler, /restoreWorkflowPackageState\(\)/);
});

test('unwritten import results clearly show skip or keep, not import-complete', () => {
    const vm = require('node:vm');
    const source = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const start = source.indexOf('    function renderWorkflowPackageImportResult(');
    const end = source.indexOf('    async function restoreWorkflowPackageState(', start);
    for (const [result, expected] of [['skipped_identical', 'Import skipped'], ['kept_existing', 'Local version kept'], ['created', 'Import complete'], ['overwritten', 'Import complete'], ['renamed', 'Import complete']]) {
        const button = {};
        const c = vm.createContext({ workflowPackageText: (_, fallback) => fallback, renderWorkflowPackageResolution() {}, workflowPackageSubmitBtn: () => button });
        vm.runInContext(source.slice(start, end), c);
        c.renderWorkflowPackageImportResult({ result });
        assert.equal(button.textContent, expected);
        assert.equal(button.disabled, true);
    }
});

test('duplicate package confirm clearly distinguishes skip and keep, create and overwrite entries retain original semantics', () => {
    const vm = require('node:vm');
    const source = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const start = source.indexOf('    function renderWorkflowPackageResolution(');
    const end = source.indexOf('    function resetWorkflowPackageImport(', start);
    for (const [state, action, expected] of [['identical', 'keep_existing', 'Confirm skip import'], ['id_conflict', 'keep_existing', 'Confirm keep local version'], ['none', 'create', 'Confirm create'], ['id_conflict', 'overwrite', 'Continue to confirm overwrite'], ['id_conflict', 'rename', 'Confirm save as']]) {
        const button = {};
        const c = vm.createContext({ workflowPackageState: { inspection: { conflict: { state } }, resolutionAction: action, riskChoicesVisible: true, newWorkflowId: 'copy' }, workflowPackageResolutionEl: () => ({}), workflowPackageSubmitBtn: () => button, workflowPackageClient: () => ({ allowedActions: () => [action] }), workflowPackageText: (_, fallback) => fallback, esc: value => value, workflowPackageResolutionCard: () => '', workflowPackageSetStep() {} });
        vm.runInContext(source.slice(start, end), c);
        c.renderWorkflowPackageResolution();
        assert.equal(button.textContent, expected);
        assert.equal(button.disabled, false);
    }
});
