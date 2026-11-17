const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const { deriveProgress, applyTaskUpdate } = require('./chat-plan-progress.js');

test('task progress locates in-progress step first and retains completed items', () => {
    const progress = deriveProgress([
        { id: '1', subject: 'Gather requirements', status: 'completed' },
        { id: '2', subject: 'Build component', activeForm: 'Building component', status: 'in_progress' },
        { id: '3', subject: 'Browser verification', status: 'pending' }
    ]);
    assert.equal(progress.activeStep, 2);
    assert.equal(progress.completed, 1);
    assert.equal(progress.total, 3);
    assert.equal(progress.allCompleted, false);
});

test('task update checks off immediately on success, final step shows all completed', () => {
    const initial = [
        { id: '1', subject: 'API', status: 'completed' },
        { id: '2', subject: 'UI', status: 'in_progress' }
    ];
    const updated = applyTaskUpdate(initial, { taskId: '2', status: 'completed' });
    const progress = deriveProgress(updated);
    assert.equal(progress.activeStep, 2);
    assert.equal(progress.completed, 2);
    assert.equal(progress.allCompleted, true);
});

test('deleted tasks do not appear in the hover list', () => {
    const tasks = applyTaskUpdate([
        { id: '1', subject: 'Keep', status: 'pending' },
        { id: '2', subject: 'Delete', status: 'pending' }
    ], { taskId: '2', status: 'deleted' });
    assert.deepEqual(tasks.map((task) => task.id), ['1']);
});

test('task progress styles follow system theme variables instead of hardcoded dark colors', () => {
    const css = fs.readFileSync('web/static/css/chat-plan-progress.css', 'utf8');
    assert.match(css, /--agent-plan-surface:\s*var\(--card-bg\)/);
    assert.match(css, /background:\s*var\(--agent-plan-surface\)/);
    assert.match(css, /color:\s*var\(--agent-plan-text\)/);
    assert.doesNotMatch(css, /background:\s*#(?:292929|2b2b2b|303030)/i);
});

test('return-to-latest button and task progress use vertically stacked layout when both visible', () => {
    const css = fs.readFileSync('web/static/css/chat-plan-progress.css', 'utf8');
    const template = fs.readFileSync('web/templates/index.html', 'utf8');
    assert.match(css, /\.chat-return-latest:not\(\[hidden\]\)\s*\+\s*\.agent-plan-progress:not\(\[hidden\]\)/);
    assert.match(css, /--agent-plan-trigger-bottom:\s*64px/);
    assert.match(css, /--agent-plan-panel-bottom:\s*120px/);
    assert.match(css, /bottom:\s*var\(--agent-plan-trigger-bottom\)/);
    assert.match(css, /bottom:\s*var\(--agent-plan-panel-bottom\)/);
    assert.match(template, /<button[^>]+id="chat-return-latest"[\s\S]*?<\/button>\s*<div id="agent-plan-progress"/);
});

test('plan details expand only on real mouse movement or explicit action', () => {
    const css = fs.readFileSync('web/static/css/chat-plan-progress.css', 'utf8');
    const source = fs.readFileSync('web/static/js/chat-plan-progress.js', 'utf8');
    assert.doesNotMatch(css, /\.agent-plan-progress:hover\s+\.agent-plan-progress-panel/);
    assert.match(css, /\.agent-plan-progress\.is-hover-active\s+\.agent-plan-progress-panel/);
    assert.match(source, /host\.addEventListener\('pointermove',\s*armHoverAfterPointerMove\)/);
    assert.match(source, /returnLatestButton\.addEventListener\('pointerdown',\s*disarmPassiveHover\)/);
    assert.match(source, /passiveHoverAnchor = \{ x: event\.clientX, y: event\.clientY \}/);
    assert.match(source, /event\.clientX === passiveHoverAnchor\.x && event\.clientY === passiveHoverAnchor\.y/);
    assert.match(source, /host\.classList\.remove\('is-hover-active'\)/);
});

test('clears old task cards immediately when server reports tasks stopped', () => {
    const source = fs.readFileSync('web/static/js/chat-plan-progress.js', 'utf8');
    assert.match(source, /payload && payload\.running === false/);
    assert.match(source, /state\.tasks = \[\][\s\S]{0,160}state\.expanded = false/);
});
