const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');

function timingSource(source) {
    const start = source.indexOf('function formatAssistantTurnDuration(');
    const end = source.indexOf('window.setAssistantTurnTiming = setAssistantTurnTiming;', start);
    assert.notEqual(start, -1, 'formatAssistantTurnDuration should exist');
    assert.notEqual(end, -1, 'timing exports should exist');
    return source.slice(start, end);
}

function processDetailFilterSource(source) {
    const start = source.indexOf('function isEinoAgentHeartbeatProgress(');
    const end = source.indexOf('function dedupeConsecutiveProcessDetailRows(', start);
    assert.notEqual(start, -1, 'process detail filter should exist');
    assert.notEqual(end, -1, 'dedupe boundary should exist');
    return source.slice(start, end);
}

function createClassList() {
    return {
        toggle() {},
    };
}

function createMessage() {
    const label = {
        innerHTML: '',
        classList: createClassList(),
        setAttribute() {},
    };
    return {
        dataset: {},
        querySelector(selector) {
            if (selector === '.mcp-call-label.turn-process-summary') return label;
            return null;
        },
        label,
    };
}

function createHarness(nowMs) {
    const RealDate = Date;
    class TestDate extends RealDate {
        static now() {
            return nowMs;
        }
    }
    const context = {
        Date: TestDate,
        Number,
        Math,
        String,
        document: {
            querySelector() { return null; },
            querySelectorAll() { return []; },
            getElementById() { return null; },
        },
        window: {},
        escapeHtml(value) { return String(value); },
        setInterval() { return 1; },
        clearInterval() {},
    };
    vm.runInNewContext(
        `${timingSource(chat)}; this.setAssistantTurnTiming = setAssistantTurnTiming; this.setAssistantTurnTokenUsage = setAssistantTurnTokenUsage; this.extractAssistantTurnTokenUsage = extractAssistantTurnTokenUsage;`,
        context
    );
    return context;
}

test('refreshing a running task ignores zero duration in summary and recovers from start time', () => {
    const startedAt = '2026-08-12T02:00:00.000Z';
    const startedMs = Date.parse(startedAt);
    const context = createHarness(startedMs + 65_000);
    const message = createMessage();

    context.setAssistantTurnTiming(message, {
        startedAt,
        durationMs: 0,
        status: 'running',
    });

    assert.equal(message.dataset.turnDurationMs, undefined);
    assert.match(message.label.innerHTML, /Processed 1 min 5 sec/);
});

test('completed tasks still prefer the persisted duration', () => {
    const context = createHarness(Date.parse('2026-08-12T02:05:00.000Z'));
    const message = createMessage();

    context.setAssistantTurnTiming(message, {
        startedAt: '2026-08-12T02:00:00.000Z',
        completedAt: '2026-08-12T02:01:05.000Z',
        durationMs: 65_000,
        status: 'completed',
    });

    assert.equal(message.dataset.turnDurationMs, '65000');
    assert.match(message.label.innerHTML, /Duration 1 min 5 sec/);
});

test('assistant turn summary displays persisted token usage', () => {
    const context = createHarness(Date.parse('2026-08-12T02:05:00.000Z'));
    const message = createMessage();

    context.setAssistantTurnTiming(message, {
        startedAt: '2026-08-12T02:00:00.000Z',
        completedAt: '2026-08-12T02:00:03.000Z',
        durationMs: 3000,
        status: 'completed',
    });
    context.setAssistantTurnTokenUsage(message, {
        promptTokens: 1200,
        completionTokens: 34,
        cachedTokens: 200,
        cacheWriteTokens: 100,
        reasoningTokens: 12,
        modelCalls: 1,
        model: 'deepseek-v3',
    });

    assert.equal(message.dataset.turnTotalTokens, '1234');
    assert.equal(message.dataset.turnCacheWriteTokens, '100');
    assert.match(message.label.innerHTML, /1\.2K tokens/);
    assert.match(message.label.innerHTML, /turn-process-token-chip/);
});

test('assistant turn can extract token usage from Eino usage summary process details', () => {
    const context = createHarness(Date.parse('2026-08-12T02:05:00.000Z'));

    const usage = context.extractAssistantTurnTokenUsage([
        { eventType: 'progress', data: { totalTokens: 9999 } },
        { eventType: 'eino_usage_summary', data: { promptTokens: 400, completionTokens: 100, modelCalls: 1 } },
        { eventType: 'eino_usage_summary', data: { totalTokens: 25, modelCalls: 1 } },
    ]);

    assert.equal(usage.totalTokens, 525);
    assert.equal(usage.promptTokens, 400);
    assert.equal(usage.completionTokens, 100);
    assert.equal(usage.modelCalls, 2);
});

test('interrupted tasks use a fixed final-state duration and no longer grow with current time', () => {
    const context = createHarness(Date.parse('2026-08-13T12:00:00.000Z'));
    const message = createMessage();

    context.setAssistantTurnTiming(message, {
        startedAt: '2026-08-11T09:47:14.000Z',
        completedAt: '2026-08-11T09:51:39.000Z',
        durationMs: 265_000,
        status: 'cancelled',
    });

    assert.equal(message.dataset.turnDurationMs, '265000');
    assert.match(message.label.innerHTML, /Interrupted - Duration 4 min 25 sec/);
    assert.doesNotMatch(message.label.innerHTML, /Processed/);
});

test('historical placeholder messages with a cancel event are no longer judged as running', () => {
    assert.match(chat, /function assistantTurnTerminalState\(processDetails\)/);
    assert.match(chat, /const isRunning = isAssistantPlaceholder && !terminalState/);
    assert.match(chat, /status: status/);
});

test('process details hide Eino internal diagnostics but retain real tool calls', () => {
    const context = {};
    vm.runInNewContext(
        `${processDetailFilterSource(chat)}; this.filterNoiseProcessDetails = filterNoiseProcessDetails;`,
        context
    );

    const filtered = context.filterNoiseProcessDetails([
        {
            eventType: 'tool_call',
            data: {
                toolName: 'task',
                argumentsObj: {
                    _veritysec_model_output_recovery: {
                        reason: 'invalid_tool_arguments_json',
                        repair_attempt: 1,
                    },
                },
            },
        },
        {
            eventType: 'model_output_rejected',
            message: 'Model tool call is incomplete or has unsafe arguments; execution was blocked and a rewrite was requested.',
            data: { reason: 'invalid_tool_arguments_json' },
        },
        {
            eventType: 'progress',
            message: 'Eino TurnLoop persistent multi-turn runtime has taken over the current session.',
            data: { kind: 'turn_loop_takeover' },
        },
        {
            eventType: 'tool_call',
            data: {
                toolName: 'task',
                argumentsObj: { _raw: 'command' },
                arguments: 'command',
            },
        },
        {
            eventType: 'tool_call',
            data: {
                toolName: 'task',
                argumentsObj: { _raw: '"' },
                arguments: '"',
            },
        },
        {
            eventType: 'tool_call',
            data: {
                toolName: 'exec',
                arguments: '{"command":"ls"}',
            },
        },
    ]);

    assert.equal(filtered.length, 1);
    assert.equal(filtered[0].data.toolName, 'exec');
});
