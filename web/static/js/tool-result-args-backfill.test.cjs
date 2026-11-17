const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

test('tool_result backfills empty arguments when merged back into tool call card', () => {
    const source = fs.readFileSync('web/static/js/monitor.js', 'utf8');
    assert.match(source, /function toolCallArgsEmpty\(args\)/);
    assert.match(source, /const resultArgs = parseToolCallArgsFromData\(data\);/);
    assert.match(source, /toolCallArgsEmpty\(state\.args\) && !toolCallArgsEmpty\(resultArgs\)/);
    assert.match(source, /state\.args = resultArgs;/);
});

test('historical process_details merge also backfills tool_call arguments from tool_result', () => {
    const source = fs.readFileSync('web/static/js/monitor.js', 'utf8');
    assert.match(source, /function absorbResult\(targetDetail, resultDetail\)/);
    assert.match(source, /targetDetail\.data\.argumentsObj = resultArgs;/);
    assert.match(source, /targetDetail\.data\.arguments = JSON\.stringify\(resultArgs\);/);
});

test('multiple calls with same toolCallId merge results in FIFO order to avoid later overwrite causing missing records', () => {
    const source = fs.readFileSync('web/static/js/monitor.js', 'utf8');
    assert.match(source, /list\.push\(copy\)/);
    assert.match(source, /const candidate = list\.shift\(\)/);
    assert.match(source, /callName === resultName/);
});
