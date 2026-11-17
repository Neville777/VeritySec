const test = require('node:test');
const assert = require('node:assert/strict');
const client = require('./workflow-package-client.js');

test('id conflicts by default only allow keep, local overwrite, or save as', () => {
    assert.deepEqual(client.allowedActions('id_conflict'), ['keep_existing', 'overwrite', 'rename']);
    assert.deepEqual(client.allowedActions('identical'), ['keep_existing']);
    assert.deepEqual(client.allowedActions('none'), ['create']);
});

test('overwrite import requests must include confirmation and an empty new ID', () => {
    assert.deepEqual(client.buildImportRequest({
        inspectionId: 'wpi_1',
        action: 'overwrite',
        newWorkflowId: '',
        confirmOverwrite: true
    }), {
        inspection_id: 'wpi_1',
        resolution: { action: 'overwrite', new_workflow_id: '' },
        confirm_overwrite: true
    });
});

test('preflight is sent as a multipart file request and preserves the API response body', async () => {
    let observed;
    const apiFetch = async (url, options) => {
        observed = { url, options };
        return new Response(JSON.stringify({ inspection: { id: 'wpi_1', status: 'ready' } }), { status: 201 });
    };
    const data = await client.createInspection(apiFetch, new Blob(['zip']));
    assert.equal(observed.url, '/api/workflow-package-inspections');
    assert.equal(observed.options.method, 'POST');
    assert.equal(observed.options.body instanceof FormData, true);
    assert.equal(data.inspection.id, 'wpi_1');
});

test('import sends a canonical request body with a stable idempotency key', async () => {
    let observed;
    const apiFetch = async (url, options) => {
        observed = { url, options };
        return new Response(JSON.stringify({ import: { id: 'wpii_1', status: 'succeeded' } }), { status: 201 });
    };
    const request = client.buildImportRequest({
        inspectionId: 'wpi_1', action: 'keep_existing', newWorkflowId: '', confirmOverwrite: false
    });
    const data = await client.applyImport(apiFetch, request, 'f1d13d55-c35d-4693-b507-d2e2ea5703f9');
    assert.equal(observed.url, '/api/workflow-package-imports');
    assert.equal(observed.options.headers['Idempotency-Key'], 'f1d13d55-c35d-4693-b507-d2e2ea5703f9');
    assert.deepEqual(JSON.parse(observed.options.body), request);
    assert.equal(data.import.id, 'wpii_1');
});
