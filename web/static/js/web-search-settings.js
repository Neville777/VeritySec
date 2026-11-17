/**
 * Settings → Web search: provider keys, order, enable switches, and tests.
 * Keys are sent to the server once and never displayed again; only a masked tail is shown.
 */
let webSearchProviders = [];

async function loadWebSearchProviders() {
    const box = document.getElementById('websearch-providers');
    if (!box) return;
    box.innerHTML = '<div class="tinst-empty">Loading providers…</div>';
    try {
        const r = await apiFetch('/api/web-search/providers');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        webSearchProviders = data.providers || [];
        renderWebSearchProviders();
    } catch (err) {
        box.innerHTML = `<div class="tinst-empty">Could not load providers: ${escapeHtml(err.message)}</div>`;
    }
}

function renderWebSearchProviders() {
    const box = document.getElementById('websearch-providers');
    if (!box) return;
    box.innerHTML = webSearchProviders.map(p => {
        const id = escapeHtml(p.id);
        const keyField = p.needKey
            ? `<label class="websearch-field">
                  <span>API key${p.hasKey ? ` <small class="websearch-masked">saved ${escapeHtml(p.keyMasked)}</small>` : ' <small>not set</small>'}</span>
                  <input type="password" autocomplete="off" id="ws-key-${id}" placeholder="${p.hasKey ? 'Leave blank to keep the saved key' : 'Paste API key'}">
               </label>`
            : '';
        const actions = p.needKey
            ? `<button class="btn-primary" onclick="saveWebSearchProvider('${id}')">Save</button>
               <button class="btn-secondary" onclick="testWebSearchProvider('${id}')">Test</button>`
            : `<button class="btn-primary" onclick="saveWebSearchProvider('${id}')">Save</button>`;
        return `<article class="tinst-card websearch-card" data-provider="${id}">
            <div class="tinst-card-head">
                <span class="tinst-name">${escapeHtml(p.name)}</span>
                <label class="websearch-toggle"><input type="checkbox" id="ws-enabled-${id}" ${p.enabled ? 'checked' : ''}> ${['browser', 'firecrawl', 'playwright'].includes(p.id) ? 'On' : 'Enabled'}</label>
            </div>
            <div class="tinst-meta"><span class="tinst-badge">order ${p.order}</span>${p.hint ? `<span>${escapeHtml(p.hint)}</span>` : ''}</div>
            ${keyField}
            <label class="websearch-field websearch-order"><span>Order</span>
                <input type="number" min="1" max="99" id="ws-order-${id}" value="${p.order}">
            </label>
            <div class="tinst-actions">${actions}<span class="tinst-job" id="ws-status-${id}"></span></div>
        </article>`;
    }).join('');
}

async function saveWebSearchProvider(id) {
    const status = document.getElementById(`ws-status-${id}`);
    const enabled = document.getElementById(`ws-enabled-${id}`)?.checked;
    const order = parseInt(document.getElementById(`ws-order-${id}`)?.value || '', 10);
    const keyInput = document.getElementById(`ws-key-${id}`);
    const body = { enabled: !!enabled };
    if (!Number.isNaN(order)) body.order = order;
    if (keyInput && keyInput.value.trim() !== '') body.key = keyInput.value.trim();
    try {
        const r = await apiFetch(`/api/web-search/providers/${encodeURIComponent(id)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
        if (keyInput) keyInput.value = '';
        if (status) status.textContent = 'Saved';
        await loadWebSearchProviders();
    } catch (err) {
        if (status) status.textContent = `Error: ${err.message}`;
    }
}

async function testWebSearchProvider(id) {
    const status = document.getElementById(`ws-status-${id}`);
    if (status) status.textContent = 'Testing…';
    try {
        const r = await apiFetch(`/api/web-search/providers/${encodeURIComponent(id)}/test`, { method: 'POST' });
        const data = await r.json();
        if (status) status.textContent = data.ok ? 'Works' : `Failed: ${data.error || 'unknown error'}`;
    } catch (err) {
        if (status) status.textContent = `Error: ${err.message}`;
    }
}

// Load the providers the first time the settings section is opened.
document.addEventListener('click', (e) => {
    const item = e.target.closest && e.target.closest('.settings-nav-item[data-section="websearch"]');
    if (item) loadWebSearchProviders();
});
