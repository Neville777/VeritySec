/**
 * Engagements page: list, create, detail tabs (overview, conversations, evidence,
 * findings, assets, report). Uses apiFetch from auth.js; reuses the mcp-tab and
 * tinst-* styles.
 */

let engagementRows = [];
let currentEngagement = null;
let engagementEvidence = [];
let engagementStages = [];

function engEsc(v) {
    return escapeHtml(v == null ? '' : String(v));
}

function engNotify(msg, type) {
    if (typeof showNotification === 'function') showNotification(msg, type || 'info');
}

function engDate(v) {
    if (!v) return '';
    const d = new Date(v);
    return isNaN(d.getTime()) ? String(v) : d.toLocaleString();
}

async function engJson(url, options) {
    const r = await apiFetch(url, options);
    let data = null;
    try { data = await r.json(); } catch (_) { data = null; }
    if (!r.ok) {
        const err = new Error((data && data.error) || `HTTP ${r.status}`);
        err.status = r.status;
        err.data = data;
        throw err;
    }
    return data;
}

function engStatusBadge(status) {
    return `<span class="tinst-state eng-status eng-status-${engEsc(status)}">${engEsc(status || 'unknown')}</span>`;
}

function initEngagementsPage() {
    if (currentEngagement) return;
    loadEngagements();
}

async function loadEngagements() {
    const box = document.getElementById('eng-list');
    if (!box) return;
    box.innerHTML = '<div class="tinst-empty">Loading engagements…</div>';
    try {
        const data = await engJson('/api/engagements');
        engagementRows = data.engagements || [];
        renderEngagementList();
    } catch (err) {
        box.innerHTML = `<div class="tinst-empty">Could not load engagements: ${engEsc(err.message)}</div>`;
    }
}

function renderEngagementList() {
    const box = document.getElementById('eng-list');
    if (!box) return;
    if (engagementRows.length === 0) {
        box.innerHTML = '<div class="tinst-empty">No engagements yet. Create one to start collecting evidence and reports.</div>';
        return;
    }
    box.innerHTML = `<div class="tinst-grid">${engagementRows.map(e => `
        <article class="tinst-card eng-card" tabindex="0" role="button" data-id="${engEsc(e.id)}" onclick="openEngagement(this.dataset.id)" onkeydown="if(event.key==='Enter')openEngagement(this.dataset.id)">
            <div class="tinst-card-head">
                <span class="tinst-name" title="${engEsc(e.name)}">${engEsc(e.name)}</span>
                ${engStatusBadge(e.status)}
            </div>
            <div class="tinst-meta"><span class="tinst-badge">${engEsc(e.target || 'no target')}</span></div>
            <div class="tinst-path">Created ${engEsc(engDate(e.created_at))}</div>
        </article>`).join('')}</div>`;
}

function toggleEngagementForm(show) {
    const f = document.getElementById('eng-create-form');
    if (!f) return;
    f.hidden = show === undefined ? !f.hidden : !show;
}

function engLines(id) {
    return (document.getElementById(id)?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
}

async function createEngagement(ev) {
    ev.preventDefault();
    const btn = document.getElementById('eng-f-submit');
    const limits = {};
    for (const line of engLines('eng-f-limits')) {
        const i = line.indexOf('=');
        if (i > 0) limits[line.slice(0, i).trim()] = line.slice(i + 1).trim();
        else limits[line] = true;
    }
    const body = {
        name: document.getElementById('eng-f-name').value.trim(),
        objective: document.getElementById('eng-f-objective').value,
        target: document.getElementById('eng-f-target').value.trim(),
        scope_json: { included: engLines('eng-f-included'), excluded: engLines('eng-f-excluded') },
        limits_json: limits,
        authorization_note: document.getElementById('eng-f-auth').value,
    };
    if (btn) btn.disabled = true;
    try {
        const created = await engJson('/api/engagements', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        engNotify('Engagement created', 'success');
        document.getElementById('eng-create-form').reset();
        toggleEngagementForm(false);
        await loadEngagements();
        if (created && created.id) openEngagement(created.id);
    } catch (err) {
        engNotify(`Could not create engagement: ${err.message}`, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
    return false;
}

async function openEngagement(id) {
    const list = document.getElementById('eng-list-view');
    const detail = document.getElementById('eng-detail-view');
    if (!detail) return;
    try {
        currentEngagement = await engJson(`/api/engagements/${encodeURIComponent(id)}`);
    } catch (err) {
        engNotify(`Could not open engagement: ${err.message}`, 'error');
        return;
    }
    if (list) list.hidden = true;
    detail.hidden = false;
    toggleEngagementForm(false);
    document.getElementById('eng-detail-title').textContent = currentEngagement.name || '';
    document.getElementById('eng-detail-status').innerHTML = engStatusBadge(currentEngagement.status);
    engagementEvidence = [];
    ['eng-evidence-list', 'eng-findings-list', 'eng-assets-list'].forEach(i => {
        const el = document.getElementById(i);
        if (el) el.innerHTML = '';
    });
    const cnt = document.getElementById('eng-count-evidence');
    if (cnt) cnt.textContent = '—';
    const st = document.getElementById('eng-report-status');
    if (st) st.textContent = '';
    renderEngagementOverview();
    engagementStages = [];
    loadEngagementStages();
    loadEngagementApprovals();
    showEngagementTab('overview');
}

function closeEngagementDetail() {
    currentEngagement = null;
    document.getElementById('eng-detail-view').hidden = true;
    document.getElementById('eng-list-view').hidden = false;
    loadEngagements();
}

function showEngagementTab(name) {
    document.querySelectorAll('.mcp-tab[data-eng-tab]').forEach(btn => {
        const on = btn.dataset.engTab === name;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.mcp-tab-pane[data-eng-pane]').forEach(p => {
        p.hidden = p.dataset.engPane !== name;
    });
    if (!currentEngagement) return;
    if (name === 'evidence') loadEngagementEvidence();
    if (name === 'findings') { loadEngagementReviewQueue(); loadEngagementLinks('findings'); }
    if (name === 'assets') { loadEngagementLinks('assets'); loadAssetGraphEdges(); loadEngagementInputs(); }
}

function engParse(raw) {
    if (raw == null || raw === '') return null;
    if (typeof raw === 'object') return raw;
    try { return JSON.parse(raw); } catch (_) { return null; }
}

function engList(items) {
    if (!Array.isArray(items) || items.length === 0) return '<span class="tinst-path">none</span>';
    return items.map(i => `<span class="tinst-badge">${engEsc(i)}</span>`).join(' ');
}

function renderEngagementOverview() {
    const e = currentEngagement;
    const box = document.getElementById('eng-overview');
    if (!e || !box) return;
    const scope = engParse(e.scope_json) || {};
    const limits = engParse(e.limits_json) || {};
    const limitRows = Object.keys(limits).map(k => `<span class="tinst-badge">${engEsc(k)}: ${engEsc(typeof limits[k] === 'object' ? JSON.stringify(limits[k]) : limits[k])}</span>`).join(' ') || '<span class="tinst-path">none</span>';
    const statuses = ['draft', 'active', 'paused', 'completed', 'archived'];
    box.innerHTML = `<dl class="eng-dl">
        <dt>Objective</dt><dd>${engEsc(e.objective) || '<span class="tinst-path">none</span>'}</dd>
        <dt>Target</dt><dd>${engEsc(e.target) || '<span class="tinst-path">none</span>'}</dd>
        <dt>Scope included</dt><dd>${engList(scope.included)}</dd>
        <dt>Scope excluded</dt><dd>${engList(scope.excluded)}</dd>
        <dt>Limits</dt><dd>${limitRows}</dd>
        <dt>Authorization</dt><dd>${engEsc(e.authorization_note) || '<span class="tinst-path">none</span>'}</dd>
        <dt>Created</dt><dd>${engEsc(engDate(e.created_at))}</dd>
        <dt>Status</dt><dd>
            <select id="eng-status-select" class="tinst-search">${statuses.map(s => `<option value="${s}"${s === e.status ? ' selected' : ''}>${s}</option>`).join('')}</select>
            <button class="btn-secondary" type="button" data-require-permission="project:write" onclick="updateEngagementStatus()">Save status</button>
            <button class="btn-secondary tinst-danger" type="button" data-require-permission="project:write" onclick="deleteCurrentEngagement()">Delete</button>
        </dd>
    </dl>`;
}

async function updateEngagementStatus() {
    const e = currentEngagement;
    const sel = document.getElementById('eng-status-select');
    if (!e || !sel) return;
    try {
        currentEngagement = await engJson(`/api/engagements/${encodeURIComponent(e.id)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: e.name, objective: e.objective, target: e.target, status: sel.value,
                scope_json: engParse(e.scope_json) || {}, limits_json: engParse(e.limits_json) || {},
                authorization_note: e.authorization_note,
            }),
        });
        document.getElementById('eng-detail-status').innerHTML = engStatusBadge(currentEngagement.status);
        renderEngagementOverview();
        engNotify('Status updated', 'success');
    } catch (err) {
        engNotify(`Could not update: ${err.message}`, 'error');
    }
}

async function deleteCurrentEngagement() {
    const e = currentEngagement;
    if (!e || !confirm(`Delete engagement "${e.name}"? Its evidence is deleted; conversations and findings are only unlinked.`)) return;
    try {
        await engJson(`/api/engagements/${encodeURIComponent(e.id)}`, { method: 'DELETE' });
        engNotify('Engagement deleted', 'success');
        closeEngagementDetail();
    } catch (err) {
        engNotify(`Could not delete: ${err.message}`, 'error');
    }
}

async function attachEngagementConversation() {
    const input = document.getElementById('eng-conv-id');
    const id = (input?.value || '').trim();
    if (!currentEngagement || !id) { engNotify('Enter a conversation ID', 'error'); return; }
    try {
        await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/conversations`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ conversation_id: id }),
        });
        engNotify('Conversation attached', 'success');
        const list = document.getElementById('eng-conv-list');
        if (list) {
            const row = document.createElement('div');
            row.className = 'tinst-badge';
            row.textContent = `Attached this session: ${id}`;
            if (list.querySelector('.tinst-empty')) list.innerHTML = '';
            list.appendChild(row);
        }
        input.value = '';
    } catch (err) {
        engNotify(`Could not attach: ${err.message}`, 'error');
    }
}

// ---- Evidence ----

function engIntegrityBadge(state) {
    const map = {
        verified: ['ok', 'ok'], mismatch: ['mismatch', 'mismatch'], missing: ['missing', 'missing'],
    };
    const [cls, label] = map[state] || ['pending', 'not checked'];
    return `<span class="eng-integrity eng-integrity-${cls}">${label}</span>`;
}

async function loadEngagementEvidence() {
    const box = document.getElementById('eng-evidence-list');
    if (!currentEngagement || !box) return;
    box.innerHTML = '<div class="tinst-empty">Loading evidence…</div>';
    try {
        const data = await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/evidence`);
        engagementEvidence = data.evidence || [];
        const cnt = document.getElementById('eng-count-evidence');
        if (cnt) cnt.textContent = engagementEvidence.length;
        renderEngagementEvidence();
        engagementEvidence.forEach(ev => verifyEvidence(ev.id));
    } catch (err) {
        box.innerHTML = `<div class="tinst-empty">Could not load evidence: ${engEsc(err.message)}</div>`;
    }
}

function renderEngagementEvidence() {
    const box = document.getElementById('eng-evidence-list');
    if (!box) return;
    if (engagementEvidence.length === 0) {
        box.innerHTML = '<div class="tinst-empty">No evidence yet. Upload text or a file above.</div>';
        return;
    }
    box.innerHTML = `<table class="eng-table"><thead><tr><th>Title</th><th>Kind</th><th>Size</th><th>SHA-256</th><th>Integrity</th><th>Added</th></tr></thead><tbody>${engagementEvidence.map(ev => `
        <tr><td>${engEsc(ev.title || ev.id)}${ev.source_tool ? ` <span class="tinst-path">${engEsc(ev.source_tool)}</span>` : ''}</td>
        <td><span class="tinst-badge">${engEsc(ev.kind)}</span></td>
        <td>${engEsc(ev.size_bytes)} B</td>
        <td><code title="${engEsc(ev.sha256)}">${engEsc((ev.sha256 || '').slice(0, 12))}</code></td>
        <td id="eng-integrity-${engEsc(ev.id)}">${engIntegrityBadge(ev._integrity)} <button class="tinst-chip" type="button" data-id="${engEsc(ev.id)}" onclick="verifyEvidence(this.dataset.id)">Verify</button></td>
        <td>${engEsc(engDate(ev.created_at))}</td></tr>`).join('')}</tbody></table>`;
}

async function verifyEvidence(id) {
    const cell = document.getElementById(`eng-integrity-${id}`);
    let state = 'pending';
    try {
        const data = await engJson(`/api/evidence/${encodeURIComponent(id)}`);
        state = data.integrity === 'verified' ? 'verified' : (data.integrity || 'pending');
    } catch (err) {
        state = (err.data && err.data.integrity) || 'pending';
        if (state === 'pending') engNotify(`Could not verify evidence: ${err.message}`, 'error');
    }
    const ev = engagementEvidence.find(e => e.id === id);
    if (ev) ev._integrity = state;
    if (cell) {
        cell.innerHTML = `${engIntegrityBadge(state)} <button class="tinst-chip" type="button" data-id="${engEsc(id)}" onclick="verifyEvidence(this.dataset.id)">Verify</button>`;
    }
}

async function uploadEngagementEvidence(ev) {
    ev.preventDefault();
    if (!currentEngagement) return false;
    const base = `/api/engagements/${encodeURIComponent(currentEngagement.id)}/evidence`;
    const kind = document.getElementById('eng-ev-kind').value;
    const title = document.getElementById('eng-ev-title').value.trim();
    const tool = document.getElementById('eng-ev-tool').value.trim();
    const finding = document.getElementById('eng-ev-finding').value.trim();
    const text = document.getElementById('eng-ev-text').value;
    const file = document.getElementById('eng-ev-file').files[0];
    if (!file && !text) { engNotify('Provide text content or a file', 'error'); return false; }
    const btn = document.getElementById('eng-ev-submit');
    if (btn) btn.disabled = true;
    try {
        let opts;
        if (file) {
            const fd = new FormData();
            fd.append('file', file);
            fd.append('kind', kind);
            if (title) fd.append('title', title);
            if (tool) fd.append('source_tool', tool);
            if (finding) fd.append('finding_id', finding);
            opts = { method: 'POST', body: fd };
        } else {
            opts = {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ kind, title, source_tool: tool, finding_id: finding, content: text }),
            };
        }
        await engJson(base, opts);
        engNotify('Evidence uploaded', 'success');
        document.getElementById('eng-ev-text').value = '';
        document.getElementById('eng-ev-file').value = '';
        await loadEngagementEvidence();
    } catch (err) {
        engNotify(`Upload failed: ${err.message}`, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
    return false;
}

// ---- Findings and assets ----
// The server has no engagement-scoped findings/assets endpoints yet; these tabs degrade to a
// "not available" state on 404/405 and start working once GET/POST
// /api/engagements/:id/findings and /assets exist.


// Download any authenticated endpoint as a file, keeping the server's file name when it sends one.
async function engDownload(path, fallbackName) {
    const r = await apiFetch(path);
    if (!r.ok) {
        let msg = `HTTP ${r.status}`;
        try { msg = (await r.json()).error || msg; } catch (_) { /* keep status */ }
        throw new Error(msg);
    }
    const blob = await r.blob();
    const name = engFilenameFrom(r.headers.get('Content-Disposition'), fallbackName);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Download the current engagement's findings, assets or evidence as CSV.
async function engExportCsv(kind) {
    if (!currentEngagement) return;
    try {
        await engDownload(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/export?kind=${encodeURIComponent(kind)}`,
            `engagement-${currentEngagement.id}-${kind}.csv`);
    } catch (err) {
        engNotify(`Download failed: ${err.message}`, 'error');
    }
}

async function loadEngagementLinks(kind) {
    const box = document.getElementById(`eng-${kind}-list`);
    if (!currentEngagement || !box) return;
    box.innerHTML = `<div class="tinst-empty">Loading ${kind}…</div>`;
    try {
        const data = await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/${kind}`);
        const rows = data[kind] || [];
        if (rows.length === 0) {
            box.innerHTML = `<div class="tinst-empty">No ${kind} linked to this engagement yet.</div>`;
            return;
        }
        box.innerHTML = kind === 'findings' ? engFindingsTable(rows) : engAssetsTable(rows);
        if (typeof applyRBACToUI === 'function') applyRBACToUI(box);
    } catch (err) {
        if (err.status === 404 || err.status === 405) {
            box.innerHTML = `<div class="tinst-empty">Listing ${kind} per engagement is not available on this server yet. Findings from attached conversations still appear in the Report tab.</div>`;
        } else {
            box.innerHTML = `<div class="tinst-empty">Could not load ${kind}: ${engEsc(err.message)}</div>`;
        }
    }
}

// Review queue: what a person must look at (findings under review, potential findings with
// unverified claims, hypotheses open for more than 7 days).
async function loadEngagementReviewQueue() {
    const box = document.getElementById('eng-review-queue');
    if (!currentEngagement || !box) return;
    box.innerHTML = '<div class="tinst-empty">Loading review queue…</div>';
    try {
        const data = await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/review-queue`);
        const items = data.items || [];
        if (items.length === 0) {
            box.innerHTML = '<h4>Review queue</h4><div class="tinst-empty">Nothing needs review.</div>';
            return;
        }
        const eid = encodeURIComponent(currentEngagement.id);
        box.innerHTML = '<h4>Review queue</h4><ul class="eng-review-queue">' + items.map(it => {
            const href = it.kind === 'hypothesis_stale'
                ? `/api/engagements/${eid}/hypotheses`
                : `#eng-finding-${engEsc(it.id)}`;
            const sev = it.severity ? ` <span class="tinst-badge">${engEsc(it.severity)}</span>` : '';
            return `<li><a href="${href}">${engEsc(it.title || it.id)}</a>${sev} <span class="tinst-state">${engEsc(it.kind)}</span> ${engEsc(it.reason)} <small>${engEsc(engDate(it.since))}</small></li>`;
        }).join('') + '</ul>';
    } catch (err) {
        box.innerHTML = `<h4>Review queue</h4><div class="tinst-empty">Could not load review queue: ${engEsc(err.message)}</div>`;
    }
}

const ENG_CONFIDENCE_LEVELS = ['potential', 'observed', 'reproduced', 'validated', 'confirmed'];
const ENG_CONFIDENCE_LABELS = {
    potential: 'Potential exposure',
    observed: 'Observed',
    reproduced: 'Reproduced',
    validated: 'Validated',
    confirmed: 'Confirmed',
};

function engConfidenceBadge(level) {
    const key = String(level || '').toLowerCase();
    const label = ENG_CONFIDENCE_LABELS[key] || (key ? key : 'Unrated');
    return `<span class="tinst-state conf-badge conf-${engEsc(ENG_CONFIDENCE_LABELS[key] ? key : 'unknown')}">${engEsc(label)}</span>`;
}

// Badge plus (for project:write) a select + reason + Save control. ctx is 'eng' or 'run'
// and decides which list is reloaded from the server after a successful save.
function engConfidenceCell(id, level, ctx) {
    const key = String(level || '').toLowerCase();
    const opts = ENG_CONFIDENCE_LEVELS.map(l => `<option value="${engEsc(l)}"${l === key ? ' selected' : ''}>${engEsc(ENG_CONFIDENCE_LABELS[l])}</option>`).join('');
    return `<div class="conf-cell" data-finding="${engEsc(id)}" data-ctx="${engEsc(ctx || 'eng')}">
        <span class="conf-current">${engConfidenceBadge(level)}</span>
        <span class="conf-control" data-require-permission="project:write">
            <select class="conf-select" aria-label="Confidence level">${opts}</select>
            <input class="conf-reason" type="text" placeholder="Reason" aria-label="Reason for change">
            <button class="btn-secondary conf-save" type="button" data-require-permission="project:write" onclick="engSaveConfidence(this)">Save</button>
        </span></div>`;
}

async function engSaveConfidence(btn) {
    const cell = btn && btn.closest('.conf-cell');
    if (!cell) return;
    const id = cell.dataset.finding;
    const confidence = cell.querySelector('.conf-select').value;
    const reason = cell.querySelector('.conf-reason').value.trim();
    btn.disabled = true;
    try {
        await engJson(`/api/vulnerabilities/${encodeURIComponent(id)}/confidence`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confidence, reason }),
        });
        engNotify('Confidence updated', 'success');
        if (cell.dataset.ctx === 'run' && typeof reloadRunWorkspace === 'function') {
            await reloadRunWorkspace();
        } else {
            await loadEngagementLinks('findings');
        }
    } catch (err) {
        // Refused (409) or failed: keep the old label, show the server's message.
        engNotify(err.message, 'error');
        btn.disabled = false;
    }
}

function engFindingsTable(rows) {
    return `<table class="eng-table"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Confidence</th><th>Target</th></tr></thead><tbody>${rows.map(v => `
        <tr id="eng-finding-${engEsc(v.id)}"><td><code>${engEsc(v.id)}</code></td><td>${engEsc(v.title)}</td><td><span class="tinst-badge">${engEsc(v.severity)}</span></td><td>${engEsc(v.status)}</td><td>${engConfidenceCell(v.id, v.confidence, 'eng')}</td><td>${engEsc(v.target)}</td></tr>
        <tr class="eng-claims-row"><td colspan="6">${engClaimsBlock(v.id)}</td></tr>`).join('')}</tbody></table>`;
}

const ENG_CLAIM_STATUSES = ['unverified', 'supported', 'disputed', 'unsupported'];

// Collapsible claims list for one finding; loaded from the server when first opened.
function engClaimsBlock(findingId) {
    return `<details class="eng-claims" data-finding="${engEsc(findingId)}" ontoggle="engClaimsToggle(this)">
        <summary>Claims</summary><div class="eng-claims-body"></div></details>`;
}

function engClaimsToggle(el) {
    if (el.open) engLoadClaims(el);
}

async function engLoadClaims(el) {
    const body = el.querySelector('.eng-claims-body');
    const id = el.dataset.finding;
    body.textContent = 'Loading...';
    try {
        const data = await engJson(`/api/vulnerabilities/${encodeURIComponent(id)}/claims`);
        const claims = (data && data.claims) || [];
        const items = claims.map(c => {
            const st = String(c.status || 'unverified');
            const opts = ENG_CLAIM_STATUSES.map(x => `<option value="${engEsc(x)}"${x === st ? ' selected' : ''}>${engEsc(x)}</option>`).join('');
            const ev = (c.evidence_ids || []).map(e => `<code>${engEsc(e)}</code>`).join(' ') || 'no evidence linked';
            return `<li class="eng-claim" data-claim="${engEsc(c.id)}">
                <span class="tinst-state claim-badge claim-${engEsc(st)}">${engEsc(st)}</span> ${engEsc(c.text)}
                <div class="eng-claim-meta">Evidence: ${ev}${c.status_reason ? ` &middot; Reason: ${engEsc(c.status_reason)}` : ''}</div>
                <span data-require-permission="project:write">
                    <select class="claim-status" aria-label="Claim status">${opts}</select>
                    <input class="claim-reason" type="text" placeholder="Reason" aria-label="Reason for claim status">
                    <button class="btn-secondary" type="button" onclick="engSetClaimStatus(this)">Set status</button>
                    <input class="claim-evidence" type="text" placeholder="Evidence ID" aria-label="Evidence ID">
                    <button class="btn-secondary" type="button" onclick="engLinkClaimEvidence(this)">Link evidence</button>
                </span></li>`;
        }).join('');
        let verLine = '';
        try {
            const v = await engJson(`/api/vulnerabilities/${encodeURIComponent(id)}/verification`);
            if (v && v.status) {
                const rs = (v.reasons || []).map(r => engEsc(r)).join('; ');
                verLine = `<div class="eng-claim-meta eng-verification">Latest verification: <strong>${engEsc(v.status)}</strong>${rs ? ` &middot; ${rs}` : ''}</div>`;
            }
        } catch (e) { /* no verification recorded yet */ }
        const missing = claims.length === 0 ? '<div class="tinst-empty">No claims recorded: confidence rests on evidence rules alone.</div>' : '';
        body.innerHTML = `${missing}${verLine}<ul class="eng-claim-list">${items}</ul>
            <span data-require-permission="project:write">
                <button class="btn-secondary" type="button" data-require-permission="project:write" onclick="engVerifyFinding(this)">Verify</button>
                <input class="claim-new" type="text" placeholder="New claim" aria-label="New claim text">
                <button class="btn-secondary" type="button" onclick="engAddClaim(this)">Add claim</button>
            </span>`;
    } catch (err) {
        body.innerHTML = `<div class="tinst-empty">Could not load claims: ${engEsc(err.message)}</div>`;
    }
}

async function engVerifyFinding(btn) {
    const el = btn.closest('.eng-claims');
    btn.disabled = true;
    try {
        const r = await engJson(`/api/vulnerabilities/${encodeURIComponent(el.dataset.finding)}/verify`, { method: 'POST' });
        engNotify('Verification: ' + String((r && r.status) || ''), 'success');
        await engLoadClaims(el);
    } catch (err) {
        engNotify(err.message, 'error');
        btn.disabled = false;
    }
}

async function engClaimCall(btn, path, method, payload, okMsg) {
    const el = btn.closest('.eng-claims');
    btn.disabled = true;
    try {
        await engJson(`/api/vulnerabilities/${encodeURIComponent(el.dataset.finding)}/claims${path}`, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        engNotify(okMsg, 'success');
        await engLoadClaims(el);
    } catch (err) {
        engNotify(err.message, 'error');
        btn.disabled = false;
    }
}

function engSetClaimStatus(btn) {
    const li = btn.closest('.eng-claim');
    return engClaimCall(btn, `/${encodeURIComponent(li.dataset.claim)}`, 'PUT',
        { status: li.querySelector('.claim-status').value, reason: li.querySelector('.claim-reason').value.trim() }, 'Claim updated');
}

function engLinkClaimEvidence(btn) {
    const li = btn.closest('.eng-claim');
    return engClaimCall(btn, `/${encodeURIComponent(li.dataset.claim)}/evidence`, 'POST',
        { evidence_id: li.querySelector('.claim-evidence').value.trim() }, 'Evidence linked');
}

function engAddClaim(btn) {
    const text = btn.parentElement.querySelector('.claim-new').value.trim();
    return engClaimCall(btn, '', 'POST', { text }, 'Claim added');
}

function engAssetsTable(rows) {
    return `<table class="eng-table"><thead><tr><th>ID</th><th>Host</th><th>IP</th><th>Port</th><th>Criticality</th><th>Status</th></tr></thead><tbody>${rows.map(a => `
        <tr><td><code>${engEsc(a.id || a.ID)}</code></td><td>${engEsc(a.host || a.Host || a.domain || a.Domain)}</td><td>${engEsc(a.ip || a.IP)}</td><td>${engEsc(a.port || a.Port)}</td><td>${engEsc(a.criticality || a.Criticality)}</td><td>${engEsc(a.status || a.Status)}</td></tr>`).join('')}</tbody></table>`;
}

// ---- Asset relationships (list view, grouped by relation type) ----

const ENG_REL_CONFIDENCE_HELP = {
    inferred: 'Inferred: a guess, not a fact',
    observed: 'Observed: seen in a tool result or evidence',
    manual: 'Manual: entered by a person',
    verified: 'Verified: confirmed by a person, with a reason',
};

function engAssetLabel(n) {
    if (!n) return '?';
    const name = n.domain || n.host || n.ip || n.id;
    return n.port ? `${name}:${n.port}` : name;
}

function engGraphEdgesHtml(graph) {
    const nodes = {};
    (graph.nodes || []).forEach(n => { nodes[n.id] = n; });
    const edges = graph.edges || [];
    if (edges.length === 0) return '<div class="tinst-empty">No asset relationships recorded yet.</div>';
    const groups = {};
    edges.forEach(e => { (groups[e.relation_type] = groups[e.relation_type] || []).push(e); });
    return Object.keys(groups).sort().map(type => `
        <h4>${engEsc(type)} <small>(${groups[type].length})</small></h4>
        <table class="eng-table"><thead><tr><th>From</th><th>To</th><th>Confidence</th><th>Provenance</th></tr></thead><tbody>${groups[type].map(e => {
            const prov = [e.evidence_id ? `evidence ${e.evidence_id}` : '', e.tool_execution_id ? `tool run ${e.tool_execution_id}` : '', e.reason || '', e.created_by ? `by ${e.created_by}` : ''].filter(Boolean).join('; ');
            return `<tr><td>${engEsc(engAssetLabel(nodes[e.from_asset_id]))}</td><td>${engEsc(engAssetLabel(nodes[e.to_asset_id]))}</td>
                <td><span class="eng-badge eng-rel-${engEsc(e.confidence)}" style="padding:1px 8px;border-radius:10px;border:1px solid currentColor;font-size:12px;${e.confidence === 'verified' ? 'color:#1a7f37;' : e.confidence === 'inferred' ? 'color:#b35900;' : ''}" title="${engEsc(ENG_REL_CONFIDENCE_HELP[e.confidence] || '')}">${engEsc(e.confidence)}</span></td>
                <td>${engEsc(prov)}</td></tr>`;
        }).join('')}</tbody></table>`).join('');
}

async function loadAssetGraphEdges() {
    const list = document.getElementById('eng-assets-list');
    if (!currentEngagement || !list) return;
    let box = document.getElementById('eng-asset-graph');
    if (!box) {
        box = document.createElement('div');
        box.id = 'eng-asset-graph';
        list.insertAdjacentElement('afterend', box);
    }
    box.innerHTML = '<h3>Relationships</h3><div class="tinst-empty">Loading relationships…</div>';
    try {
        const graph = await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/asset-graph`);
        box.innerHTML = '<h3>Relationships</h3>' + engGraphEdgesHtml(graph);
    } catch (err) {
        box.innerHTML = `<h3>Relationships</h3><div class="tinst-empty">Could not load relationships: ${engEsc(err.message)}</div>`;
    }
}

async function addEngagementLink(kind) {
    const input = document.getElementById(kind === 'findings' ? 'eng-finding-id' : 'eng-asset-id');
    const id = (input?.value || '').trim();
    if (!currentEngagement || !id) { engNotify('Enter an ID', 'error'); return; }
    try {
        await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/${kind}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(kind === 'findings' ? { finding_id: id } : { asset_id: id }),
        });
        engNotify(kind === 'findings' ? 'Finding added' : 'Asset added', 'success');
        input.value = '';
        loadEngagementLinks(kind);
    } catch (err) {
        if (err.status === 404 || err.status === 405) {
            engNotify(`Adding ${kind} by ID is not available on this server yet`, 'error');
        } else {
            engNotify(`Could not add: ${err.message}`, 'error');
        }
    }
}

// ---- Report ----

function engFilenameFrom(disposition, fallback) {
    const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition || '');
    if (!m) return fallback;
    try { return decodeURIComponent(m[1]); } catch (_) { return m[1]; }
}

async function downloadEngagementReport() {
    if (!currentEngagement) return;
    const audience = document.getElementById('eng-report-audience').value;
    const format = document.getElementById('eng-report-format').value;
    const status = document.getElementById('eng-report-status');
    const btn = document.getElementById('eng-report-btn');
    if (btn) btn.disabled = true;
    if (status) status.textContent = 'Generating report…';
    try {
        const r = await apiFetch(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/report?audience=${encodeURIComponent(audience)}&format=${encodeURIComponent(format)}`);
        if (!r.ok) {
            let msg = `HTTP ${r.status}`;
            try { msg = (await r.json()).error || msg; } catch (_) { /* keep status */ }
            throw new Error(msg);
        }
        const blob = await r.blob();
        const name = engFilenameFrom(r.headers.get('Content-Disposition'), `engagement-report-${audience}.${format}`);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        const reason = r.headers.get('X-Report-Audience-Reason');
        if (status) status.textContent = `Downloaded ${name}` + (reason ? ` · Audience: ${reason}` : '');
    } catch (err) {
        if (status) status.textContent = `Report failed: ${err.message}`;
        engNotify(`Report failed: ${err.message}`, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

/* ---- Assessment stages (server-recorded; UI always reloads from the server) ---- */

function engStagesUrl(suffix) {
    return `/api/engagements/${encodeURIComponent(currentEngagement.id)}/stages${suffix || ''}`;
}

async function loadEngagementStages() {
    const box = document.getElementById('eng-stages');
    if (!currentEngagement || !box) return;
    const id = currentEngagement.id;
    box.innerHTML = '<div class="tinst-empty">Loading stages…</div>';
    try {
        const data = await engJson(engStagesUrl());
        if (!currentEngagement || currentEngagement.id !== id) return;
        engagementStages = (data && data.stages) || [];
        renderEngagementStages();
    } catch (err) {
        if (!currentEngagement || currentEngagement.id !== id) return;
        box.innerHTML = `<div class="tinst-empty">Could not load stages: ${engEsc(err.message)}</div>`;
    }
}

const ENG_STAGE_RECOVERY_LABELS = { blocked: 'Blocked', needs_review: 'Needs review', failed: 'Failed', interrupted: 'Interrupted' };

function renderEngagementStages() {
    const box = document.getElementById('eng-stages');
    if (!box) return;
    if (engagementStages.length === 0) {
        box.innerHTML = '<div class="tinst-empty">No stages recorded for this engagement.</div>';
        return;
    }
    const stages = engagementStages.slice().sort((a, b) => (a.order || 0) - (b.order || 0));
    const next = stages.find(s => s.status === 'pending');
    box.innerHTML = `<ol class="eng-stage-list">${stages.map(s => {
        const st = s.status || 'pending';
        const isNext = next && next.stage === s.stage;
        const evCount = Array.isArray(s.evidence_ids) ? s.evidence_ids.length : 0;
        const times = [
            s.started_at ? `Started ${engEsc(engDate(s.started_at))}` : '',
            s.finished_at ? `Finished ${engEsc(engDate(s.finished_at))}` : '',
        ].filter(Boolean).join(' · ');
        // blocked/needs_review/failed/interrupted are all non-terminal recovery states: not
        // recorded, but the stage can be started again (back to running), completed or skipped.
        const isRecoveryState = st === 'blocked' || st === 'needs_review' || st === 'failed' || st === 'interrupted';
        let actions = '';
        if (st === 'pending') {
            actions = `<button class="btn-secondary" type="button" data-require-permission="project:write" data-stage="${engEsc(s.stage)}" onclick="startEngagementStage(this.dataset.stage)">Start</button>`;
        } else if (isRecoveryState) {
            actions = `<button class="btn-secondary" type="button" data-require-permission="project:write" data-stage="${engEsc(s.stage)}" onclick="startEngagementStage(this.dataset.stage)">Start</button>
                <button class="btn-secondary" type="button" data-require-permission="project:write" data-stage="${engEsc(s.stage)}" onclick="toggleEngStageForm(this.dataset.stage, 'complete')">Complete</button>
                <button class="btn-secondary" type="button" data-require-permission="project:write" data-stage="${engEsc(s.stage)}" onclick="toggleEngStageForm(this.dataset.stage, 'skip')">Skip</button>`;
        } else if (st === 'running') {
            actions = `<button class="btn-secondary" type="button" data-require-permission="project:write" data-stage="${engEsc(s.stage)}" onclick="toggleEngStageForm(this.dataset.stage, 'complete')">Complete</button>
                <button class="btn-secondary" type="button" data-require-permission="project:write" data-stage="${engEsc(s.stage)}" onclick="toggleEngStageForm(this.dataset.stage, 'skip')">Skip</button>`;
        }
        const forms = !(st === 'running' || isRecoveryState) ? '' : `
            <div class="eng-stage-form" data-form="complete" hidden>
                <input class="tinst-search" data-field="evidence" placeholder="Evidence IDs, comma-separated" autocomplete="off">
                <textarea class="tinst-search" data-field="note" rows="2" placeholder="Note"></textarea>
                <button class="btn-primary" type="button" data-require-permission="project:write" data-stage="${engEsc(s.stage)}" onclick="completeEngagementStage(this.dataset.stage)">Submit</button>
            </div>
            <div class="eng-stage-form" data-form="skip" hidden>
                <input class="tinst-search" data-field="reason" placeholder="Reason for skipping" autocomplete="off">
                <button class="btn-primary" type="button" data-require-permission="project:write" data-stage="${engEsc(s.stage)}" onclick="skipEngagementStage(this.dataset.stage)">Submit</button>
            </div>`;
        return `<li class="eng-stage eng-stage-${engEsc(st)}${isNext ? ' eng-stage-next' : ''}" data-stage="${engEsc(s.stage)}">
            <span class="eng-stage-dot" aria-hidden="true"></span>
            <div class="eng-stage-body">
                <div class="eng-stage-head">
                    <strong>${engEsc(s.title || s.stage)}</strong>
                    <span class="tinst-state eng-stage-badge eng-stage-badge-${engEsc(st)}">${engEsc(st.replace('_', ' '))}</span>
                    ${isNext ? '<span class="tinst-badge eng-stage-nextbadge">next</span>' : ''}
                </div>
                ${times ? `<div class="tinst-path">${times}</div>` : ''}
                <div class="tinst-path">Evidence: ${engEsc(evCount)}</div>
                ${s.note ? `<div class="eng-stage-note">${engEsc(s.note)}</div>` : ''}
                ${isRecoveryState && s.reason ? `<div class="eng-stage-note">${engEsc(ENG_STAGE_RECOVERY_LABELS[st] || st)}: ${engEsc(s.reason)}</div>` : ''}
                ${st === 'skipped' && s.reason ? `<div class="eng-stage-note">Skipped: ${engEsc(s.reason)}</div>` : ''}
                ${actions ? `<div class="eng-stage-actions">${actions}</div>` : ''}
                <div class="eng-stage-tasks" data-stage-tasks="${engEsc(s.stage)}"></div>
                <div class="eng-stage-plans" data-stage-plans="${engEsc(s.stage)}"></div>
                ${forms}
            </div>
        </li>`;
    }).join('')}</ol>`;
    stages.forEach(s => { loadEngStageTasks(s.stage); loadEngStagePlans(s.stage); });
}

async function loadEngStageTasks(stage) {
    const li = engStageEl(stage);
    const box = li && li.querySelector('.eng-stage-tasks');
    if (!box || !currentEngagement) return;
    const id = currentEngagement.id;
    try {
        const data = await engJson(engStagesUrl(`/${encodeURIComponent(stage)}/tasks`));
        if (!currentEngagement || currentEngagement.id !== id) return;
        const tasks = (data && data.tasks) || [];
        if (!tasks.length) { box.innerHTML = ''; return; }
        box.innerHTML = `<ul class="eng-task-list">${tasks.map(t => `<li class="eng-task eng-task-${engEsc(t.status)}">
            <span class="eng-task-title">${engEsc(t.title)}</span>
            <span class="tinst-state">${engEsc(t.status)}${t.required ? '' : ' (optional)'}</span>
            ${t.reason ? `<span class="tinst-path">Reason: ${engEsc(t.reason)}</span>` : ''}
            ${t.status === 'open' ? `<button class="btn-secondary" type="button" data-require-permission="project:write" data-task="${engEsc(t.id)}" onclick="setEngStageTask(this.dataset.task, 'done')">Done</button>
            <button class="btn-secondary" type="button" data-require-permission="project:write" data-task="${engEsc(t.id)}" data-stage="${engEsc(stage)}" onclick="skipEngStageTask(this.dataset.task, this.dataset.stage)">Skip</button>` : ''}
        </li>`).join('')}</ul>`;
    } catch (err) {
        box.innerHTML = `<div class="tinst-path">Could not load tasks: ${engEsc(err.message)}</div>`;
    }
}

async function loadEngStagePlans(stage) {
    const li = engStageEl(stage);
    const box = li && li.querySelector('.eng-stage-plans');
    if (!box || !currentEngagement) return;
    const id = currentEngagement.id;
    try {
        const data = await engJson(engStagesUrl(`/${encodeURIComponent(stage)}/plans`));
        if (!currentEngagement || currentEngagement.id !== id) return;
        const plans = (data && data.plans) || [];
        box.innerHTML = plans.map(p => `<div class="eng-plan eng-plan-${engEsc(p.status)}">
            <div><strong>Plan</strong> <span class="tinst-state">${engEsc(p.status)}</span> <span class="tinst-path">by ${engEsc(p.created_by)}</span>
            ${p.status === 'draft' ? `<button class="btn-secondary" type="button" data-require-permission="project:write" data-plan="${engEsc(p.id)}" onclick="activateEngStagePlan(this.dataset.plan)">Activate</button>` : ''}</div>
            <div class="tinst-path">${engEsc(p.objective)}</div>
            <ol class="eng-task-list">${(p.tasks || []).map(t => `<li class="eng-task eng-task-${engEsc(t.status)}">
                <span class="eng-task-title">${engEsc(t.title)}</span>
                <span class="tinst-state">${engEsc(t.status)}</span>
                ${(t.depends_on || []).length ? `<span class="tinst-path">after ${engEsc(t.depends_on.join(', '))}</span>` : ''}
                ${t.reason ? `<span class="tinst-path">Reason: ${engEsc(t.reason)}</span>` : ''}
            </li>`).join('')}</ol>
        </div>`).join('');
    } catch (err) {
        box.innerHTML = `<div class="tinst-path">Could not load plans: ${engEsc(err.message)}</div>`;
    }
}

async function activateEngStagePlan(planId) {
    try {
        await engJson(`/api/stage-plans/${encodeURIComponent(planId)}/activate`, { method: 'POST' });
        engNotify('Plan activated', 'success');
    } catch (err) {
        engNotify(err.message, 'error');
    }
    await loadEngagementStages();
}

async function setEngStageTask(taskId, status, reason) {
    try {
        await engJson(`/api/stage-tasks/${encodeURIComponent(taskId)}`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status, reason: reason || '' }),
        });
        engNotify('Task ' + status, 'success');
    } catch (err) {
        engNotify(err.message, 'error');
    }
    await loadEngagementStages();
}

function skipEngStageTask(taskId) {
    const reason = window.prompt('Reason for skipping this task:');
    if (reason === null || !reason.trim()) { engNotify('A reason is required to skip a task', 'error'); return; }
    return setEngStageTask(taskId, 'skipped', reason.trim());
}

function engStageEl(stage) {
    const box = document.getElementById('eng-stages');
    if (!box) return null;
    return Array.from(box.querySelectorAll('li.eng-stage')).find(li => li.dataset.stage === stage) || null;
}

function toggleEngStageForm(stage, which) {
    const li = engStageEl(stage);
    if (!li) return;
    li.querySelectorAll('.eng-stage-form').forEach(f => {
        f.hidden = f.dataset.form !== which ? true : !f.hidden;
    });
}

async function engStageAction(stage, action, body, okMsg) {
    if (!currentEngagement || !stage) return;
    const opts = { method: 'POST' };
    if (body) {
        opts.headers = { 'Content-Type': 'application/json' };
        opts.body = JSON.stringify(body);
    }
    try {
        await engJson(engStagesUrl(`/${encodeURIComponent(stage)}/${action}`), opts);
        engNotify(okMsg, 'success');
    } catch (err) {
        engNotify(err.message, 'error');
    }
    await loadEngagementStages();
}

function startEngagementStage(stage) {
    return engStageAction(stage, 'start', null, 'Stage started');
}

function completeEngagementStage(stage) {
    const li = engStageEl(stage);
    if (!li) return;
    const ids = (li.querySelector('[data-field="evidence"]').value || '')
        .split(',').map(v => v.trim()).filter(Boolean);
    const note = li.querySelector('[data-field="note"]').value.trim();
    return engStageAction(stage, 'complete', { evidence_ids: ids, note }, 'Stage completed');
}

function skipEngagementStage(stage) {
    const li = engStageEl(stage);
    if (!li) return;
    const reason = li.querySelector('[data-field="reason"]').value.trim();
    if (!reason) { engNotify('Enter a reason for skipping', 'error'); return; }
    return engStageAction(stage, 'skip', { reason }, 'Stage skipped');
}

/* ---- Approvals (risky in-scope tool calls waiting for a person; the model cannot approve) ---- */

function engApprovalsBox() {
    let box = document.getElementById('eng-approvals');
    if (box) return box;
    const stages = document.getElementById('eng-stages');
    const host = stages && stages.closest('section');
    if (!host || !host.parentNode) return null;
    const section = document.createElement('section');
    section.className = 'eng-stages-section';
    section.setAttribute('aria-labelledby', 'eng-approvals-heading');
    section.innerHTML = '<h4 id="eng-approvals-heading">Approvals</h4><div id="eng-approvals"></div>' +
        '<p class="tinst-path eng-stages-note">Each approval allows one identical call and expires. Arguments are never stored, only a hash.</p>';
    host.parentNode.insertBefore(section, host);
    return section.querySelector('#eng-approvals');
}

async function loadEngagementApprovals() {
    const box = engApprovalsBox();
    if (!box || !currentEngagement) return;
    try {
        const data = await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/approvals`);
        renderEngagementApprovals((data && data.approvals) || []);
    } catch (err) {
        box.innerHTML = `<div class="tinst-empty">Could not load approvals: ${engEsc(err.message)}</div>`;
    }
}

function renderEngagementApprovals(list) {
    const box = engApprovalsBox();
    if (!box) return;
    if (list.length === 0) {
        box.innerHTML = '<div class="tinst-empty">No approval requests.</div>';
        return;
    }
    box.innerHTML = list.map(a => {
        const id = engEsc(a.id);
        const pending = a.status === 'pending';
        const used = a.used_at ? ' (used)' : '';
        return `<div class="eng-approval" data-approval="${id}">
            <div><strong>${engEsc(a.tool_name)}</strong> on <code>${engEsc(a.target)}</code> ${engStatusBadge(a.status)}${engEsc(used)}</div>
            <div class="eng-stage-note">Requested ${engEsc(a.requested_at || '')}, expires ${engEsc(a.expires_at || '')}${a.decision_reason ? ', reason: ' + engEsc(a.decision_reason) : ''}</div>
            ${pending ? `<div class="eng-stage-actions">
                <input type="text" data-field="reason" placeholder="Reason (required to deny)" maxlength="2000" autocomplete="off">
                <button class="btn-secondary" type="button" data-require-permission="project:write" onclick="decideEngagementApproval('${id}','approve')">Approve</button>
                <button class="btn-secondary tinst-danger" type="button" data-require-permission="project:write" onclick="decideEngagementApproval('${id}','deny')">Deny</button>
            </div>` : ''}
        </div>`;
    }).join('');
}

async function decideEngagementApproval(id, decision) {
    const box = document.getElementById('eng-approvals');
    const row = box && Array.from(box.querySelectorAll('.eng-approval')).find(r => r.dataset.approval === id);
    const reason = row ? row.querySelector('[data-field="reason"]').value.trim() : '';
    if (decision === 'deny' && !reason) {
        engNotify('A reason is required to deny', 'error');
        return;
    }
    try {
        await engJson(`/api/approval-requests/${encodeURIComponent(id)}/decision`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision, reason })
        });
        engNotify(decision === 'approve' ? 'Approved (valid for one call)' : 'Denied', 'success');
    } catch (err) {
        engNotify(err.message, 'error');
    }
    await loadEngagementApprovals();
}


// ---- Inputs (multimodal intake) ----
// Uploaded material is stored unchanged and scanned for URLs/hosts/IPs. Indicators are only
// "discovered": authorization is decided later by the scope engine. Nothing here runs a tool,
// opens a browser or fetches a URL; values are rendered as escaped text, never as links.
async function loadEngagementInputs() {
    const box = document.getElementById('eng-inputs-list');
    if (!currentEngagement || !box) return;
    box.innerHTML = '<div class="tinst-empty">Loading inputs…</div>';
    try {
        const data = await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/inputs`);
        const rows = (data && data.inputs) || [];
        if (!rows.length) { box.innerHTML = '<div class="tinst-empty">No inputs uploaded yet.</div>'; return; }
        box.innerHTML = `<table class="tinst-table"><thead><tr><th>Name</th><th>Detected kind</th><th>Confidence</th><th>Size</th><th>SHA-256</th><th></th></tr></thead><tbody>${rows.map(r => {
            const reasons = engParse(r.reasons) || [];
            return `<tr><td>${engEsc(r.original_name)}</td><td>${engEsc(r.detected_kind)}</td><td>${engEsc(Math.round((r.confidence || 0) * 100))}%</td><td>${engEsc(r.size)}</td><td title="${engEsc(r.sha256)}">${engEsc(String(r.sha256 || '').slice(0, 12))}</td><td><button class="btn-secondary" type="button" data-input-id="${engEsc(r.id)}" onclick="toggleInputIndicators(this.dataset.inputId)">Indicators</button></td></tr>` +
                (reasons.length ? `<tr><td colspan="6" class="tinst-empty">${engEsc(reasons.join('; '))}</td></tr>` : '') +
                `<tr hidden id="eng-input-ind-${engEsc(r.id)}"><td colspan="6"></td></tr>`;
        }).join('')}</tbody></table>`;
    } catch (err) {
        box.innerHTML = `<div class="tinst-empty">Could not load inputs: ${engEsc(err.message)}</div>`;
    }
}

function engDecisionLabel(d) {
    if (!d) return '';
    if (d.error) return `Authorize failed: ${engEsc(d.error)}`;
    if (d.decision === 'IN_SCOPE') return 'authorized (IN_SCOPE)';
    return `${engEsc(d.decision || 'UNKNOWN')}: ${engEsc(d.reason || 'not authorized')}`;
}

function renderInputIndicators(cell, inds, decisions) {
    cell._inds = inds;
    cell._decisions = decisions || {};
    if (!inds.length) { cell.innerHTML = '<span class="tinst-empty">No indicators found.</span>'; return; }
    cell.innerHTML = `<ul>${inds.map(i => {
        const authorized = !!i.authorized;
        const btn = authorized ? '' : ` <button class="btn-secondary" type="button" data-require-permission="project:write" data-indicator-id="${engEsc(i.id)}" onclick="authorizeInputIndicator(this)">Authorize</button>`;
        const dec = cell._decisions[i.id];
        const decHtml = dec ? ` <span class="tinst-empty eng-ind-decision">${engDecisionLabel(dec)}</span>` : '';
        return `<li><code>${engEsc(i.kind)}</code> ${engEsc(i.value)} <span class="tinst-empty">${engEsc(authorized ? 'authorized' : 'discovered, not authorized')}</span>${btn}${decHtml}</li>`;
    }).join('')}</ul>`;
}

async function authorizeInputIndicator(btn) {
    const id = btn.dataset.indicatorId;
    const cell = btn.closest('td');
    if (!id || !cell) return;
    btn.disabled = true;
    const decisions = cell._decisions || {};
    try {
        const data = await engJson(`/api/input-indicators/${encodeURIComponent(id)}/authorize`, { method: 'POST' });
        decisions[id] = { decision: data && data.decision, reason: data && data.reason };
        const updated = data && data.indicator;
        const inds = (cell._inds || []).map(i => (updated && i.id === id) ? Object.assign({}, i, updated) : i);
        renderInputIndicators(cell, inds, decisions);
    } catch (err) {
        decisions[id] = { error: err.message };
        renderInputIndicators(cell, cell._inds || [], decisions);
    }
}

async function toggleInputIndicators(inputId) {
    const row = document.getElementById('eng-input-ind-' + inputId);
    if (!row || !currentEngagement) return;
    if (!row.hidden) { row.hidden = true; return; }
    row.hidden = false;
    const cell = row.firstElementChild;
    cell.innerHTML = 'Loading…';
    try {
        const base = `/api/engagements/${encodeURIComponent(currentEngagement.id)}/inputs/${encodeURIComponent(inputId)}`;
        const data = await engJson(`${base}/indicators`);
        const inds = (data && data.indicators) || [];
        let obsHtml = '';
        try {
            const od = await engJson(`${base}/observations`);
            const obs = (od && od.observations) || [];
            if (obs.length) obsHtml = `<div><strong>Observations</strong><ul>${obs.map(o => `<li><code>${engEsc(o.kind)}</code> ${engEsc(o.summary)}</li>`).join('')}</ul></div>`;
        } catch (e) { /* observations are optional */ }
        renderInputIndicators(cell, inds, {});
        if (obsHtml) cell.insertAdjacentHTML('afterbegin', obsHtml);
    } catch (err) {
        cell.innerHTML = `<span class="tinst-empty">Could not load indicators: ${engEsc(err.message)}</span>`;
    }
}

async function uploadEngagementInput() {
    const el = document.getElementById('eng-input-file');
    if (!currentEngagement || !el || !el.files || !el.files[0]) return;
    const fd = new FormData();
    fd.append('file', el.files[0]);
    try {
        await engJson(`/api/engagements/${encodeURIComponent(currentEngagement.id)}/inputs`, { method: 'POST', body: fd });
        el.value = '';
        loadEngagementInputs();
    } catch (err) {
        const box = document.getElementById('eng-inputs-list');
        if (box) box.insertAdjacentHTML('afterbegin', `<div class="tinst-empty">Upload failed: ${engEsc(err.message)}</div>`);
    }
}
