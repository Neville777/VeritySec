/**
 * Run workspace: modal opened from a finished assistant message. Reads
 * GET /api/runs/:messageId/workspace. Relies on engEsc/engJson/engNotify/engDate and the
 * confidence helpers from engagements.js. No timers: reloads on open and after actions.
 */

let runWorkspaceMessageId = null;

const RW_STATUS_LABELS = {
    running: 'Running',
    completed: 'Completed',
    completed_with_unresolved: 'Completed with unresolved items',
    interrupted: 'Interrupted',
};

function rwBadge(status) {
    const key = RW_STATUS_LABELS[status] ? status : 'unknown';
    const label = RW_STATUS_LABELS[status] || String(status || 'unknown');
    return `<span class="tinst-state rw-status-${engEsc(key)}">${engEsc(label)}</span>`;
}

function rwDuration(ms) {
    const n = Number(ms);
    if (!isFinite(n) || ms == null || ms === '') return '';
    if (n < 1000) return `${Math.round(n)} ms`;
    const s = n / 1000;
    if (s < 60) return `${s.toFixed(1)} s`;
    return `${Math.floor(s / 60)} m ${Math.round(s % 60)} s`;
}

function rwTable(heads, rows, emptyText) {
    if (!rows.length) return `<div class="tinst-empty">${engEsc(emptyText)}</div>`;
    return `<table class="eng-table"><thead><tr>${heads.map(h => `<th>${engEsc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

function rwMessage(text) {
    const m = String(text == null ? '' : text);
    if (m.length <= 200) return `<div class="rw-msg">${engEsc(m)}</div>`;
    return `<div class="rw-msg is-collapsed">${engEsc(m)}</div><button class="tinst-chip rw-more" type="button" onclick="rwToggleMsg(this)">Show more</button>`;
}

function rwToggleMsg(btn) {
    const el = btn.previousElementSibling;
    const collapsed = el.classList.toggle('is-collapsed');
    btn.textContent = collapsed ? 'Show more' : 'Show less';
}

function renderRunWorkspace(d) {
    const run = d.run || {};
    const status = d.status || run.status;
    const disc = d.discoveries || {};
    const model = d.model || {};
    const timeline = d.timeline || [], tools = d.tools || [], evidence = d.evidence || [];
    const findings = d.findings || [], assets = d.assets || [];
    const stat = (n, l) => `<div class="rw-stat"><b>${engEsc(n == null ? 0 : n)}</b><span>${engEsc(l)}</span></div>`;
    const sec = (title, inner) => `<section class="rw-section"><h4>${engEsc(title)}</h4>${inner}</section>`;

    const head = `<div class="rw-head">${rwBadge(status)}
        <span>Duration: ${engEsc(rwDuration(run.duration_ms) || 'n/a')}</span>
        <span class="tinst-path">Started ${engEsc(engDate(run.started_at))}${run.ended_at ? ` · Ended ${engEsc(engDate(run.ended_at))}` : ''}</span>
        <span class="tinst-path">Message ${engEsc(run.message_id)}</span></div>`;
    const strip = `<div class="rw-strip">${stat(disc.assets, 'Assets')}${stat(disc.findings, 'Findings')}${stat(disc.evidence, 'Evidence')}</div>`;
    const tl = rwTable(['#', 'Time', 'Event', 'Message'],
        timeline.map(e => [engEsc(e.seq), engEsc(engDate(e.created_at)), `<span class="tinst-badge">${engEsc(e.event_type)}</span>`, rwMessage(e.message)]),
        'No timeline events recorded for this run.');
    const tt = rwTable(['Tool', 'Status', 'Duration'],
        tools.map(t => [engEsc(t.tool_name) + (t.execution_id ? ` <span class="tinst-path">${engEsc(t.execution_id)}</span>` : ''), engEsc(t.status), engEsc(rwDuration(t.duration_ms))]),
        'No tools were executed in this run.');
    const ev = rwTable(['Title', 'Kind', 'Origin', 'Stage', 'SHA-256'],
        evidence.map(e => [engEsc(e.title || e.id), `<span class="tinst-badge">${engEsc(e.kind)}</span>`,
            engEsc(e.origin) + (String(e.origin).toLowerCase() === 'manual' ? ' <span class="rw-manual">manual</span>' : ''),
            engEsc(e.stage), `<code title="${engEsc(e.sha256)}">${engEsc((e.sha256 || '').slice(0, 12))}</code>`]),
        'No evidence captured in this run.');
    const fi = rwTable(['ID', 'Title', 'Severity', 'Status', 'Confidence'],
        findings.map(f => [`<code>${engEsc(f.id)}</code>`, engEsc(f.title), `<span class="tinst-badge">${engEsc(f.severity)}</span>`, engEsc(f.status), engConfidenceCell(f.id, f.confidence, 'run')]),
        'No findings recorded in this run.');
    const as = rwTable(['ID', 'Host', 'IP', 'Port'],
        assets.map(a => [`<code>${engEsc(a.id)}</code>`, engEsc(a.host), engEsc(a.ip), engEsc(a.port)]),
        'No assets discovered in this run.');
    const usage = `<div class="rw-usage">${engEsc(model.calls || 0)} model calls · ${engEsc(model.prompt_tokens || 0)} prompt tokens · ${engEsc(model.completion_tokens || 0)} completion tokens · ${engEsc(model.cached_tokens || 0)} cached tokens</div>`;

    const resume = status === 'interrupted'
        ? `<div id="rw-resume-box"><button class="btn-secondary" type="button" data-require-permission="chat:write" onclick="rwShowResumePlan()">Resume run</button></div>` : '';

    return head + resume + sec('Discoveries', strip) + sec('Execution timeline', tl) + sec('Tools', tt)
        + sec('Evidence', ev) + sec('Findings', fi) + sec('Assets', as) + sec('Model usage', usage);
}

async function rwShowResumePlan() {
    const box = document.getElementById('rw-resume-box');
    if (!box || !runWorkspaceMessageId) return;
    box.innerHTML = '<div class="tinst-empty">Loading resume plan…</div>';
    try {
        const plan = await engJson(`/api/runs/${encodeURIComponent(runWorkspaceMessageId)}/resume-plan`);
        const done = plan.completed_executions || [], unknown = plan.unknown_executions || [];
        const rows = unknown.map(u => `<div class="rw-resume-unknown" data-exec="${engEsc(u.execution_id)}">
            <code>${engEsc(u.execution_id)}</code> ${engEsc(u.tool_name)} (${engEsc(u.status)})
            <select class="rw-resume-decision" aria-label="Decision for ${engEsc(u.execution_id)}">
                <option value="">Choose a decision…</option>
                <option value="treat_as_not_run">Treat as not run (may run again)</option>
                <option value="treat_as_done">Treat as done (never run again)</option>
            </select></div>`).join('');
        box.innerHTML = `<section class="rw-section"><h4>Resume plan</h4>
            <div>Resume stage: <b>${engEsc(plan.resume_stage || 'n/a')}</b></div>
            <div>Completed executions (will not be repeated): <b>${engEsc(done.length)}</b></div>
            <div>Unknown executions: <b>${engEsc(unknown.length)}</b></div>${rows}
            <label><input type="checkbox" id="rw-resume-confirm"> I confirm resuming this run from its checkpoint</label>
            <div><button class="btn-secondary" type="button" data-require-permission="chat:write" onclick="rwSubmitResume()">Confirm resume</button>
            <button class="btn-secondary" type="button" onclick="reloadRunWorkspace()">Cancel</button></div></section>`;
        if (typeof applyRBACToUI === 'function') applyRBACToUI(box);
    } catch (err) {
        box.innerHTML = `<div class="tinst-empty">Could not load resume plan: ${engEsc(err.message)}</div>`;
    }
}

async function rwSubmitResume() {
    const confirmBox = document.getElementById('rw-resume-confirm');
    if (!confirmBox || !confirmBox.checked) { engNotify('Tick the confirmation first.', 'error'); return; }
    const decisions = [];
    for (const row of document.querySelectorAll('#rw-resume-box .rw-resume-unknown')) {
        const decision = row.querySelector('.rw-resume-decision').value;
        if (!decision) { engNotify('Choose a decision for every unknown execution.', 'error'); return; }
        decisions.push({ execution_id: row.dataset.exec, decision });
    }
    try {
        await engJson(`/api/runs/${encodeURIComponent(runWorkspaceMessageId)}/resume`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ confirm: true, unknown_decisions: decisions }),
        });
        engNotify('Resume started.', 'success');
        reloadRunWorkspace();
    } catch (err) {
        engNotify(`Resume refused: ${err.message}`, 'error');
    }
}

async function reloadRunWorkspace() {
    const body = document.getElementById('run-workspace-body');
    if (!body || !runWorkspaceMessageId) return;
    body.innerHTML = '<div class="tinst-empty">Loading run workspace…</div>';
    try {
        const data = await engJson(`/api/runs/${encodeURIComponent(runWorkspaceMessageId)}/workspace`);
        body.innerHTML = renderRunWorkspace(data || {});
        if (typeof applyRBACToUI === 'function') applyRBACToUI(body);
    } catch (err) {
        body.innerHTML = err.status === 404
            ? '<div class="tinst-empty">Run not found or not available to your account.</div>'
            : `<div class="tinst-empty">Could not load run workspace: ${engEsc(err.message)}</div>`;
    }
}

function openRunWorkspace(messageId) {
    const overlay = document.getElementById('run-workspace-overlay');
    if (!overlay || !messageId) return;
    runWorkspaceMessageId = String(messageId);
    overlay.hidden = false;
    document.addEventListener('keydown', rwEscClose);
    reloadRunWorkspace();
}

function rwEscClose(ev) {
    if (ev.key === 'Escape') closeRunWorkspace();
}

function closeRunWorkspace() {
    const overlay = document.getElementById('run-workspace-overlay');
    if (overlay) overlay.hidden = true;
    runWorkspaceMessageId = null;
    document.removeEventListener('keydown', rwEscClose);
}

window.openRunWorkspace = openRunWorkspace;
window.reloadRunWorkspace = reloadRunWorkspace;
window.closeRunWorkspace = closeRunWorkspace;
window.rwShowResumePlan = rwShowResumePlan;
window.rwSubmitResume = rwSubmitResume;
