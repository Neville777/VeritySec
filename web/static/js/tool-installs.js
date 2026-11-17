/**
 * MCP Management page: tab switching and the security tool install cards.
 * Uses the authenticated apiFetch helper from auth.js.
 */

let toolInstallRows = [];
let toolInstallFilter = 'all';
let toolRiskByCommand = {};

const TINST_GROUPS = [
    { method: 'pipx', title: 'Python (pipx)' },
    { method: 'go', title: 'Go' },
    { method: 'gem', title: 'Ruby gems' },
    { method: 'manual', title: 'System packages (apt)' },
];

function showMcpTab(name) {
    document.querySelectorAll('.mcp-tab[data-mcp-tab]').forEach(btn => {
        const on = btn.dataset.mcpTab === name;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.mcp-tab-pane[data-mcp-pane]').forEach(pane => {
        pane.hidden = pane.dataset.mcpPane !== name;
    });
    if (name === 'installs') {
        if (typeof AppEvents !== 'undefined') AppEvents.connect();
        if (toolInstallRows.length === 0) loadToolInstalls();
    }
    syncToolsTabCount();
}

function syncToolsTabCount() {
    if (typeof toolsPagination !== 'undefined' && toolsPagination.total) setMcpTabCount('tools', toolsPagination.total);
}

function setMcpTabCount(name, value) {
    const el = document.getElementById(`mcp-count-${name}`);
    if (el) el.textContent = value;
}

function toolInstallStatusText(job) {
    if (!job) return '';
    if (job.status === 'running') return `${job.action} running…`;
    if (job.status === 'done') return `${job.action} finished`;
    return `${job.action} failed`;
}

async function loadToolInstalls() {
    const box = document.getElementById('tool-installs-list');
    if (!box) return;
    box.innerHTML = '<div class="tinst-empty">Loading tools…</div>';
    try {
        const r = await apiFetch('/api/tools/installs');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        toolInstallRows = data.tools || [];
        setMcpTabCount('installs', toolInstallRows.filter(t => t.installed).length);
        renderToolInstalls();
    } catch (err) {
        box.innerHTML = `<div class="tinst-empty">Could not load tools: ${escapeHtml(err.message)}</div>`;
    }
}

function setToolInstallFilter(name) {
    toolInstallFilter = name;
    document.querySelectorAll('.tinst-chip[data-tinst-filter]').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tinstFilter === name);
    });
    renderToolInstalls();
}

function filterToolInstalls() {
    renderToolInstalls();
}

function passesFilter(row) {
    if (toolInstallFilter === 'installed') return row.installed;
    if (toolInstallFilter === 'missing') return !row.installed && row.installable;
    if (toolInstallFilter === 'manual') return row.method === 'manual';
    return true;
}

function matchesSearch(row, q) {
    if (!q) return true;
    return [row.command, row.package, row.path || '', row.method].some(v => String(v).toLowerCase().includes(q));
}

function riskClass(rep) {
    if (!rep || rep.error) return '';
    if (rep.max_cvss >= 7) return 'high';
    if (rep.max_cvss >= 4) return 'medium';
    return '';
}

function riskBlock(row) {
    const rep = toolRiskByCommand[row.command];
    if (!row.installed) return '';
    if (!rep) {
        return '<div class="tinst-risk"><span>Risk not checked yet</span></div>';
    }
    if (rep.error && (!rep.vulns || rep.vulns.length === 0)) {
        return `<div class="tinst-risk"><span title="${escapeHtml(rep.error)}">Could not check risk</span></div>`;
    }
    if (!rep.vulns || rep.vulns.length === 0) {
        return '<div class="tinst-risk"><span>No known vulnerabilities</span><div class="tinst-risk-bar"><span style="width:0%"></span></div></div>';
    }
    const pct = Math.min(100, Math.round((rep.max_cvss / 10) * 100));
    const kev = rep.kev_count > 0 ? `<span class="tinst-kev" title="Listed in CISA KEV">KEV ${rep.kev_count}</span>` : '';
    const ids = rep.vulns.slice(0, 3).map(v => escapeHtml(v.id)).join(', ');
    return `<div class="tinst-risk ${riskClass(rep)}">
        <span>${rep.vulns.length} vuln(s) · max CVSS ${rep.max_cvss.toFixed(1)}${kev}</span>
        <div class="tinst-risk-bar"><span style="width:${pct}%"></span></div>
        <span class="tinst-path" title="${escapeHtml(ids)}">${ids}</span>
    </div>`;
}

function cardActions(row) {
    const cmd = escapeHtml(row.command);
    if (!row.installable) {
        return `<div class="tinst-actions tinst-manual"><span>Run in a terminal: <code>sudo apt install ${escapeHtml(row.package)}</code></span></div>`;
    }
    if (row.installed) {
        return `<div class="tinst-actions">
            <button onclick="startToolInstall('${cmd}', 'upgrade')">Upgrade</button>
            <button class="tinst-danger" onclick="startToolInstall('${cmd}', 'uninstall')">Remove</button>
            <span class="tinst-job" id="tool-install-job-${cmd}"></span>
        </div>`;
    }
    return `<div class="tinst-actions">
        <button class="tinst-install" onclick="startToolInstall('${cmd}', 'install')">Install</button>
        <span class="tinst-job" id="tool-install-job-${cmd}"></span>
    </div>`;
}

function toolCard(row) {
    const cmd = escapeHtml(row.command);
    const state = row.installed
        ? '<span class="tinst-state ok">Installed</span>'
        : (row.installable ? '<span class="tinst-state missing">Not installed</span>' : '<span class="tinst-state">System package</span>');
    const path = row.path ? `<div class="tinst-path" title="${escapeHtml(row.path)}">${escapeHtml(row.path)}</div>` : '';
    return `<article class="tinst-card ${row.installed ? '' : 'is-missing'}" data-command="${cmd}">
        <div class="tinst-card-head">
            <span class="tinst-name" title="${cmd}">${cmd}</span>
            ${state}
        </div>
        <div class="tinst-meta">
            <span class="tinst-badge">${escapeHtml(row.method)}</span>
            <span class="tinst-badge">${escapeHtml(row.package)}</span>
        </div>
        ${path}
        ${riskBlock(row)}
        ${cardActions(row)}
    </article>`;
}

function renderToolInstalls() {
    const box = document.getElementById('tool-installs-list');
    if (!box) return;
    const q = (document.getElementById('tool-installs-search')?.value || '').trim().toLowerCase();
    const visible = toolInstallRows.filter(r => passesFilter(r) && matchesSearch(r, q));
    const installed = toolInstallRows.filter(r => r.installed).length;
    const stats = document.getElementById('tool-installs-stats');
    if (stats) stats.textContent = `${installed} of ${toolInstallRows.length} installed · showing ${visible.length}`;

    if (visible.length === 0) {
        box.innerHTML = '<div class="tinst-empty">No tools match this filter.</div>';
        return;
    }
    box.innerHTML = TINST_GROUPS.map(group => {
        const rows = visible.filter(r => r.method === group.method);
        if (rows.length === 0) return '';
        const inGroup = toolInstallRows.filter(r => r.method === group.method);
        const have = inGroup.filter(r => r.installed).length;
        return `<section class="tinst-group">
            <h3 class="tinst-group-title">${group.title} <small>${have} of ${inGroup.length} installed</small></h3>
            <div class="tinst-grid">${rows.map(toolCard).join('')}</div>
        </section>`;
    }).join('');
}

async function startToolInstall(command, action) {
    if (action === 'uninstall' && !confirm(`Remove ${command}?`)) return;
    if (action === 'upgrade' && !confirm(`Upgrade ${command} to the latest release?`)) return;
    const cell = document.getElementById(`tool-install-job-${command}`);
    try {
        const r = await apiFetch('/api/tools/installs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command, action }),
        });
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
        if (cell) cell.textContent = toolInstallStatusText(data);
        if (typeof AppEvents !== 'undefined') AppEvents.connect();
    } catch (err) {
        if (cell) cell.textContent = `Error: ${err.message}`;
    }
}

function handleToolInstallEvent(job, finished) {
    const cell = document.getElementById(`tool-install-job-${job.command}`);
    if (cell) cell.textContent = toolInstallStatusText(job);
    if (finished) {
        const ok = job.status === 'done';
        if (typeof showNotification === 'function') {
            showNotification(`${job.command}: ${job.action} ${ok ? 'finished' : 'failed'}`, ok ? 'success' : 'error');
        }
        loadToolInstalls();
    }
}

if (typeof AppEvents !== 'undefined') {
    AppEvents.on('tools.install.started', job => handleToolInstallEvent(job, false));
    AppEvents.on('tools.install.finished', job => handleToolInstallEvent(job, true));
}

async function checkToolRisk() {
    const btn = document.getElementById('tool-risk-check');
    if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
    try {
        const r = await apiFetch('/api/tools/risk');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();
        toolRiskByCommand = {};
        for (const rep of data.reports || []) toolRiskByCommand[rep.command] = rep;
        renderToolInstalls();
    } catch (err) {
        const stats = document.getElementById('tool-installs-stats');
        if (stats) stats.textContent = `Risk check failed: ${err.message}`;
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Check risk'; }
    }
}

// Keep the Tools tab count in step with the tool list.
window.addEventListener('load', () => {
    syncToolsTabCount();
    if (typeof AppEvents !== 'undefined') AppEvents.connect();
});
