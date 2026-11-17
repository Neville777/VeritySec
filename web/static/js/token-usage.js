// Token detail data belongs to the settings section; the dashboard keeps a
// separate fixed seven-day summary.
var tokenUsageState = { days: 7, controller: null, requestSequence: 0, result: null, trendMetric: 'totalTokens' };

function tokenUsageText(key, opts, fallback) {
    if (typeof window.t === 'function') {
        const text = window.t(key, opts);
        if (text && text !== key) return text;
    }
    return fallback == null ? key : fallback;
}

function openDashboardTokenUsage() {
    if (getRoutePath() === 'settings?section=token-usage') {
        switchPage('settings');
        switchSettingsSection('token-usage');
    } else {
        setRoutePath('settings?section=token-usage');
    }
}

function stopTokenUsageRequests() {
    tokenUsageState.requestSequence++;
    if (tokenUsageState.controller) tokenUsageState.controller.abort();
    tokenUsageState.controller = null;
}

async function refreshTokenUsage() {
    const host = document.getElementById('settings-token-analysis');
    if (!host) return;
    stopTokenUsageRequests();
    const sequence = tokenUsageState.requestSequence;
    const controller = new AbortController();
    tokenUsageState.controller = controller;
    host.setAttribute('aria-busy', 'true');
    host.textContent = tokenUsageText('common.loading', null, 'Loading…');
    const select = document.getElementById('settings-token-days');
    if (select) select.value = String(tokenUsageState.days);
    let url = '/api/usage/tokens?days=' + tokenUsageState.days + '&limit=20';
    const projectId = typeof getActiveProjectId === 'function' ? getActiveProjectId() : '';
    const scope = document.getElementById('settings-token-scope');
    if (scope) scope.textContent = tokenUsageText('tokenUsageUI.' + (projectId ? 'scopeProject' : 'scopeAccessible'), null, projectId ? 'Current project' : 'Accessible conversations');
    if (projectId) url += '&project_id=' + encodeURIComponent(projectId);
    try {
        const response = await apiFetch(url, { signal: controller.signal });
        const result = response && response.ok ? await response.json() : null;
        if (sequence !== tokenUsageState.requestSequence) return;
        tokenUsageState.result = result;
        renderTokenUsageAnalysis(result);
        loadPerCallUsage();
    } catch (_) {
        if (sequence !== tokenUsageState.requestSequence) return;
        tokenUsageState.result = null;
        renderTokenUsageAnalysis(null);
    } finally {
        if (sequence === tokenUsageState.requestSequence) {
            tokenUsageState.controller = null;
            host.removeAttribute('aria-busy');
        }
    }
}

function changeTokenUsagePeriod(value) {
    const days = Number(value);
    if (![7, 30, 90].includes(days)) return;
    tokenUsageState.days = days;
    refreshTokenUsage();
}

function tokenUsageCacheRate(summary) {
    const input = tokenUsageCount(summary && summary.promptTokens);
    const cached = tokenUsageCount(summary && summary.cachedTokens);
    return input > 0 ? (Math.min(cached, input) / input * 100).toFixed(1) + '%' : '—';
}

function tokenUsageCount(value) {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.trunc(n) : 0;
}

function tokenUsageMetrics(summary) {
    const input = tokenUsageCount(summary.promptTokens);
    const cached = tokenUsageCount(summary.cachedTokens);
    return [
        ['usageTotal', summary.totalTokens],
        ['usageInput', input],
        ['usageOutput', summary.completionTokens],
        ['usageCacheRead', cached],
        ['usageCacheWrite', summary.cacheWriteTokens],
        ['usageReasoning', summary.reasoningTokens],
        ['usageCalls', summary.modelCalls],
        ['usageCacheRate', tokenUsageCacheRate(summary)]
    ];
}

document.addEventListener('languagechange', function () {
    if (tokenUsageState.controller) return;
    const page = document.getElementById('page-settings');
    const section = document.getElementById('settings-section-token-usage');
    if (page && page.classList.contains('active') && section && section.classList.contains('active')) {
        renderTokenUsageAnalysis(tokenUsageState.result);
    }
});

function tokenUsageNode(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
}

// Fill only gaps between returned dates. The API's server-local day keys are
// authoritative; do not invent a browser-timezone endpoint for the period.
function tokenUsageTimeline(rows) {
    const dated = (rows || []).filter(row => /^\d{4}-\d{2}-\d{2}$/.test(row.key || '')).sort((a, b) => a.key.localeCompare(b.key));
    if (!dated.length) return [];
    const byDay = new Map(dated.map(row => [row.key, row]));
    const start = Date.parse(dated[0].key + 'T00:00:00Z');
    const end = Date.parse(dated[dated.length - 1].key + 'T00:00:00Z');
    if (!Number.isFinite(start) || !Number.isFinite(end)) return dated;
    const days = [];
    for (let time = start; time <= end && days.length < 365; time += 86400000) {
        const key = new Date(time).toISOString().slice(0, 10);
        days.push(byDay.get(key) || { key, events: 0, totalTokens: 0, modelCalls: 0, promptTokens: 0 });
    }
    return days;
}

function setTokenUsageTrend(metric) {
    if (!['totalTokens', 'modelCalls', 'cacheRate'].includes(metric)) return;
    tokenUsageState.trendMetric = metric;
    renderTokenUsageAnalysis(tokenUsageState.result);
    const button = document.querySelector('[data-token-trend="' + metric + '"]');
    if (button) button.focus();
}

function renderTokenUsageAnalysis(res) {
    const host = document.getElementById('settings-token-analysis');
    if (!host) return;
    host.replaceChildren();
    const label = key => tokenUsageText('dashboard.' + key, null, key);
    const ui = key => tokenUsageText('tokenUsageUI.' + key, null, key);
    const exact = value => tokenUsageCount(value).toLocaleString(window.__locale || 'zh-CN');
    if (!res || !res.summary) {
        const empty = tokenUsageNode('div', 'token-usage-empty', label('usageUnavailable'));
        host.append(empty);
        return;
    }
    const summary = res.summary;
    const metrics = new Map(tokenUsageMetrics(summary));
    const primary = tokenUsageNode('div', 'token-usage-metrics token-usage-primary');
    const secondary = tokenUsageNode('div', 'token-usage-metrics token-usage-secondary');
    const primaryKeys = ['usageTotal', 'usageInput', 'usageOutput', 'usageCacheRate'];
    [...primaryKeys, 'usageCalls', 'usageCacheRead', 'usageCacheWrite', 'usageReasoning'].forEach(key => {
        const value = metrics.get(key);
        const card = tokenUsageNode('div', 'token-usage-metric');
        card.dataset.metric = key;
        card.append(tokenUsageNode('span', '', label(key)), tokenUsageNode('strong', '', typeof value === 'string' ? value : exact(value)));
        (primaryKeys.includes(key) ? primary : secondary).append(card);
    });
    host.append(primary, secondary);
    if (!tokenUsageCount(summary.events)) {
        host.append(tokenUsageNode('div', 'token-usage-empty', label('noTokenUsageYet')));
        return;
    }

    const chartLayout = tokenUsageNode('div', 'token-usage-charts');
    const chart = tokenUsageNode('section', 'token-usage-chart-card');
    const chartHead = tokenUsageNode('div', 'token-usage-chart-head');
    chartHead.append(tokenUsageNode('h4', '', label('usageTrend')));
    const tabs = tokenUsageNode('div', 'token-usage-chart-tabs');
    tabs.setAttribute('role', 'group');
    tabs.setAttribute('aria-label', ui('trendMetric'));
    for (const [metric, key] of [['totalTokens', 'usageTotal'], ['modelCalls', 'usageCalls'], ['cacheRate', 'usageCacheRate']]) {
        const button = tokenUsageNode('button', '', label(key));
        button.type = 'button';
        button.dataset.tokenTrend = metric;
        button.setAttribute('aria-pressed', String(tokenUsageState.trendMetric === metric));
        button.addEventListener('click', () => setTokenUsageTrend(metric));
        tabs.append(button);
    }
    chartHead.append(tabs);
    chart.append(chartHead);
    const tooltip = tokenUsageNode('p', 'token-usage-chart-tooltip', ui('chartHint'));
    tooltip.setAttribute('aria-live', 'polite');
    const days = tokenUsageTimeline(res.byDay);
    const metric = tokenUsageState.trendMetric;
    const valueOf = row => metric === 'cacheRate' ? (tokenUsageCount(row.promptTokens) ? Math.min(tokenUsageCount(row.cachedTokens), tokenUsageCount(row.promptTokens)) / tokenUsageCount(row.promptTokens) * 100 : 0) : tokenUsageCount(row[metric]);
    const peak = metric === 'cacheRate' ? 100 : Math.max(1, ...days.map(valueOf));
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', '0 0 640 230');
    svg.setAttribute('role', 'group');
    svg.setAttribute('aria-label', label('usageTrend'));
    svg.classList.add('token-usage-trend-svg');
    const element = (tag, attrs, text) => {
        const node = document.createElementNS(svgNS, tag);
        Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)));
        if (text != null) node.textContent = text;
        return node;
    };
    for (let tick = 0; tick <= 4; tick++) {
        const y = 18 + tick * 44;
        svg.append(element('line', { x1: 54, x2: 624, y1: y, y2: y, class: 'token-usage-chart-grid' }));
        svg.append(element('text', { x: 46, y: y + 4, 'text-anchor': 'end', class: 'token-usage-chart-label' }, metric === 'cacheRate' ? (100 - tick * 25) + '%' : formatTokenUsageCompact(peak * (4 - tick) / 4)));
    }
    const slot = 570 / Math.max(days.length, 1);
    const every = Math.max(1, Math.ceil(days.length / 7));
    days.forEach((row, index) => {
        const x = 54 + slot * (index + .5);
        const height = valueOf(row) / peak * 176;
        const detail = row.key + ' · ' + label('usageTotal') + ' ' + exact(row.totalTokens) + ' · ' + label('usageCalls') + ' ' + exact(row.modelCalls) + ' · ' + label('usageCacheRate') + ' ' + tokenUsageCacheRate(row);
        const bar = element('rect', { x: x - Math.min(24, slot * .55) / 2, y: 194 - height, width: Math.min(24, slot * .55), height: Math.max(height, 1), rx: 3, class: 'token-usage-chart-bar', tabindex: 0, 'aria-label': detail });
        bar.append(element('title', {}, detail));
        for (const event of ['mouseenter', 'focus']) bar.addEventListener(event, () => { tooltip.textContent = detail; });
        for (const event of ['mouseleave', 'blur']) bar.addEventListener(event, () => { tooltip.textContent = ui('chartHint'); });
        svg.append(bar);
        if (index % every === 0 || index === days.length - 1) {
            svg.append(element('text', { x, y: 218, 'text-anchor': 'middle', class: 'token-usage-chart-label' }, row.key.slice(5)));
        }
    });
    const plot = tokenUsageNode('div', 'token-usage-svg-wrap');
    plot.append(svg);
    chart.append(plot);
    chart.append(tooltip);
    if (!days.length) chart.append(tokenUsageNode('p', 'token-usage-empty', ui('noDailyData')));
    chartLayout.append(chart);

    const cache = tokenUsageNode('section', 'token-usage-chart-card token-usage-cache-card');
    cache.append(tokenUsageNode('h4', '', ui('cacheComposition')));
    const input = tokenUsageCount(summary.promptTokens);
    const cached = Math.min(input, tokenUsageCount(summary.cachedTokens));
    const ratio = input ? cached / input * 100 : 0;
    const ring = tokenUsageNode('div', 'token-usage-cache-ring');
    ring.style.setProperty('--cache-ratio', ratio + '%');
    ring.append(tokenUsageNode('strong', '', tokenUsageCacheRate(summary)), tokenUsageNode('span', '', ui('cacheHit')));
    cache.append(ring);
    for (const [key, value, className] of [['usageCacheRead', cached, 'is-cached'], ['uncachedInput', input - cached, 'is-uncached']]) {
        const line = tokenUsageNode('div', 'token-usage-cache-legend ' + className);
        line.append(tokenUsageNode('span', '', key === 'uncachedInput' ? ui(key) : label(key)), tokenUsageNode('strong', '', exact(value)));
        cache.append(line);
    }
    cache.append(tokenUsageNode('p', 'token-usage-chart-note', ui('cacheNote')));
    chartLayout.append(cache);
    host.append(chartLayout);

    // Provider labels are untrusted: render all values as text or constructed
    // nodes, never as HTML. Full precision is retained in every table.
    const table = (titleKey, headings, rows, collapsed = false) => {
        const section = tokenUsageNode(collapsed ? 'details' : 'section', 'token-usage-data-card');
        const title = tokenUsageNode(collapsed ? 'summary' : 'h4', '', label(titleKey));
        const wrap = tokenUsageNode('div', 'token-usage-table-wrap');
        const grid = tokenUsageNode('table');
        const caption = tokenUsageNode('caption', 'sr-only', label(titleKey));
        const head = tokenUsageNode('thead');
        const hr = tokenUsageNode('tr');
        headings.forEach(key => { const th = tokenUsageNode('th', '', label(key)); th.scope = 'col'; hr.append(th); });
        head.append(hr);
        const body = tokenUsageNode('tbody');
        rows.forEach(values => {
            const tr = tokenUsageNode('tr');
            values.forEach(value => {
                const td = tokenUsageNode('td');
                if (value && value.nodeType) td.append(value);
                else td.textContent = String(value == null ? '' : value);
                tr.append(td);
            });
            body.append(tr);
        });
        grid.append(caption, head, body);
        wrap.append(grid);
        section.append(title, wrap);
        host.append(section);
    };
    const counts = row => [exact(row.promptTokens), exact(row.completionTokens), exact(row.cachedTokens), exact(row.cacheWriteTokens), exact(row.reasoningTokens), exact(row.totalTokens), exact(row.modelCalls)];
    const fields = ['usageInput', 'usageOutput', 'usageCacheRead', 'usageCacheWrite', 'usageReasoning', 'usageTotal', 'usageCalls'];
    table('usageByModel', ['usageModel', 'usageShare', ...fields], (res.byModel || []).map(row => {
        const ratio = tokenUsageCount(summary.totalTokens) ? tokenUsageCount(row.totalTokens) / tokenUsageCount(summary.totalTokens) * 100 : 0;
        const share = tokenUsageNode('div', 'token-usage-share');
        share.append(tokenUsageNode('span', '', ratio.toFixed(1) + '%'));
        const track = tokenUsageNode('span', 'token-usage-share-track');
        const fill = tokenUsageNode('span'); fill.style.width = Math.min(100, ratio) + '%'; track.append(fill); share.append(track);
        return [row.label || row.key, share, ...counts(row)];
    }));
    table('usageByDay', ['usageDate', ...fields], (res.byDay || []).map(row => [row.key, ...counts(row)]), true);
    table('usageRecent', ['usageTime', 'usageModel', 'usageStatus', 'usageTotal', 'usageCalls'], (res.recent || []).map(row => {
        const time = new Date(row.createdAt);
        const status = tokenUsageNode('span', 'token-usage-status', row.reason === 'final' ? label('usageFinal') : row.reason === 'partial' ? label('usagePartial') : (row.reason || '—'));
        if (row.reason === 'final' || row.reason === 'partial') status.classList.add('is-' + row.reason);
        return [Number.isFinite(time.getTime()) ? time.toLocaleString(window.__locale || 'zh-CN') : '—', row.model || '—', status, exact(row.totalTokens), exact(row.modelCalls)];
    }));
}

// Per-call usage. The server does not expose per-call rows yet (model_call_usage is written but
// not served), so a 404/405 or an empty answer renders "no per-call data yet".
// Download recent per-call usage as CSV, using the same authenticated download helper as the engagement pages.
function tokenUsageDownloadCalls() {
    if (typeof engDownload !== 'function') return;
    engDownload('/api/usage/calls?format=csv&limit=500', 'model-calls.csv').catch(err => {
        if (typeof showNotification === 'function') showNotification('Download failed: ' + err.message, 'error');
    });
}

async function loadPerCallUsage() {
    const host = document.getElementById('token-percall');
    if (!host) return;
    host.textContent = 'Loading per-call usage…';
    let calls = null;
    try {
        const response = await apiFetch('/api/usage/calls?limit=50');
        if (response && response.ok) {
            const data = await response.json();
            calls = Array.isArray(data) ? data : (data.calls || data.items || []);
        } else if (response && response.status !== 404 && response.status !== 405) {
            host.replaceChildren(tokenUsageNode('div', 'tinst-empty', 'Could not load per-call usage (HTTP ' + response.status + ').'));
            return;
        }
    } catch (err) {
        host.replaceChildren(tokenUsageNode('div', 'tinst-empty', 'Could not load per-call usage: ' + (err && err.message ? err.message : err)));
        return;
    }
    if (!calls || calls.length === 0) {
        host.replaceChildren(tokenUsageNode('div', 'tinst-empty', 'No per-call data yet.'));
        return;
    }
    renderPerCallUsage(host, calls);
}

function perCallField(row, snake, camel) {
    const v = row[snake] != null ? row[snake] : row[camel];
    return v == null ? 0 : v;
}

function perCallManifest(row) {
    let m = row.manifest_json != null ? row.manifest_json : row.manifestJson;
    if (typeof m === 'string' && m) { try { m = JSON.parse(m); } catch (_) { m = null; } }
    return m && typeof m === 'object' ? m : null;
}

function perCallManifestRows(m) {
    const rows = [];
    ['system', 'tools', 'user', 'assistant'].forEach(k => { if (m[k] != null && typeof m[k] !== 'object') rows.push([k, m[k]]); });
    const tr = m.tool_results != null ? m.tool_results : m.toolResults;
    if (tr && typeof tr === 'object') {
        Object.keys(tr).forEach(name => rows.push(['tool result: ' + name, tr[name]]));
    } else if (tr != null) {
        rows.push(['tool results', tr]);
    }
    return rows;
}

function renderPerCallUsage(host, calls) {
    const dl = document.createElement('button');
    dl.type = 'button';
    dl.className = 'btn-secondary';
    dl.textContent = 'Download CSV';
    dl.addEventListener('click', tokenUsageDownloadCalls);
    host.appendChild(dl);
    const table = tokenUsageNode('table', 'eng-table');
    const head = tokenUsageNode('tr');
    ['Time', 'Conversation', 'Call', 'Prompt', 'Completion', 'Cached', 'Manifest'].forEach(h => head.appendChild(tokenUsageNode('th', null, h)));
    table.appendChild(tokenUsageNode('thead')).appendChild(head);
    const body = tokenUsageNode('tbody');
    calls.forEach(row => {
        const tr = tokenUsageNode('tr');
        const when = row.created_at || row.createdAt;
        const d = when ? new Date(when) : null;
        tr.appendChild(tokenUsageNode('td', null, d && !isNaN(d.getTime()) ? d.toLocaleString() : ''));
        tr.appendChild(tokenUsageNode('td', null, String(row.conversation_id || row.conversationId || '')));
        tr.appendChild(tokenUsageNode('td', null, String(perCallField(row, 'call_index', 'callIndex'))));
        tr.appendChild(tokenUsageNode('td', null, String(perCallField(row, 'prompt_tokens', 'promptTokens'))));
        tr.appendChild(tokenUsageNode('td', null, String(perCallField(row, 'completion_tokens', 'completionTokens'))));
        tr.appendChild(tokenUsageNode('td', null, String(perCallField(row, 'cached_tokens', 'cachedTokens'))));
        const mcell = tokenUsageNode('td');
        const m = perCallManifest(row);
        const rows = m ? perCallManifestRows(m) : [];
        if (rows.length) {
            const det = tokenUsageNode('details');
            det.appendChild(tokenUsageNode('summary', null, 'Breakdown'));
            const ul = tokenUsageNode('ul', 'token-percall-manifest');
            rows.forEach(r => ul.appendChild(tokenUsageNode('li', null, r[0] + ': ' + r[1])));
            det.appendChild(ul);
            mcell.appendChild(det);
        } else {
            mcell.textContent = '—';
        }
        tr.appendChild(mcell);
        body.appendChild(tr);
    });
    table.appendChild(body);
    host.replaceChildren(table);
}
