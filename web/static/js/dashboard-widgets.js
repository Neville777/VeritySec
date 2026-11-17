// Dashboard sub-components: Heatmap, Detection Counters, Recent Tests, CVE Feed
// These are real components with internal state, sub-rendering, and data fetching.

(function () {
    'use strict';

    // ================================================================
    //  1. TESTING ACTIVITY HEATMAP
    //     GitHub-style contribution grid. Data source: vulnerabilities
    //     created_at timestamps bucketed by day over the last ~52 weeks.
    // ================================================================

    var HeatmapWidget = {
        _built: false,
        _data: {},          // { 'YYYY-MM-DD': count }
        _tooltipEl: null,

        build: function () {
            var grid = document.getElementById('dashboard-heatmap-grid');
            var months = document.getElementById('dashboard-heatmap-months');
            if (!grid || this._built) return;

            var today = new Date();
            var dayOfWeek = today.getDay(); // 0=Sun
            var totalDays = 52 * 7 + dayOfWeek + 1;
            var startDate = new Date(today);
            startDate.setDate(startDate.getDate() - totalDays + 1);

            // adjust to start on Sunday
            var startDow = startDate.getDay();
            if (startDow !== 0) {
                startDate.setDate(startDate.getDate() - startDow);
                totalDays += startDow;
            }

            grid.innerHTML = '';
            var cells = [];
            var currentMonth = -1;
            var monthLabels = [];
            var colCount = Math.ceil(totalDays / 7);

            for (var i = 0; i < totalDays; i++) {
                var d = new Date(startDate);
                d.setDate(startDate.getDate() + i);
                var key = _dateKey(d);
                var cell = document.createElement('div');
                cell.className = 'dashboard-heatmap-cell';
                cell.dataset.date = key;
                cell.dataset.level = '0';
                cell.title = key + ': 0 activities';
                grid.appendChild(cell);
                cells.push({ el: cell, date: key });

                // month labels — track when a new month starts at the top row
                var dayIdx = i % 7;
                if (dayIdx === 0) {
                    var colIdx = Math.floor(i / 7);
                    var m = d.getMonth();
                    if (m !== currentMonth) {
                        currentMonth = m;
                        monthLabels.push({ col: colIdx, name: _monthName(m) });
                    }
                }
            }

            // render month headers
            if (months) {
                months.innerHTML = '';
                var colW = 16; // 13px cell + 3px gap
                for (var mi = 0; mi < monthLabels.length; mi++) {
                    var span = document.createElement('span');
                    span.textContent = monthLabels[mi].name;
                    var nextCol = mi + 1 < monthLabels.length ? monthLabels[mi + 1].col : colCount;
                    span.style.width = ((nextCol - monthLabels[mi].col) * colW) + 'px';
                    months.appendChild(span);
                }
            }

            this._cells = cells;
            this._built = true;
        },

        update: function (dateCounts) {
            this._data = dateCounts || {};
            if (!this._cells) return;

            // find max for quantile
            var max = 0;
            for (var k in this._data) {
                if (this._data[k] > max) max = this._data[k];
            }

            for (var i = 0; i < this._cells.length; i++) {
                var c = this._cells[i];
                var count = this._data[c.date] || 0;
                var level = _quantize(count, max);
                c.el.dataset.level = String(level);
                c.el.title = c.date + ': ' + count + ' activit' + (count === 1 ? 'y' : 'ies');
            }
        }
    };

    function _dateKey(d) {
        var y = d.getFullYear();
        var m = String(d.getMonth() + 1).padStart(2, '0');
        var day = String(d.getDate()).padStart(2, '0');
        return y + '-' + m + '-' + day;
    }
    function _monthName(m) {
        return ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][m];
    }
    function _quantize(val, max) {
        if (!val || !max) return 0;
        var r = val / max;
        if (r <= 0) return 0;
        if (r < 0.25) return 1;
        if (r < 0.5) return 2;
        if (r < 0.75) return 3;
        return 4;
    }

    // ================================================================
    //  2. DETECTION COUNTERS
    //     Vuln counts for 7d / 30d. Data source: /api/vulnerabilities
    //     with date filters.
    // ================================================================

    var DetectionCounters = {
        update: function (count7d, count30d) {
            var el7 = document.getElementById('dashboard-detect-7d');
            var el30 = document.getElementById('dashboard-detect-30d');
            if (el7) el7.textContent = _formatCount(count7d);
            if (el30) el30.textContent = _formatCount(count30d);
        }
    };

    function _formatCount(n) {
        if (n == null) return '-';
        if (n >= 10000) return (n / 1000).toFixed(0) + 'k';
        return String(n);
    }

    // ================================================================
    //  3. RECENT TESTS
    //     Latest engagements. Data source: /api/engagements?limit=5
    // ================================================================

    var RecentTestsWidget = {
        render: function (engagements) {
            var body = document.getElementById('dashboard-recent-tests-body');
            if (!body) return;
            if (!engagements || engagements.length === 0) {
                body.innerHTML =
                    '<div class="dashboard-recent-tests-empty">'
                    + '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.5"><rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/></svg>'
                    + '<p>No tests yet</p>'
                    + '<p style="font-size:12px;color:var(--text-muted);">Run your first pentest to see results here</p>'
                    + '</div>';
                return;
            }
            body.innerHTML = engagements.slice(0, 5).map(function (e) {
                var status = (e.status || 'draft').toLowerCase();
                var vulnCount = e.vulnerability_count || 0;
                var name = _escHtml(e.name || e.id || 'Unnamed');
                var timeAgo = e.updated_at ? _relTime(e.updated_at) : '';
                return '<div class="dashboard-recent-test-item">'
                    + '<span class="dashboard-recent-test-name" title="' + name + '">' + name + '</span>'
                    + '<div class="dashboard-recent-test-meta">'
                    + (vulnCount ? '<span class="dashboard-recent-test-vulns">' + vulnCount + ' finding' + (vulnCount !== 1 ? 's' : '') + '</span>' : '')
                    + '<span class="dashboard-recent-test-status" data-status="' + status + '">' + _escHtml(status) + '</span>'
                    + (timeAgo ? '<span style="font-size:11px;color:var(--text-muted);">' + timeAgo + '</span>' : '')
                    + '</div></div>';
            }).join('');
        }
    };

    // ================================================================
    //  4. CVE FEED — "What's New in Cyber"
    //     Latest CVEs from the cache. Data source: /api/cves?limit=8
    // ================================================================

    var CVEFeedWidget = {
        render: function (cves) {
            var body = document.getElementById('dashboard-cve-feed-body');
            if (!body) return;
            if (!cves || cves.length === 0) {
                body.innerHTML = '<div style="color:var(--text-muted);font-size:13px;padding:16px 0;text-align:center;">'
                    + 'No CVE data cached yet. The feed populates as CVEs are linked to findings or fetched externally.'
                    + '</div>';
                return;
            }
            body.innerHTML = cves.map(function (cve) {
                var cvss = cve.cvss_score != null ? parseFloat(cve.cvss_score).toFixed(1) : null;
                var sevLabel = _cvssToSev(cvss);
                var epss = cve.epss_score != null ? (parseFloat(cve.epss_score) * 100).toFixed(1) + '%' : null;
                var kev = cve.kev_known_exploited;
                var pubDate = cve.published_at ? _relTime(cve.published_at) : (cve.fetched_at ? _relTime(cve.fetched_at) : '');

                return '<div class="dashboard-cve-item" style="cursor:pointer" onclick="if(typeof openCVEDetail===\'function\')openCVEDetail(\'' + _escHtml(cve.cve_id) + '\')">'
                    + '<div class="dashboard-cve-item-left">'
                    + '<div class="dashboard-cve-id">' + _escHtml(cve.cve_id) + '</div>'
                    + '<div class="dashboard-cve-desc" title="' + _escHtml(cve.description || '') + '">' + _escHtml(cve.description || 'No description available') + '</div>'
                    + '</div>'
                    + '<div class="dashboard-cve-item-right">'
                    + '<span class="dashboard-cve-time">' + pubDate + '</span>'
                    + '<div class="dashboard-cve-badges">'
                    + (cve.category && typeof cveCatBadgeHTML === 'function' ? cveCatBadgeHTML(cve.category) : '')
                    + (kev ? '<span class="dashboard-cve-kev">KEV</span>' : '')
                    + (sevLabel ? '<span class="dashboard-cve-severity" data-sev="' + sevLabel + '">' + sevLabel.charAt(0).toUpperCase() + sevLabel.slice(1) + '</span>' : '')
                    + (cvss != null ? '<span class="dashboard-cve-cvss">CVSS ' + cvss + '</span>' : '')
                    + '</div>'
                    + '</div>'
                    + '</div>';
            }).join('');
        }
    };

    function _cvssToSev(cvss) {
        if (cvss == null) return null;
        var v = parseFloat(cvss);
        if (v >= 9) return 'critical';
        if (v >= 7) return 'high';
        if (v >= 4) return 'medium';
        return 'low';
    }

    function _relTime(dateStr) {
        try {
            var d = new Date(dateStr);
            var now = new Date();
            var diff = now - d;
            if (diff < 60000) return 'just now';
            if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
            if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
            var days = Math.floor(diff / 86400000);
            if (days === 0) return 'today';
            if (days === 1) return 'yesterday';
            if (days < 7) return days + 'd ago';
            if (days < 30) return Math.floor(days / 7) + 'w ago';
            return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        } catch (e) {
            return '';
        }
    }

    function _escHtml(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ================================================================
    //  5. MASTER REFRESH — called from the main refreshDashboard hook
    // ================================================================

    async function refreshDashboardWidgets() {
        if (typeof apiFetch === 'undefined') return;

        // Build heatmap grid on first call
        HeatmapWidget.build();

        var fetchJson = function (url) {
            return apiFetch(url)
                .then(function (r) { return r && r.ok ? r.json() : null; })
                .catch(function () { return null; });
        };

        // Parallel data fetch for all widgets
        var now = new Date();
        var d7 = new Date(now);
        d7.setDate(d7.getDate() - 7);
        var d30 = new Date(now);
        d30.setDate(d30.getDate() - 30);
        var d365 = new Date(now);
        d365.setDate(d365.getDate() - 365);

        var iso7 = d7.toISOString();
        var iso30 = d30.toISOString();

        try {
            var results = await Promise.all([
                // 7-day vuln count
                fetchJson('/api/vulnerabilities?limit=1&created_after=' + encodeURIComponent(iso7)),
                // 30-day vuln count
                fetchJson('/api/vulnerabilities?limit=1&created_after=' + encodeURIComponent(iso30)),
                // recent engagements
                fetchJson('/api/engagements?limit=5'),
                // CVE cache
                fetchJson('/api/cves?limit=8'),
                // all vulns for heatmap (we'll count by created_at date)
                fetchJson('/api/vulnerabilities?limit=500&page=1'),
            ]);

            var vulns7d = results[0];
            var vulns30d = results[1];
            var engagements = results[2];
            var cves = results[3];
            var allVulns = results[4];

            // Detection counters
            var count7 = 0, count30 = 0;
            if (vulns7d) count7 = vulns7d.total || (vulns7d.vulnerabilities ? vulns7d.vulnerabilities.length : 0);
            if (vulns30d) count30 = vulns30d.total || (vulns30d.vulnerabilities ? vulns30d.vulnerabilities.length : 0);
            DetectionCounters.update(count7, count30);

            // Recent Tests
            var engList = [];
            if (engagements) {
                engList = engagements.engagements || engagements;
                if (!Array.isArray(engList)) engList = [];
            }
            RecentTestsWidget.render(engList);

            // CVE Feed
            var cveList = cves ? (cves.cves || []) : [];
            CVEFeedWidget.render(cveList);

            // Heatmap: bucket vulns by created_at date
            var dateCounts = {};
            var vulnList = [];
            if (allVulns) {
                vulnList = allVulns.vulnerabilities || allVulns;
                if (!Array.isArray(vulnList)) vulnList = [];
            }
            // also count engagements by date
            for (var vi = 0; vi < vulnList.length; vi++) {
                var v = vulnList[vi];
                if (v.created_at) {
                    try {
                        var vd = new Date(v.created_at);
                        var vk = _dateKey(vd);
                        dateCounts[vk] = (dateCounts[vk] || 0) + 1;
                    } catch (e) {}
                }
            }
            for (var ei = 0; ei < engList.length; ei++) {
                var eng = engList[ei];
                if (eng.created_at) {
                    try {
                        var ed = new Date(eng.created_at);
                        var ek = _dateKey(ed);
                        dateCounts[ek] = (dateCounts[ek] || 0) + 2; // engagements weigh more
                    } catch (e) {}
                }
            }
            HeatmapWidget.update(dateCounts);

        } catch (e) {
            console.error('refreshDashboardWidgets:', e);
        }
    }

    // Export
    window.refreshDashboardWidgets = refreshDashboardWidgets;
    window.DashboardHeatmap = HeatmapWidget;
    window.DashboardDetectionCounters = DetectionCounters;
    window.DashboardRecentTests = RecentTestsWidget;
    window.DashboardCVEFeed = CVEFeedWidget;
})();
