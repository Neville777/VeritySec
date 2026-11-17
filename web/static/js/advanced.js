// Advanced testing features JS — MITRE, OWASP, CVE, PoC, Knowledge Graph, Scope Gates, CI/CD, Auto-Fix, Goals

// ============ MITRE ATT&CK ============

async function loadMitreTechniques() {
    var filter = document.getElementById('mitre-tactic-filter');
    var tactic = filter ? filter.value : '';
    var url = '/api/mitre/techniques';
    if (tactic) url += '?tactic=' + encodeURIComponent(tactic);
    try {
        var resp = await apiFetch(url);
        var data = await resp.json();
        var list = document.getElementById('mitre-techniques-list');
        if (!list) return;
        var items = data.techniques || [];
        if (items.length === 0) {
            list.innerHTML = '<p style="color:var(--text-muted);">No techniques found.</p>';
            return;
        }
        list.innerHTML = items.map(function(t) {
            return '<div style="padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);">'
                + '<div style="font-weight:600;font-size:14px;">' + escapeHtml(t.id) + ' — ' + escapeHtml(t.name) + '</div>'
                + '<div style="color:var(--text-muted);font-size:12px;margin-top:4px;">' + escapeHtml(t.tactic) + '</div>'
                + (t.description ? '<div style="font-size:13px;margin-top:6px;">' + escapeHtml(t.description) + '</div>' : '')
                + '</div>';
        }).join('');
    } catch (e) {
        console.error('loadMitreTechniques:', e);
    }
}
window.loadMitreTechniques = loadMitreTechniques;

// ============ OWASP TEST CASES ============

async function loadOwaspTestCases() {
    var filter = document.getElementById('owasp-category-filter');
    var category = filter ? filter.value : '';
    var url = '/api/owasp/test-cases';
    if (category) url += '?category=' + encodeURIComponent(category);
    try {
        var resp = await apiFetch(url);
        var data = await resp.json();
        var list = document.getElementById('owasp-test-list');
        if (!list) return;
        var items = data.test_cases || [];
        if (items.length === 0) {
            list.innerHTML = '<p style="color:var(--text-muted);">No test cases found.</p>';
            return;
        }
        // populate category filter if empty
        if (filter && filter.options.length <= 1) {
            var cats = {};
            items.forEach(function(tc) { cats[tc.category] = true; });
            Object.keys(cats).sort().forEach(function(c) {
                var opt = document.createElement('option');
                opt.value = c;
                opt.textContent = c;
                filter.appendChild(opt);
            });
        }
        list.innerHTML = items.map(function(tc) {
            return '<div style="padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);display:flex;justify-content:space-between;align-items:center;">'
                + '<div>'
                + '<span style="font-weight:600;font-size:13px;color:var(--accent);">' + escapeHtml(tc.test_id) + '</span> '
                + '<span style="font-size:13px;">' + escapeHtml(tc.title) + '</span>'
                + '<div style="color:var(--text-muted);font-size:12px;">' + escapeHtml(tc.category) + '</div>'
                + '</div>'
                + '<span style="font-size:12px;padding:2px 8px;border-radius:4px;background:var(--bg);color:var(--text-muted);">' + escapeHtml(tc.severity_default) + '</span>'
                + '</div>';
        }).join('');
    } catch (e) {
        console.error('loadOwaspTestCases:', e);
    }
}
window.loadOwaspTestCases = loadOwaspTestCases;

// ============ CVE FEED ============

async function searchCVEs() {
    var input = document.getElementById('cve-search-input');
    var q = input ? input.value : '';
    var url = '/api/cves?limit=50';
    if (q) url += '&q=' + encodeURIComponent(q);
    try {
        var resp = await apiFetch(url);
        var data = await resp.json();
        var list = document.getElementById('cve-results-list');
        if (!list) return;
        var items = data.cves || [];
        if (items.length === 0) {
            list.innerHTML = '<p style="color:var(--text-muted);">No CVEs found. Try a different search term.</p>';
            return;
        }
        list.innerHTML = items.map(function(cve) {
            var cvss = cve.cvss_score ? parseFloat(cve.cvss_score).toFixed(1) : 'N/A';
            var epss = cve.epss_score ? (parseFloat(cve.epss_score) * 100).toFixed(1) + '%' : 'N/A';
            var kev = cve.kev_known_exploited ? '<span style="color:#ef4444;font-weight:600;font-size:11px;padding:2px 6px;background:rgba(239,68,68,0.15);border-radius:4px;">KEV</span>' : '';
            var sevColor = cvss === 'N/A' ? 'var(--text-muted)' : parseFloat(cvss) >= 9 ? '#ef4444' : parseFloat(cvss) >= 7 ? '#f97316' : parseFloat(cvss) >= 4 ? '#eab308' : '#22c55e';
            return '<div style="padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);">'
                + '<div style="display:flex;justify-content:space-between;align-items:center;">'
                + '<span style="font-weight:600;font-size:14px;">' + escapeHtml(cve.cve_id) + '</span>'
                + '<div style="display:flex;gap:8px;align-items:center;">'
                + kev
                + '<span style="font-weight:600;color:' + sevColor + ';">CVSS ' + cvss + '</span>'
                + '<span style="font-size:12px;color:var(--text-muted);">EPSS ' + epss + '</span>'
                + '</div></div>'
                + '<div style="font-size:13px;margin-top:6px;color:var(--text-secondary);max-height:60px;overflow:hidden;">' + escapeHtml(cve.description || '') + '</div>'
                + '</div>';
        }).join('');
    } catch (e) {
        console.error('searchCVEs:', e);
    }
}
window.searchCVEs = searchCVEs;

// ============ SCOPE GATES ============

async function loadScopeGates() {
    var sel = document.getElementById('scope-engagement-select');
    var engID = sel ? sel.value : '';
    var rulesDiv = document.getElementById('scope-rules-list');
    var noisePanel = document.getElementById('noise-config-panel');
    if (!engID) {
        if (rulesDiv) rulesDiv.innerHTML = '';
        if (noisePanel) noisePanel.style.display = 'none';
        return;
    }
    try {
        var resp = await apiFetch('/api/engagements/' + engID + '/scope-rules');
        var data = await resp.json();
        var rules = data.rules || [];
        if (rulesDiv) {
            if (rules.length === 0) {
                rulesDiv.innerHTML = '<p style="color:var(--text-muted);">No scope rules defined.</p>';
            } else {
                rulesDiv.innerHTML = rules.map(function(r) {
                    var color = r.rule_type === 'allow' ? '#22c55e' : '#ef4444';
                    return '<div style="padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);display:flex;justify-content:space-between;align-items:center;">'
                        + '<div><span style="color:' + color + ';font-weight:600;text-transform:uppercase;font-size:11px;">' + r.rule_type + '</span> '
                        + '<span style="font-size:13px;">' + escapeHtml(r.target_type) + ': ' + escapeHtml(r.target_value) + '</span></div>'
                        + '<button class="btn-small" onclick="deleteScopeRule(\'' + engID + '\',\'' + r.id + '\')" style="font-size:12px;color:var(--text-muted);">Remove</button>'
                        + '</div>';
                }).join('');
            }
        }
        // load noise config
        var ncResp = await apiFetch('/api/engagements/' + engID + '/noise-config');
        var ncData = await ncResp.json();
        var cfg = ncData.config || {};
        if (noisePanel) {
            noisePanel.style.display = '';
            document.getElementById('noise-rpm').value = cfg.max_requests_per_minute || 60;
            document.getElementById('noise-concurrent').value = cfg.max_concurrent_tools || 3;
            document.getElementById('noise-turns').value = cfg.max_agent_turns || 500;
            document.getElementById('noise-tokens').value = cfg.max_tokens_budget || 1000000;
        }
    } catch (e) {
        console.error('loadScopeGates:', e);
    }
}
window.loadScopeGates = loadScopeGates;

async function deleteScopeRule(engID, ruleID) {
    try {
        await apiFetch('/api/engagements/' + engID + '/scope-rules/' + ruleID, { method: 'DELETE' });
        loadScopeGates();
    } catch (e) {
        console.error('deleteScopeRule:', e);
    }
}
window.deleteScopeRule = deleteScopeRule;

async function saveNoiseConfig() {
    var sel = document.getElementById('scope-engagement-select');
    var engID = sel ? sel.value : '';
    if (!engID) return;
    try {
        await apiFetch('/api/engagements/' + engID + '/noise-config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                max_requests_per_minute: parseInt(document.getElementById('noise-rpm').value) || 60,
                max_concurrent_tools: parseInt(document.getElementById('noise-concurrent').value) || 3,
                max_agent_turns: parseInt(document.getElementById('noise-turns').value) || 500,
                max_tokens_budget: parseInt(document.getElementById('noise-tokens').value) || 1000000,
            })
        });
        showNotification('Noise config saved', 'success');
    } catch (e) {
        console.error('saveNoiseConfig:', e);
    }
}
window.saveNoiseConfig = saveNoiseConfig;

// ============ CI/CD ============

async function loadCICDPage() {
    try {
        var tokResp = await apiFetch('/api/cicd/tokens');
        var tokData = await tokResp.json();
        var tokens = tokData.tokens || [];
        var tokList = document.getElementById('cicd-tokens-list');
        if (tokList) {
            if (tokens.length === 0) {
                tokList.innerHTML = '<p style="color:var(--text-muted);">No CI/CD tokens. Create one to integrate with your pipeline.</p>';
            } else {
                tokList.innerHTML = tokens.map(function(t) {
                    return '<div style="padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);display:flex;justify-content:space-between;align-items:center;">'
                        + '<div><span style="font-weight:600;font-size:13px;">' + escapeHtml(t.name) + '</span>'
                        + '<div style="color:var(--text-muted);font-size:12px;">Created: ' + escapeHtml(t.created_at || '') + '</div></div>'
                        + '<button class="btn-small" onclick="deleteCICDToken(\'' + t.id + '\')" style="font-size:12px;color:#ef4444;">Delete</button>'
                        + '</div>';
                }).join('');
            }
        }
        var runResp = await apiFetch('/api/cicd/runs');
        var runData = await runResp.json();
        var runs = runData.runs || [];
        var runList = document.getElementById('cicd-runs-list');
        if (runList) {
            if (runs.length === 0) {
                runList.innerHTML = '<p style="color:var(--text-muted);">No runs yet.</p>';
            } else {
                runList.innerHTML = runs.map(function(r) {
                    var statusColor = r.status === 'completed' ? '#22c55e' : r.status === 'failed' ? '#ef4444' : r.status === 'running' ? '#3b82f6' : 'var(--text-muted)';
                    return '<div style="padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);display:flex;justify-content:space-between;align-items:center;">'
                        + '<div>'
                        + '<span style="font-size:13px;">' + escapeHtml(r.repo_url || 'Manual trigger') + '</span>'
                        + (r.branch ? '<span style="color:var(--text-muted);font-size:12px;margin-left:8px;">' + escapeHtml(r.branch) + '</span>' : '')
                        + '</div>'
                        + '<div style="display:flex;gap:12px;align-items:center;">'
                        + '<span style="font-size:12px;color:var(--text-muted);">Findings: ' + (r.findings_count || 0) + '</span>'
                        + '<span style="font-size:12px;font-weight:600;color:' + statusColor + ';">' + escapeHtml(r.status) + '</span>'
                        + '</div></div>';
                }).join('');
            }
        }
    } catch (e) {
        console.error('loadCICDPage:', e);
    }
}
window.loadCICDPage = loadCICDPage;

async function deleteCICDToken(tokenID) {
    try {
        await apiFetch('/api/cicd/tokens/' + tokenID, { method: 'DELETE' });
        loadCICDPage();
    } catch (e) {
        console.error('deleteCICDToken:', e);
    }
}
window.deleteCICDToken = deleteCICDToken;

function showCreateCICDTokenModal() {
    var name = prompt('Token name:');
    if (!name) return;
    apiFetch('/api/cicd/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name })
    }).then(function(resp) { return resp.json(); })
      .then(function(data) {
          if (data.token) {
              alert('Token created! Copy it now — it will not be shown again:\n\n' + data.token);
          }
          loadCICDPage();
      })
      .catch(function(e) { console.error('createCICDToken:', e); });
}
window.showCreateCICDTokenModal = showCreateCICDTokenModal;

// ============ KNOWLEDGE GRAPH ============

async function loadKnowledgeGraph() {
    var sel = document.getElementById('kg-engagement-select');
    var engID = sel ? sel.value : '';
    var statsDiv = document.getElementById('kg-stats');
    var nodeList = document.getElementById('kg-node-list');
    if (!engID) {
        if (statsDiv) statsDiv.innerHTML = '';
        if (nodeList) nodeList.innerHTML = '';
        return;
    }
    try {
        var resp = await apiFetch('/api/engagements/' + engID + '/knowledge/graph');
        var data = await resp.json();
        var nodes = data.nodes || [];
        var edges = data.edges || [];
        if (statsDiv) {
            statsDiv.innerHTML =
                '<div style="padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);text-align:center;">'
                + '<div style="font-size:24px;font-weight:700;">' + nodes.length + '</div><div style="font-size:12px;color:var(--text-muted);">Nodes</div></div>'
                + '<div style="padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);text-align:center;">'
                + '<div style="font-size:24px;font-weight:700;">' + edges.length + '</div><div style="font-size:12px;color:var(--text-muted);">Edges</div></div>'
                + '<div style="padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);text-align:center;">'
                + '<div style="font-size:24px;font-weight:700;">' + new Set(nodes.map(function(n) { return n.type; })).size + '</div><div style="font-size:12px;color:var(--text-muted);">Node Types</div></div>';
        }
        if (nodeList) {
            if (nodes.length === 0) {
                nodeList.innerHTML = '<p style="color:var(--text-muted);">No knowledge nodes yet. Nodes are created as agents discover targets and findings.</p>';
            } else {
                nodeList.innerHTML = nodes.map(function(n) {
                    return '<div style="padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);display:flex;justify-content:space-between;align-items:center;">'
                        + '<div><span style="font-weight:600;font-size:13px;">' + escapeHtml(n.label) + '</span>'
                        + '<span style="color:var(--text-muted);font-size:12px;margin-left:8px;">' + escapeHtml(n.type) + '</span></div>'
                        + '</div>';
                }).join('');
            }
        }
    } catch (e) {
        console.error('loadKnowledgeGraph:', e);
    }
}
window.loadKnowledgeGraph = loadKnowledgeGraph;

// ============ AUTONOMOUS GOALS ============

async function loadAutonomousGoals() {
    var sel = document.getElementById('goals-engagement-select');
    var engID = sel ? sel.value : '';
    var list = document.getElementById('goals-tree-list');
    if (!engID || !list) {
        if (list) list.innerHTML = '';
        return;
    }
    try {
        var resp = await apiFetch('/api/engagements/' + engID + '/goal-tree');
        var data = await resp.json();
        var goals = data.goals || [];
        if (goals.length === 0) {
            list.innerHTML = '<p style="color:var(--text-muted);">No goals set. Create a high-level assessment goal to get started.</p>';
            return;
        }
        list.innerHTML = goals.map(function(g) {
            var statusColor = g.status === 'completed' ? '#22c55e' : g.status === 'active' ? '#3b82f6' : g.status === 'failed' ? '#ef4444' : 'var(--text-muted)';
            var indent = g.parent_goal_id ? 'margin-left:24px;' : '';
            return '<div style="padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);' + indent + '">'
                + '<div style="display:flex;justify-content:space-between;align-items:center;">'
                + '<span style="font-size:13px;">' + escapeHtml(g.goal_text) + '</span>'
                + '<div style="display:flex;gap:8px;align-items:center;">'
                + '<span style="font-size:11px;color:var(--text-muted);">' + escapeHtml(g.goal_type) + '</span>'
                + '<span style="font-size:12px;font-weight:600;color:' + statusColor + ';">' + escapeHtml(g.status) + '</span>'
                + '</div></div></div>';
        }).join('');
    } catch (e) {
        console.error('loadAutonomousGoals:', e);
    }
}
window.loadAutonomousGoals = loadAutonomousGoals;

// ============ POC VALIDATION OVERVIEW ============

async function loadPocOverview() {
    var list = document.getElementById('poc-overview-list');
    if (!list) return;
    try {
        var resp = await apiFetch('/api/vulnerabilities?limit=100');
        var data = await resp.json();
        var vulns = (data.vulnerabilities || []).filter(function(v) { return v.poc_count > 0 || v.severity === 'critical' || v.severity === 'high'; });
        if (vulns.length === 0) {
            list.innerHTML = '<p style="color:var(--text-muted);">No vulnerabilities with PoC validations yet. Create findings from an engagement first.</p>';
            return;
        }
        list.innerHTML = vulns.map(function(v) {
            var sevColor = v.severity === 'critical' ? '#ef4444' : v.severity === 'high' ? '#f97316' : v.severity === 'medium' ? '#eab308' : '#22c55e';
            return '<div style="padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="switchPage(\'vulnerabilities\')">'
                + '<div><span style="font-weight:600;font-size:13px;">' + escapeHtml(v.title || v.name || v.id) + '</span>'
                + '<div style="color:var(--text-muted);font-size:12px;margin-top:2px;">' + (v.poc_count || 0) + ' PoC validation(s)</div></div>'
                + '<span style="font-size:11px;font-weight:600;color:' + sevColor + ';text-transform:uppercase;">' + escapeHtml(v.severity || '') + '</span>'
                + '</div>';
        }).join('');
    } catch (e) {
        console.error('loadPocOverview:', e);
        if (list) list.innerHTML = '<p style="color:var(--text-muted);">No vulnerabilities found. Run a security scan or create findings first.</p>';
    }
}
window.loadPocOverview = loadPocOverview;

// ============ AUTOFIX OVERVIEW ============

async function loadAutofixOverview() {
    var list = document.getElementById('autofix-overview-list');
    if (!list) return;
    try {
        var resp = await apiFetch('/api/vulnerabilities?limit=100');
        var data = await resp.json();
        var vulns = data.vulnerabilities || [];
        if (vulns.length === 0) {
            list.innerHTML = '<p style="color:var(--text-muted);">No vulnerabilities found. Auto-fix suggestions are generated per vulnerability after scanning.</p>';
            return;
        }
        list.innerHTML = vulns.map(function(v) {
            var sevColor = v.severity === 'critical' ? '#ef4444' : v.severity === 'high' ? '#f97316' : v.severity === 'medium' ? '#eab308' : '#22c55e';
            return '<div style="padding:12px;border:1px solid var(--border);border-radius:8px;background:var(--bg-secondary);display:flex;justify-content:space-between;align-items:center;cursor:pointer;" onclick="switchPage(\'vulnerabilities\')">'
                + '<div><span style="font-weight:600;font-size:13px;">' + escapeHtml(v.title || v.name || v.id) + '</span>'
                + '<div style="color:var(--text-muted);font-size:12px;margin-top:2px;">' + escapeHtml(v.fix_status || 'pending') + '</div></div>'
                + '<span style="font-size:11px;font-weight:600;color:' + sevColor + ';text-transform:uppercase;">' + escapeHtml(v.severity || '') + '</span>'
                + '</div>';
        }).join('');
    } catch (e) {
        console.error('loadAutofixOverview:', e);
        if (list) list.innerHTML = '<p style="color:var(--text-muted);">No vulnerabilities found. Run a security scan first.</p>';
    }
}
window.loadAutofixOverview = loadAutofixOverview;

// ============ HELPERS ============

async function populateEngagementSelectors() {
    try {
        var resp = await apiFetch('/api/engagements');
        var data = await resp.json();
        var engs = data.engagements || data || [];
        ['kg-engagement-select', 'scope-engagement-select', 'goals-engagement-select'].forEach(function(id) {
            var sel = document.getElementById(id);
            if (!sel) return;
            while (sel.options.length > 1) sel.remove(1);
            engs.forEach(function(e) {
                var opt = document.createElement('option');
                opt.value = e.id;
                opt.textContent = e.name || e.id;
                sel.appendChild(opt);
            });
        });
    } catch (e) {
        console.error('populateEngagementSelectors:', e);
    }
}
window.populateEngagementSelectors = populateEngagementSelectors;

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
