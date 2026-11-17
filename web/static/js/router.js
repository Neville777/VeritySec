// Page routing management — history-based (no # in URLs)
let currentPage = null;

const APP_BASE = '/app';

/** Read the current route path (e.g. "chat?conversation=abc") */
function getRoutePath() {
    const pathname = window.location.pathname;
    const prefix = APP_BASE + '/';
    let path = '';
    if (pathname === APP_BASE || pathname === APP_BASE + '/') {
        path = '';
    } else if (pathname.startsWith(prefix)) {
        path = pathname.slice(prefix.length);
    }
    const search = window.location.search;
    if (search) {
        path += search;
    }
    return path;
}
window.getRoutePath = getRoutePath;

/** Set the route path via pushState (e.g. "dashboard", "chat?conversation=abc") */
function setRoutePath(path, replace) {
    const clean = (path || '').replace(/^[#/]+/, '');
    const parts = clean.split('?');
    const pagePart = parts[0] || '';
    const queryPart = parts.length > 1 ? '?' + parts.slice(1).join('?') : '';
    const url = APP_BASE + (pagePart ? '/' + pagePart : '') + queryPart;
    if (replace) {
        history.replaceState(null, '', url);
    } else {
        history.pushState(null, '', url);
    }
}
window.setRoutePath = setRoutePath;

/** Preserve the query string (session ID or settings section) when switching between chat, vulnerability management and settings pages. */
function buildHashForPage(pageId) {
    if (pageId !== 'chat' && pageId !== 'vulnerabilities' && pageId !== 'settings') {
        return pageId;
    }
    const full = getRoutePath();
    const parts = full.split('?');
    const curPage = parts[0];
    const q = parts.length > 1 ? parts.slice(1).join('?') : '';
    if (curPage === pageId && q) {
        return pageId + '?' + q;
    }
    return pageId;
}

let chatConversationFromHashSeq = 0;

function cancelScheduledChatConversationFromHash() {
    chatConversationFromHashSeq++;
    setChatConversationRestorePending('', false);
}
window.cancelScheduledChatConversationFromHash = cancelScheduledChatConversationFromHash;

function setChatConversationRestorePending(conversationId, pending) {
    const container = document.querySelector('.chat-container');
    if (!container) return;
    const id = String(conversationId || '').trim();
    if (pending && id) {
        container.classList.add('is-conversation-restoring');
        container.dataset.restoringConversationId = id;
        container.setAttribute('aria-busy', 'true');
        return;
    }
    container.classList.remove('is-conversation-restoring');
    delete container.dataset.restoringConversationId;
    container.removeAttribute('aria-busy');
}

function finishChatConversationRestore(conversationId) {
    setChatConversationRestorePending(conversationId, false);
}
window.finishChatConversationRestore = finishChatConversationRestore;

function scheduleChatConversationFromHash(delayMs) {
    const full = getRoutePath();
    const hashParts = full.split('?');
    if (hashParts[0] !== 'chat' || hashParts.length < 2) {
        return;
    }
    const params = new URLSearchParams(hashParts.slice(1).join('?'));
    const conversationId = params.get('conversation');
    const projectId = params.get('project');
    if (projectId && typeof setActiveProjectId === 'function') {
        setActiveProjectId(projectId);
        if (typeof refreshChatProjectSelector === 'function') {
            refreshChatProjectSelector();
        }
    }
    if (!conversationId) {
        return;
    }
    setChatConversationRestorePending(conversationId, true);
    const token = ++chatConversationFromHashSeq;
    setTimeout(() => {
        if (token !== chatConversationFromHashSeq) {
            return;
        }
        if (typeof loadConversation === 'function') {
            loadConversation(conversationId);
        } else if (typeof window.loadConversation === 'function') {
            window.loadConversation(conversationId);
        } else {
            console.warn('loadConversation function not found');
        }
    }, delayMs);
}

/** Jump to a specific conversation: a single page switch + a single load, to avoid duplicate triggers between popstate and manual load causing flicker */
function navigateToConversation(conversationId) {
    const cid = String(conversationId || '').trim();
    if (!cid) return;
    const targetPath = 'chat?conversation=' + encodeURIComponent(cid);
    const alreadyOnChat = currentPage === 'chat';

    if (getRoutePath() !== targetPath) {
        setRoutePath(targetPath, true);
    }

    if (!alreadyOnChat) {
        switchPage('chat');
    }

    if (typeof loadConversation === 'function') {
        return loadConversation(cid);
    } else if (typeof window.loadConversation === 'function') {
        return window.loadConversation(cid);
    }
}
window.navigateToConversation = navigateToConversation;

// Initialize routing
function initRouter() {
    const full = getRoutePath();
    if (full) {
        const hashParts = full.split('?');
        let pageId = hashParts[0].replace(/^[#/]+/, '');
        if (pageId === 'c2') pageId = 'c2-listeners';
        const settingsSection = pageId === 'system-update' ? 'update' : pageId === 'settings' && new URLSearchParams(hashParts.slice(1).join('?')).get('section') === 'token-usage' ? 'token-usage' : '';
        if (settingsSection) pageId = 'settings';
        if (pageId && document.getElementById(`page-${pageId}`)) {
            switchPage(pageId);
            if (settingsSection && typeof switchSettingsSection === 'function') {
                switchSettingsSection(settingsSection);
            }
            if (pageId === 'chat') {
                scheduleChatConversationFromHash(0);
            }
            return;
        }
    }

    // Show the dashboard by default
    switchPage('dashboard');
}

// Switch page
function switchPage(pageId) {
    const targetPage = document.getElementById(`page-${pageId}`);
    if (!targetPage) return;
    if (pageId !== 'chat') {
        setChatConversationRestorePending('', false);
        if (currentPage === 'chat' && typeof window.abandonChatConversationForPageNavigation === 'function') {
            window.abandonChatConversationForPageNavigation();
        }
    }

    if (currentPage === pageId && targetPage.classList.contains('active')) {
        const currentHash = buildHashForPage(pageId);
        if (getRoutePath() !== currentHash) {
            setRoutePath(currentHash);
        }
        initPage(pageId);
        return;
    }

    if (typeof window.syncC2NavOnceFromServer === 'function') {
        void window.syncC2NavOnceFromServer();
    }
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });

    // Show the target page
    targetPage.classList.add('active');
    currentPage = pageId;

    const newHash = buildHashForPage(pageId);
    if (getRoutePath() !== newHash) {
        setRoutePath(newHash);
    }

    // Update navigation state
    updateNavState(pageId);

    // Page-specific initialization
    initPage(pageId);

    if (typeof applyRBACToUI === 'function') {
        applyRBACToUI(targetPage);
    }
}
window.switchPage = switchPage;

 // Update navigation state
function updateNavState(pageId) {
    // Remove all active states
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        item.classList.remove('expanded');
    });

    document.querySelectorAll('.nav-submenu-item').forEach(item => {
        item.classList.remove('active');
    });

    // Set active state
    if (pageId === 'hitl' || pageId === 'tool-guard') {
        const securityItem = document.querySelector('.nav-item[data-page="security"]');
        if (securityItem) {
            securityItem.classList.add('active');
            securityItem.classList.add('expanded');
        }
        const submenuItem = document.querySelector(`.nav-submenu-item[data-page="${pageId}"]`);
        if (submenuItem) submenuItem.classList.add('active');
    } else if (pageId === 'asset-overview' || pageId === 'asset-library' || pageId === 'info-collect') {
        const assetItem = document.querySelector('.nav-item[data-page="assets"]');
        if (assetItem) {
            assetItem.classList.add('active');
            assetItem.classList.add('expanded');
        }
        const submenuItem = document.querySelector(`.nav-submenu-item[data-page="${pageId}"]`);
        if (submenuItem) submenuItem.classList.add('active');
    } else if (pageId === 'mcp-monitor' || pageId === 'mcp-management') {
        // MCP submenu item
        const mcpItem = document.querySelector('.nav-item[data-page="mcp"]');
        if (mcpItem) {
            mcpItem.classList.add('active');
            // Expand MCP submenu
            mcpItem.classList.add('expanded');
        }

        const submenuItem = document.querySelector(`.nav-submenu-item[data-page="${pageId}"]`);
        if (submenuItem) {
            submenuItem.classList.add('active');
        }
    } else if (pageId === 'knowledge-management' || pageId === 'knowledge-retrieval-logs') {
        // Knowledge submenu item
        const knowledgeItem = document.querySelector('.nav-item[data-page="knowledge"]');
        if (knowledgeItem) {
            knowledgeItem.classList.add('active');
            // Expand knowledge submenu
            knowledgeItem.classList.add('expanded');
        }

        const submenuItem = document.querySelector(`.nav-submenu-item[data-page="${pageId}"]`);
        if (submenuItem) {
            submenuItem.classList.add('active');
        }
    } else if (pageId === 'skills-monitor' || pageId === 'skills-management') {
        // Skills submenu item
        const skillsItem = document.querySelector('.nav-item[data-page="skills"]');
        if (skillsItem) {
            skillsItem.classList.add('active');
            // Expand Skills submenu
            skillsItem.classList.add('expanded');
        }

        const submenuItem = document.querySelector(`.nav-submenu-item[data-page="${pageId}"]`);
        if (submenuItem) {
            submenuItem.classList.add('active');
        }
    } else if (pageId === 'agents-management') {
        const agentsItem = document.querySelector('.nav-item[data-page="agents"]');
        if (agentsItem) {
            agentsItem.classList.add('active');
            agentsItem.classList.add('expanded');
        }
        const submenuItem = document.querySelector(`.nav-submenu-item[data-page="${pageId}"]`);
        if (submenuItem) {
            submenuItem.classList.add('active');
        }
    } else if (pageId.startsWith('c2') || pageId === 'c2-listeners' || pageId === 'c2-sessions' || pageId === 'c2-tasks' || pageId === 'c2-payloads' || pageId === 'c2-events' || pageId === 'c2-profiles') {
        // C2 submenu item
        const c2Item = document.querySelector('.nav-item[data-page="c2"]');
        if (c2Item) {
            c2Item.classList.add('active');
            c2Item.classList.add('expanded');
        }
        const submenuItem = document.querySelector(`.nav-submenu-item[data-page="${pageId}"]`);
        if (submenuItem) {
            submenuItem.classList.add('active');
        }
    } else if (pageId === 'roles-management') {
        // Role submenu item
        const rolesItem = document.querySelector('.nav-item[data-page="roles"]');
        if (rolesItem) {
            rolesItem.classList.add('active');
            // Expand role submenu
            rolesItem.classList.add('expanded');
        }

        const submenuItem = document.querySelector(`.nav-submenu-item[data-page="${pageId}"]`);
        if (submenuItem) {
            submenuItem.classList.add('active');
        }
    } else {
        // Main menu item
        const navItem = document.querySelector(`.nav-item[data-page="${pageId}"]`);
        if (navItem) {
            navItem.classList.add('active');
        }
    }
}

/** Read sidebar submenu items (only inside .nav-submenu, to avoid false matches) */
function getNavSubmenuItems(navItem) {
    if (!navItem) return [];
    const submenu = navItem.querySelector('.nav-submenu');
    if (!submenu) return [];
    return Array.from(submenu.querySelectorAll('.nav-submenu-item'));
}

// Toggle submenu
function toggleSubmenu(menuId) {
    const sidebar = document.getElementById('main-sidebar');
    const navItem = document.querySelector(`.nav-item[data-page="${menuId}"]`);

    if (!navItem) return;

    const collapsed = sidebar && sidebar.classList.contains('collapsed');

    // Check whether the sidebar is collapsed
    if (collapsed) {
        // When collapsed, show the popup menu
        showSubmenuPopup(navItem, menuId);
        return;
    }

    // When expanded, toggle the submenu and scroll it into view so the sub-items are visible
    const willExpand = !navItem.classList.contains('expanded');
    navItem.classList.toggle('expanded');
    if (willExpand) {
        requestAnimationFrame(() => {
            navItem.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            const items = getNavSubmenuItems(navItem);
            const last = items[items.length - 1];
            if (last) {
                last.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
            }
        });
    }
}
window.toggleSubmenu = toggleSubmenu;

// Show submenu popup
function showSubmenuPopup(navItem, menuId) {
    const existingPopup = document.querySelector('.submenu-popup');
    if (existingPopup) {
        const sameMenu = existingPopup.dataset.menuId === menuId;
        existingPopup.remove();
        if (sameMenu) {
            return;
        }
    }

    const navItemContent = navItem.querySelector('.nav-item-content');
    const submenu = navItem.querySelector('.nav-submenu');

    if (!submenu) return;

    const rect = navItemContent.getBoundingClientRect();

    const popup = document.createElement('div');
    popup.className = 'submenu-popup';
    popup.dataset.menuId = menuId;
    popup.style.position = 'fixed';
    popup.style.left = (rect.right + 8) + 'px';
    popup.style.top = rect.top + 'px';
    popup.style.zIndex = '1000';

    const submenuItems = submenu.querySelectorAll('.nav-submenu-item');
    submenuItems.forEach(item => {
        if (item.hidden || (typeof permissionAllowedForElement === 'function' && !permissionAllowedForElement(item))) return;
        const popupItem = document.createElement('div');
        popupItem.className = 'submenu-popup-item';
        popupItem.textContent = item.textContent.trim();

        const pageId = item.getAttribute('data-page');
        if (pageId && document.querySelector(`.nav-submenu-item[data-page="${pageId}"].active`)) {
            popupItem.classList.add('active');
        }

        popupItem.onclick = function(e) {
            e.stopPropagation();
            e.preventDefault();

            const pageId = item.getAttribute('data-page');
            if (pageId) {
                switchPage(pageId);
            }

            popup.remove();
            document.removeEventListener('click', closePopup);
        };
        popup.appendChild(popupItem);
    });

    document.body.appendChild(popup);

    const closePopup = function(e) {
        if (!popup.contains(e.target) && !navItem.contains(e.target)) {
            popup.remove();
            document.removeEventListener('click', closePopup);
        }
    };

    setTimeout(() => {
        document.addEventListener('click', closePopup);
    }, 0);
}

// Initialize page
async function initPage(pageId) {
    if (window.i18nReady) await window.i18nReady;
    if (typeof stopExternalMcpPoll === 'function') {
        stopExternalMcpPoll();
    }
    switch(pageId) {
        case 'dashboard':
            if (typeof refreshDashboard === 'function') {
                refreshDashboard();
            }
            break;
        case 'chat':
            initConversationSidebarState();
            if (typeof prefetchProjectsForChat === 'function') {
                prefetchProjectsForChat();
            }
            if (typeof refreshChatProjectSelector === 'function') {
                refreshChatProjectSelector();
            }
            break;
        case 'tool-guard':
            if (typeof loadToolGuardConfig === 'function') loadToolGuardConfig();
            break;
        case 'hitl':
            if (typeof refreshHitlActivePanel === 'function') {
                refreshHitlActivePanel();
            } else if (typeof refreshHitlPending === 'function') {
                refreshHitlPending();
            }
            break;
        case 'info-collect':
            if (typeof initInfoCollectPage === 'function') {
                initInfoCollectPage();
            }
            break;
        case 'asset-overview':
            if (typeof loadAssetOverview === 'function') loadAssetOverview();
            break;
        case 'asset-library':
            if (typeof loadAssets === 'function') loadAssets();
            break;
        case 'tasks':
            if (typeof initTasksPage === 'function') {
                initTasksPage();
            }
            break;
        case 'mcp-monitor':
            if (typeof refreshMonitorPanel === 'function') {
                refreshMonitorPanel();
            }
            if (typeof startMonitorPoll === 'function') {
                startMonitorPoll();
            }
            break;
        case 'mcp-management':
            const startLoadMcpTools = () => {
                if (typeof loadToolsList === 'function') {
                    if (typeof getToolsPageSize === 'function' && typeof toolsPagination !== 'undefined') {
                        toolsPagination.pageSize = getToolsPageSize();
                    }
                    setTimeout(() => {
                        loadToolsList(1, '').catch(err => {
                            console.error('Failed to load tool list:', err);
                        });
                    }, 100);
                    setTimeout(() => {
                        if (typeof loadToolInstalls === 'function') loadToolInstalls();
                    }, 150);
                }
            };
            const afterMcpConfigReady = () => {
                startLoadMcpTools();
                if (typeof loadExternalMCPs === 'function') {
                    loadExternalMCPs().catch(err => {
                        console.warn('Failed to load external MCP list:', err);
                    });
                }
                if (typeof startExternalMcpPoll === 'function') {
                    startExternalMcpPoll();
                }
            };
            const canLoadFullConfig = typeof hasPermission !== 'function' || hasPermission('config:read');
            if (typeof loadConfig === 'function' && canLoadFullConfig) {
                loadConfig(false, { silent: true })
                    .catch(err => {
                        console.warn('Failed to load config (continuing to load MCP list):', err);
                    })
                    .finally(afterMcpConfigReady);
            } else {
                afterMcpConfigReady();
            }
            break;
        case 'engagements':
            if (typeof initEngagementsPage === 'function') initEngagementsPage();
            break;
        case 'projects':
            if (typeof initProjectsPage === 'function') {
                initProjectsPage();
            }
            break;
        case 'vulnerabilities':
            if (typeof initVulnerabilityPage === 'function') {
                initVulnerabilityPage();
            }
            break;
        case 'webshell':
            if (typeof initWebshellPage === 'function') {
                initWebshellPage();
            }
            break;
        case 'chat-files':
            if (typeof initChatFilesPage === 'function') {
                initChatFilesPage();
            }
            break;
        case 'settings':
            if (typeof loadConfig === 'function') {
                loadConfig(false);
            }
            const updateSection = document.getElementById('settings-section-update');
            if (updateSection && updateSection.classList.contains('active') && typeof loadUpdateConsole === 'function') {
                loadUpdateConsole();
            }
            const tokenSection = document.getElementById('settings-section-token-usage');
            if (tokenSection && tokenSection.classList.contains('active') && getRoutePath() !== 'settings?section=token-usage' && typeof refreshTokenUsage === 'function') {
                refreshTokenUsage();
            }
            break;
        case 'roles-management':
            const rolesSearchInput = document.getElementById('roles-search');
            if (rolesSearchInput) {
                rolesSearchInput.value = '';
            }
            const rolesSearchClear = document.getElementById('roles-search-clear');
            if (rolesSearchClear) {
                rolesSearchClear.style.display = 'none';
            }
            if (typeof loadRoles === 'function') {
                loadRoles().then(() => {
                    if (typeof renderRolesList === 'function') {
                        renderRolesList();
                    }
                });
            }
            break;
        case 'api-keys':
            if (typeof loadBYOKKeysPage === 'function') {
                loadBYOKKeysPage();
            }
            break;
        case 'mitre-attack':
            if (typeof loadMitreTechniques === 'function') loadMitreTechniques();
            break;
        case 'owasp-tests':
            if (typeof loadOwaspTestCases === 'function') loadOwaspTestCases();
            break;
        case 'cve-feed':
            if (typeof loadCVEFeedPage === 'function') loadCVEFeedPage();
            break;
        case 'cve-detail':
            break;
        case 'poc-validation':
            if (typeof loadPocOverview === 'function') loadPocOverview();
            break;
        case 'knowledge-graph':
            if (typeof populateEngagementSelectors === 'function') populateEngagementSelectors();
            break;
        case 'scope-gates':
            if (typeof populateEngagementSelectors === 'function') populateEngagementSelectors();
            break;
        case 'cicd-integration':
            if (typeof loadCICDPage === 'function') loadCICDPage();
            break;
        case 'autofix':
            if (typeof loadAutofixOverview === 'function') loadAutofixOverview();
            break;
        case 'autonomous-goals':
            if (typeof populateEngagementSelectors === 'function') populateEngagementSelectors();
            break;
        case 'platform-rbac':
            if (typeof initPlatformRbacPage === 'function') {
                initPlatformRbacPage();
            }
            break;
        case 'workflows':
            if (typeof refreshWorkflows === 'function') {
                refreshWorkflows();
            }
            break;
        case 'skills-monitor':
            if (typeof loadSkillsMonitor === 'function') {
                loadSkillsMonitor();
            }
            break;
        case 'skills-management':
            const skillsSearchInput = document.getElementById('skills-search');
            if (skillsSearchInput) {
                skillsSearchInput.value = '';
            }
            const skillsSearchClear = document.getElementById('skills-search-clear');
            if (skillsSearchClear) {
                skillsSearchClear.style.display = 'none';
            }
            if (typeof initSkillsPagination === 'function') {
                initSkillsPagination();
            }
            if (typeof loadSkills === 'function') {
                loadSkills();
            }
            break;
        case 'agents-management':
            if (typeof loadMarkdownAgents === 'function') {
                loadMarkdownAgents();
            }
            break;
        case 'c2-listeners':
        case 'c2-sessions':
        case 'c2-tasks':
        case 'c2-payloads':
        case 'c2-events':
        case 'c2-profiles':
            window.currentPageId = pageId;
            if (window.C2 && typeof window.C2.init === 'function') {
                window.C2.init();
            }
            break;
    }

    if (pageId !== 'tasks' && typeof cleanupTasksPage === 'function') {
        cleanupTasksPage();
    }
    if (pageId !== 'settings' && typeof stopUpdatePolling === 'function') {
        stopUpdatePolling();
    }
    if (pageId !== 'settings' && typeof stopTokenUsageRequests === 'function') {
        stopTokenUsageRequests();
    }
}

// Initialize routing after the page has loaded
document.addEventListener('DOMContentLoaded', function() {
    // Migrate old hash URLs to history URLs
    if (window.location.hash && window.location.hash.length > 1) {
        const hashPath = window.location.hash.slice(1).replace(/^[#/]+/, '');
        setRoutePath(hashPath, true);
    }

    initRouter();
    document.documentElement.classList.remove('initial-route-pending');
    initSidebarState();

    // Listen for browser back/forward
    window.addEventListener('popstate', function() {
        const full = getRoutePath();
        const hashParts = full.split('?');
        let pageId = hashParts[0].replace(/^[#/]+/, '');

        if (pageId === 'c2') pageId = 'c2-listeners';
        const settingsSection = pageId === 'system-update' ? 'update' : pageId === 'settings' && new URLSearchParams(hashParts.slice(1).join('?')).get('section') === 'token-usage' ? 'token-usage' : '';
        if (settingsSection) pageId = 'settings';
        if (pageId && document.getElementById(`page-${pageId}`)) {
            switchPage(pageId);
            if (settingsSection && typeof switchSettingsSection === 'function') {
                switchSettingsSection(settingsSection);
            }
            if (pageId === 'chat') {
                scheduleChatConversationFromHash(0);
            }
        }
    });
});

// Toggle sidebar collapse/expand
function toggleSidebar() {
    const sidebar = document.getElementById('main-sidebar');
    if (sidebar) {
        sidebar.classList.toggle('collapsed');
        const isCollapsed = sidebar.classList.contains('collapsed');
        localStorage.setItem('sidebarCollapsed', isCollapsed ? 'true' : 'false');
    }
}
window.toggleSidebar = toggleSidebar;

// Initialize sidebar state
function initSidebarState() {
    const sidebar = document.getElementById('main-sidebar');
    if (sidebar) {
        const savedState = localStorage.getItem('sidebarCollapsed');
        if (savedState === 'true') {
            sidebar.classList.add('collapsed');
        }
    }
    initConversationSidebarState();
}

// Toggle the left conversation list on the chat page: collapse/expand
function toggleConversationSidebar() {
    const sidebar = document.getElementById('conversation-sidebar');
    if (sidebar) {
        sidebar.classList.toggle('collapsed');
        const isCollapsed = sidebar.classList.contains('collapsed');
        localStorage.setItem('conversationSidebarCollapsed', isCollapsed ? 'true' : 'false');
    }
}
window.toggleConversationSidebar = toggleConversationSidebar;

// Restore conversation list collapse state (applied when entering the chat page)
function initConversationSidebarState() {
    const sidebar = document.getElementById('conversation-sidebar');
    if (sidebar) {
        const savedState = localStorage.getItem('conversationSidebarCollapsed');
        if (savedState === 'true') {
            sidebar.classList.add('collapsed');
        } else {
            sidebar.classList.remove('collapsed');
        }
    }
}

// Export functions for use by other scripts
window.currentPage = function() { return currentPage; };
