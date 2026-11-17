let currentConversationId = null;

/** Persist the visible chat in the URL so a reload can restore and reconnect it. */
function syncChatConversationHash(conversationId) {
    const normalizedConversationId = String(conversationId || '').trim();
    if (!normalizedConversationId || window.location.hash.split('?')[0] !== '#chat') return;
    const targetHash = '#chat?conversation=' + encodeURIComponent(normalizedConversationId);
    if (window.location.hash !== targetHash) {
        window.history.replaceState(null, '', targetHash);
    }
}
window.syncChatConversationHash = syncChatConversationHash;

function clearChatConversationHash() {
    if (window.location.hash.split('?')[0] !== '#chat' || window.location.hash === '#chat') return;
    window.history.replaceState(null, '', '#chat');
}
window.clearChatConversationHash = clearChatConversationHash;
let loadConversationRequestSeq = 0;
let loadConversationAbortController = null;
let loadConversationPendingId = '';
let chatConversationNavigationSeq = 0;

function isChatConversationLoadPending(conversationId) {
    const id = String(conversationId || '').trim();
    return !!id && loadConversationPendingId === id;
}
window.isChatConversationLoadPending = isChatConversationLoadPending;

function markChatConversationNavigation(nextConversationId, force = false) {
    const nextId = String(nextConversationId || '').trim();
    const visibleId = String(currentConversationId || '').trim();
    if (force || nextId !== visibleId) {
        chatConversationNavigationSeq++;
    }
    return chatConversationNavigationSeq;
}

/**
 * When leaving the chat page, immediately revoke page ownership from any send request still initializing.
 * The backend task keeps running; here we only abort the browser foreground stream, so the first conversation
 * event does not reclaim the current conversation after the user has already switched to another page.
 */
function abandonChatConversationForPageNavigation() {
    markChatConversationNavigation('', true);
    if (typeof window.cancelScheduledChatConversationFromHash === 'function') {
        window.cancelScheduledChatConversationFromHash();
    }
    cancelPendingConversationLoad();
    detachLiveChatStreamForNavigation('', true);
}
window.abandonChatConversationForPageNavigation = abandonChatConversationForPageNavigation;

/**
 * Lightweight conversation LRU cache.
 *
 * The cache is only used as fallback data when a request fails; it must not render before the server response:
 * process details of running conversations keep being written; rendering an old snapshot directly would make
 * the UI temporarily fall back to an old turn, then jump to the latest turn once task-events takes over.
 */
const CONVERSATION_LITE_CACHE_MAX = 12;
const conversationLiteCache = new Map();

function getConversationLiteFromCache(conversationId) {
    if (!conversationId) return null;
    const hit = conversationLiteCache.get(conversationId);
    if (!hit) return null;
    conversationLiteCache.delete(conversationId);
    conversationLiteCache.set(conversationId, hit);
    return hit;
}

function putConversationLiteCache(conversationId, data) {
    if (!conversationId || !data) return;
    conversationLiteCache.delete(conversationId);
    conversationLiteCache.set(conversationId, data);
    while (conversationLiteCache.size > CONVERSATION_LITE_CACHE_MAX) {
        const oldest = conversationLiteCache.keys().next().value;
        conversationLiteCache.delete(oldest);
    }
}

function invalidateConversationLiteCache(conversationId) {
    if (conversationId) {
        conversationLiteCache.delete(conversationId);
    } else {
        conversationLiteCache.clear();
    }
}

window.invalidateConversationLiteCache = invalidateConversationLiteCache;

// @ mention related state
let mentionTools = [];
let mentionToolsLoaded = false;
let mentionToolsLoadingPromise = null;
let mentionSuggestionsEl = null;
let mentionFilteredTools = [];
let externalMcpNames = []; // External MCP name list
const mentionState = {
    active: false,
    startIndex: -1,
    query: '',
    selectedIndex: 0,
};

// IME composition state tracking
let isComposing = false;
let compositionEndTimer = null;

// Input draft saving
const DRAFT_STORAGE_KEY = 'veritysec-chat-draft';
const RECENT_CONVERSATIONS_EXPANDED_KEY = 'veritysec-chat-recent-conversations-expanded';
let draftSaveTimer = null;
const DRAFT_SAVE_DELAY = 500; // 500ms debounce delay

// Chat file upload (the backend concatenates paths and contents when sending to the LLM; the frontend no longer resends the file list)
const MAX_CHAT_FILES = 10;
const CHAT_FILE_DEFAULT_PROMPT = 'Please analyze the contents of the uploaded file.';
/** Matches the first segment of handler.formatInterruptContinueUserMessage; not shown in the main conversation, only in iteration details (user_interrupt_continue) */
const CHAT_INTERRUPT_CONTINUE_USER_PREFIX = '[User supplement / continue after interruption]';
function isInterruptContinueInjectChatMessage(content) {
    return typeof content === 'string' && content.trimStart().startsWith(CHAT_INTERRUPT_CONTINUE_USER_PREFIX);
}
/**
* Chat attachments: after selecting files they are POSTed asynchronously to /api/chat-uploads; on send only serverPath (absolute path) is passed, and large file contents are no longer inlined in the request body.
 * @type {{ id: number, fileName: string, mimeType: string, serverPath: string|null, uploading: boolean, uploadPercent: number, uploadPromise: Promise<void>|null, uploadError: string|null }[]}
 */
let chatAttachments = [];
let chatAttachmentSeq = 0;

// Conversation mode: eino_single = Eino ADK single agent (/api/eino-agent/stream); deep / plan_execute / supervisor = Eino multi-agent (/api/multi-agent/stream, request body orchestration)
const AGENT_MODE_STORAGE_KEY = 'veritysec-chat-agent-mode';
const AGENT_MODE_CONVERSATION_STORAGE_PREFIX = 'veritysec-chat-agent-mode:conversation';
const AI_CHANNEL_STORAGE_KEY = 'veritysec-chat-ai-channel';
const REASONING_MODE_LS = 'veritysec-chat-reasoning-mode';
const REASONING_EFFORT_LS = 'veritysec-chat-reasoning-effort';
const CHAT_AI_CHANNEL_SUMMARY_NAME_MAX = 10;
const CHAT_AGENT_MODE_EINO_SINGLE = 'eino_single';
const CHAT_AGENT_EINO_MODES = ['deep', 'plan_execute', 'supervisor'];
let multiAgentAPIEnabled = false;
let chatAIChannels = {};
let chatDefaultAIChannel = '';
let chatAIChannelIdByNormalizedId = {};
let chatHitlAuditModelName = '';
let chatHitlAuditBackend = '';
let chatSystemModelRequestSeq = 0;
let chatSystemModelSaving = false;
let chatSystemModelCloseTimer = null;
let chatSystemModelOptions = [];
let chatSystemModelCurrent = '';
let chatSystemModelLoadError = '';
const CHAT_SYSTEM_MODEL_CACHE_TTL_MS = 5 * 60 * 1000;
const chatSystemModelCache = new Map();

// Human-in-the-loop (HITL) per-session config
const HITL_STORAGE_PREFIX = 'veritysec-chat-hitl';
const HITL_MODE_OFF = 'off';
const HITL_MODE_APPROVAL = 'approval';
const HITL_MODE_REVIEW_EDIT = 'review_edit';
const HITL_MODE_OPTIONS = [HITL_MODE_OFF, HITL_MODE_APPROVAL, HITL_MODE_REVIEW_EDIT];
const DEFAULT_HITL_TIMEOUT_SECONDS = 300;
// Agent orchestration/control tools are safe baseline exemptions for every
// conversation. Keep this separate from config.tool_whitelist: the latter is
// enforced globally by the backend and must not be copied into this field.
const DEFAULT_HITL_SESSION_TOOL_WHITELIST = 'tool_search, skill, task, write_todos, transfer_to_agent, exit, TaskCreate, TaskGet, TaskUpdate, TaskList, upsert_project_fact, get_project_fact';
let hitlApplyFeedbackTimer = null;
let hitlAutoSaveTimer = null;
let hitlConfigSyncConversationId = '';
let hitlConfigSyncPromise = Promise.resolve();
const sessionSettingsSelects = new Map();
let sessionSettingsSelectDocBound = false;

function sessionSettingsSelectLabel(option) {
    return option ? (option.textContent || option.label || option.value || '') : '';
}

function syncSessionSettingsSelect(select) {
    const reg = sessionSettingsSelects.get(select);
    if (!reg) return;
    const selected = select.options[select.selectedIndex];
    reg.value.textContent = sessionSettingsSelectLabel(selected);
    reg.trigger.disabled = !!select.disabled;
    reg.wrapper.classList.toggle('is-disabled', !!select.disabled);
    reg.menu.innerHTML = '';

    Array.prototype.forEach.call(select.options, function (option, index) {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'session-settings-select-option';
        item.setAttribute('role', 'option');
        item.setAttribute('data-index', String(index));
        item.setAttribute('aria-selected', option.selected ? 'true' : 'false');
        item.disabled = !!option.disabled;
        item.classList.toggle('is-selected', !!option.selected);

        const label = document.createElement('span');
        label.className = 'session-settings-select-option-label';
        label.textContent = sessionSettingsSelectLabel(option);
        item.appendChild(label);
        reg.menu.appendChild(item);
    });
}

function closeSessionSettingsSelect(select) {
    const reg = sessionSettingsSelects.get(select);
    if (!reg) return;
    reg.wrapper.classList.remove('open');
    reg.trigger.setAttribute('aria-expanded', 'false');
}

function closeAllSessionSettingsSelects() {
    sessionSettingsSelects.forEach(function (_reg, select) {
        closeSessionSettingsSelect(select);
    });
}

function enhanceSessionSettingsSelect(select) {
    if (!select || select.dataset.sessionSettingsSelect === '1') {
        if (select) syncSessionSettingsSelect(select);
        return;
    }
    const panel = select.closest && select.closest('.conversation-reasoning-card');
    if (!panel) return;

    select.dataset.sessionSettingsSelect = '1';
    select.classList.add('session-settings-native-select');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');

    const wrapper = document.createElement('div');
    wrapper.className = 'session-settings-select';
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'session-settings-select-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    const value = document.createElement('span');
    value.className = 'session-settings-select-value';
    const caret = document.createElement('span');
    caret.className = 'session-settings-select-caret';
    caret.setAttribute('aria-hidden', 'true');
    caret.textContent = '⌄';
    trigger.appendChild(value);
    trigger.appendChild(caret);

    const menu = document.createElement('div');
    menu.className = 'session-settings-select-menu';
    menu.setAttribute('role', 'listbox');

    select.parentNode.insertBefore(wrapper, select);
    wrapper.appendChild(trigger);
    wrapper.appendChild(menu);
    wrapper.appendChild(select);
    sessionSettingsSelects.set(select, { wrapper: wrapper, trigger: trigger, value: value, menu: menu });

    trigger.addEventListener('click', function (event) {
        event.stopPropagation();
        if (select.disabled) return;
        const willOpen = !wrapper.classList.contains('open');
        closeAllSessionSettingsSelects();
        wrapper.classList.toggle('open', willOpen);
        trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
    });

    trigger.addEventListener('keydown', function (event) {
        if (select.disabled) return;
        const enabled = Array.prototype.filter.call(select.options, function (option) { return !option.disabled; });
        if (!enabled.length) return;
        const currentOption = select.options[select.selectedIndex];
        const current = Math.max(0, enabled.indexOf(currentOption));
        let next = current;
        if (event.key === 'ArrowDown') next = Math.min(enabled.length - 1, current + 1);
        else if (event.key === 'ArrowUp') next = Math.max(0, current - 1);
        else if (event.key === 'Home') next = 0;
        else if (event.key === 'End') next = enabled.length - 1;
        else if (event.key === 'Escape') {
            closeSessionSettingsSelect(select);
            return;
        } else if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            wrapper.classList.add('open');
            trigger.setAttribute('aria-expanded', 'true');
            return;
        } else {
            return;
        }
        event.preventDefault();
        const nextOption = enabled[next];
        if (nextOption && select.value !== nextOption.value) {
            select.value = nextOption.value;
            select.dispatchEvent(new Event('change', { bubbles: true }));
        }
        syncSessionSettingsSelect(select);
    });

    menu.addEventListener('click', function (event) {
        const item = event.target.closest('.session-settings-select-option');
        if (!item || item.disabled) return;
        event.stopPropagation();
        const option = select.options[Number(item.dataset.index)];
        if (option && !option.disabled && select.value !== option.value) {
            select.value = option.value;
            select.dispatchEvent(new Event('change', { bubbles: true }));
        }
        syncSessionSettingsSelect(select);
        closeSessionSettingsSelect(select);
    });

    select.addEventListener('change', function () {
        syncSessionSettingsSelect(select);
    });
    syncSessionSettingsSelect(select);
}

function initSessionSettingsSelects() {
    const panel = document.getElementById('conversation-reasoning-body');
    if (!panel) return;
    panel.querySelectorAll('select').forEach(enhanceSessionSettingsSelect);
    if (!sessionSettingsSelectDocBound) {
        document.addEventListener('click', closeAllSessionSettingsSelects);
        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') closeAllSessionSettingsSelects();
        });
        sessionSettingsSelectDocBound = true;
    }
}

function refreshSessionSettingsSelects() {
    sessionSettingsSelects.forEach(function (_reg, select) {
        syncSessionSettingsSelect(select);
    });
}

function syncChatReasoningBarHeight() {
    const reasoning = document.getElementById('chat-reasoning-wrapper');
    const inputBar = document.getElementById('chat-input-container');
    if (!reasoning || !inputBar) return;
    // The composer is now a two-layer surface and is intentionally taller than
    // the sidebar trigger. Do not mirror its height into the settings card.
    reasoning.style.removeProperty('--chat-input-bar-height');
    const chatContainer = inputBar.closest('.chat-container');
    const height = Math.ceil(inputBar.getBoundingClientRect().height || 0);
    if (chatContainer && height > 0) {
        chatContainer.style.setProperty('--chat-composer-total-height', height + 'px');
    }
}

function mountChatSessionSettingsPopover() {
    const wrap = document.getElementById('chat-reasoning-wrapper');
    const composerSurface = document.querySelector('.chat-composer-surface');
    if (!wrap || !composerSurface) return;
    if (wrap.parentElement !== composerSurface) {
        composerSurface.appendChild(wrap);
    }
    wrap.classList.add('chat-session-settings-popover');
    syncChatSessionSettingsLayerState();
}

function syncChatSessionSettingsLayerState() {
    const wrap = document.getElementById('chat-reasoning-wrapper');
    const inputBar = document.getElementById('chat-input-container');
    if (!inputBar) return;
    const open = !!wrap && wrap.style.display !== 'none' &&
        !wrap.classList.contains('conversation-reasoning-collapsed');
    inputBar.classList.toggle('is-session-settings-open', open);
}

function initChatReasoningBarHeightSync() {
    mountChatSessionSettingsPopover();
    syncChatReasoningBarHeight();
    window.addEventListener('resize', syncChatReasoningBarHeight);
    const inputBar = document.getElementById('chat-input-container');
    if (inputBar && typeof ResizeObserver !== 'undefined') {
        const ro = new ResizeObserver(syncChatReasoningBarHeight);
        ro.observe(inputBar);
    }
}

/** Non-blocking hint (shares styling with chat-files-toast) */
function showChatToast(message, type) {
    const text = message == null ? '' : String(message);
    if (!text) return;
    const el = document.createElement('div');
    el.className = 'chat-files-toast' + (type === 'error' ? ' chat-toast--error' : '');
    el.setAttribute('role', 'status');
    el.textContent = text;
    document.body.appendChild(el);
    requestAnimationFrame(function () {
        el.classList.add('chat-files-toast-visible');
    });
    const hideMs = type === 'error' ? 4500 : 2600;
    setTimeout(function () {
        el.classList.remove('chat-files-toast-visible');
        setTimeout(function () { el.remove(); }, 300);
    }, hideMs);
}
if (typeof window !== 'undefined') {
    window.showChatToast = showChatToast;
}

function normalizeOrchestrationClient(s) {
    const v = String(s || '').trim().toLowerCase().replace(/-/g, '_');
    if (v === 'plan_execute' || v === 'planexecute' || v === 'pe') return 'plan_execute';
    if (v === 'supervisor' || v === 'super' || v === 'sv') return 'supervisor';
    return 'deep';
}

function chatAgentModeIsEino(mode) {
    return CHAT_AGENT_EINO_MODES.indexOf(mode) >= 0;
}

function chatAgentModeIsEinoSingle(mode) {
    return mode === CHAT_AGENT_MODE_EINO_SINGLE;
}

function normalizeHitlMode(mode) {
    let v = String(mode || '').trim().toLowerCase().replace(/-/g, '_');
    if (v === 'feedback' || v === 'followup') {
        v = HITL_MODE_APPROVAL;
    }
    if (HITL_MODE_OPTIONS.includes(v)) return v;
    return HITL_MODE_OFF;
}

function normalizeHitlTimeoutForChat(value, fallback) {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.max(0, Math.min(86400, Math.round(n)));
}

function defaultHitlConfig() {
    const serverDefault = (typeof window !== 'undefined' && window.csaiHitlDefaultConfig && typeof window.csaiHitlDefaultConfig === 'object')
        ? window.csaiHitlDefaultConfig
        : {};
    const serverReviewer = serverDefault.reviewer || ((typeof window !== 'undefined' && window.csaiHitlDefaultReviewer)
        ? window.csaiHitlDefaultReviewer
        : 'human');
    return {
        mode: normalizeHitlMode(serverDefault.mode || HITL_MODE_OFF),
        reviewer: normalizeHitlReviewer(serverReviewer),
        sensitiveTools: DEFAULT_HITL_SESSION_TOOL_WHITELIST,
        timeoutSeconds: normalizeHitlTimeoutForChat(serverDefault.timeoutSeconds, DEFAULT_HITL_TIMEOUT_SECONDS),
        updatedAt: ''
    };
}

function normalizeHitlReviewer(v) {
    const x = String(v || '').trim().toLowerCase();
    if (x === 'audit_agent' || x === 'agent' || x === 'ai') return 'audit_agent';
    return 'human';
}

/** Split the whitelist string into an array (comma or newline separated, consistent with the textarea) */
function hitlToolsSplitToArray(s) {
    return String(s || '')
        .split(/[,\n\r]+/)
        .map(function (x) { return x.trim(); })
        .filter(Boolean);
}

/** Merged with config.yaml hitl.tool_whitelist for display in the input box (global items first; de-duplicated case-insensitively) */
function hitlMergeToolsForDisplay(globalArr, sessionToolsArr) {
    const seen = Object.create(null);
    const out = [];
    function addOne(t) {
        const n = String(t || '').trim();
        if (!n) return;
        const k = n.toLowerCase();
        if (seen[k]) return;
        seen[k] = true;
        out.push(n);
    }
    if (Array.isArray(globalArr)) {
        globalArr.forEach(addOne);
    }
    if (Array.isArray(sessionToolsArr)) {
        sessionToolsArr.forEach(addOne);
    }
    return out.join(', ');
}

/** Strip global whitelist tools before saving or sending requests, to avoid storing items already present in config in the session */
function hitlStripGlobalToolsFromFormString(globalArr, commaStr) {
    if (!Array.isArray(globalArr) || globalArr.length === 0) {
        return typeof commaStr === 'string' ? commaStr.trim() : '';
    }
    const g = Object.create(null);
    globalArr.forEach(function (t) {
        const k = String(t || '').trim().toLowerCase();
        if (k) g[k] = true;
    });
    return hitlToolsSplitToArray(commaStr)
        .filter(function (p) {
            return p && !g[p.toLowerCase()];
        })
        .join(', ');
}

function getHitlStorageKeyByConversation(conversationId) {
    return `${HITL_STORAGE_PREFIX}:${String(conversationId || '').trim()}`;
}

function chatTranslate(key, fallback) {
    if (typeof window.t === 'function') {
        const translated = window.t(key);
        if (translated && translated !== key) return translated;
    }
    return fallback;
}

function getHitlModeLabel(mode) {
    const safeMode = normalizeHitlMode(mode);
    switch (safeMode) {
        case HITL_MODE_APPROVAL:
            return chatTranslate('chat.hitlModeApproval', 'Approval mode');
        case HITL_MODE_REVIEW_EDIT:
            return chatTranslate('chat.hitlModeReviewEdit', 'Review & edit');
        default:
            return chatTranslate('chat.hitlModeOff', 'Off');
    }
}

function getHitlConfigForConversation(conversationId) {
    const fallback = defaultHitlConfig();
    const cid = conversationId ? String(conversationId).trim() : '';
    if (!cid) {
        return fallback;
    }
    const key = getHitlStorageKeyByConversation(cid);
    try {
        const raw = localStorage.getItem(key);
        if (!raw) {
            return fallback;
        }
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object') {
            return fallback;
        }
        return {
            mode: normalizeHitlMode(parsed.mode),
            reviewer: normalizeHitlReviewer(parsed.reviewer),
            sensitiveTools: typeof parsed.sensitiveTools === 'string' ? parsed.sensitiveTools : fallback.sensitiveTools,
            timeoutSeconds: normalizeHitlTimeoutForChat(parsed.timeoutSeconds, fallback.timeoutSeconds),
            updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : ''
        };
    } catch (e) {
        return fallback;
    }
}

function setHitlReviewerUI(reviewer) {
    const v = normalizeHitlReviewer(reviewer);
    const hidden = document.getElementById('hitl-reviewer-select');
    if (hidden) hidden.value = v;
    document.querySelectorAll('.hitl-reviewer-toggle-btn').forEach(function (btn) {
        const active = btn.getAttribute('data-reviewer') === v;
        btn.classList.toggle('is-active', active);
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
}

async function onHitlReviewerChanged(reviewer) {
    setHitlReviewerUI(reviewer);
    updateChatReasoningSummary();
    const cfg = readHitlConfigFromForm();
    const cid = typeof currentConversationId === 'string' ? currentConversationId.trim() : '';
    saveHitlConfigForConversation(cid, cfg, { syncGlobalLast: true });
    try {
        if (cid && typeof window.saveHitlConversationConfig === 'function') {
            await window.saveHitlConversationConfig(cid, cfg);
        } else if (typeof window.putHitlDefaultConfig === 'function') {
            await window.putHitlDefaultConfig(cfg);
        } else if (typeof window.putHitlDefaultReviewer === 'function') {
            await window.putHitlDefaultReviewer(cfg.reviewer);
        }
        const ok = typeof window.t === 'function' ? window.t('hitl.pageReviewerSaved') : 'Reviewer saved.';
        showChatToast(ok, 'success');
    } catch (e) {
        console.warn('onHitlReviewerChanged', e);
        const prefix = typeof window.t === 'function' ? window.t('chat.hitlApplyFail') : 'Failed to sync to server';
        showChatToast(prefix, 'error');
    }
}

function bindHitlReviewerToggleListeners() {
    document.querySelectorAll('.hitl-reviewer-toggle-btn').forEach(function (btn) {
        if (btn.dataset.hitlReviewerBound === '1') return;
        btn.dataset.hitlReviewerBound = '1';
        btn.addEventListener('click', function () {
            const v = btn.getAttribute('data-reviewer');
            if (!v) return;
            onHitlReviewerChanged(v);
        });
    });
}

function saveHitlConfigForConversation(conversationId, cfg, opts) {
    void opts;
    if (!conversationId) {
        return;
    }
    const payload = {
        mode: normalizeHitlMode(cfg && cfg.mode),
        reviewer: normalizeHitlReviewer(cfg && cfg.reviewer),
        sensitiveTools: typeof (cfg && cfg.sensitiveTools) === 'string' ? cfg.sensitiveTools : '',
        timeoutSeconds: normalizeHitlTimeoutForChat(cfg && cfg.timeoutSeconds, DEFAULT_HITL_TIMEOUT_SECONDS),
        updatedAt: typeof (cfg && cfg.updatedAt) === 'string' ? cfg.updatedAt : ''
    };
    const key = getHitlStorageKeyByConversation(conversationId);
    try {
        localStorage.setItem(key, JSON.stringify(payload));
    } catch (e) {
        console.warn('saveHitlConfigForConversation failed', e);
    }
}

function readHitlConfigFromForm() {
    const modeEl = document.getElementById('hitl-mode-select');
    const reviewerEl = document.getElementById('hitl-reviewer-select');
    const toolsEl = document.getElementById('hitl-sensitive-tools');
    const timeoutEl = document.getElementById('hitl-timeout-select');
    const mode = normalizeHitlMode(modeEl ? modeEl.value : HITL_MODE_OFF);
    const reviewer = normalizeHitlReviewer(reviewerEl ? reviewerEl.value : 'human');
    let sensitiveTools = toolsEl ? String(toolsEl.value || '').trim() : '';
    const g = typeof window !== 'undefined' ? window.csaiHitlGlobalToolWhitelist : null;
    if (Array.isArray(g) && g.length > 0) {
        sensitiveTools = hitlStripGlobalToolsFromFormString(g, sensitiveTools);
    }
    return {
        mode,
        reviewer,
        sensitiveTools,
        timeoutSeconds: normalizeHitlTimeoutForChat(timeoutEl ? timeoutEl.value : DEFAULT_HITL_TIMEOUT_SECONDS, DEFAULT_HITL_TIMEOUT_SECONDS),
        updatedAt: new Date().toISOString()
    };
}

function updateHitlStatusUI(_cfg) {
    /* Sidebar now autosaves; also update the input box quick summary. */
    updateChatReasoningSummary();
}

function applyHitlConfigToUI(cfg) {
    const conf = cfg || defaultHitlConfig();
    const modeEl = document.getElementById('hitl-mode-select');
    const toolsEl = document.getElementById('hitl-sensitive-tools');
    const timeoutEl = document.getElementById('hitl-timeout-select');
    const uiMode = normalizeHitlMode(conf.mode);
    if (modeEl) modeEl.value = uiMode;
    setHitlReviewerUI(conf.reviewer);
    // Keep this field scoped to the current conversation. The config-level
    // allowlist is applied by the backend and must not be copied into the
    // editable session value. Empty/legacy sessions receive only the stable
    // Agent control-tool baseline shown by the original UI.
    const toolsVal = typeof conf.sensitiveTools === 'string' && conf.sensitiveTools.trim()
        ? conf.sensitiveTools.trim()
        : DEFAULT_HITL_SESSION_TOOL_WHITELIST;
    if (toolsEl) {
        toolsEl.value = toolsVal;
    }
    if (timeoutEl) {
        const timeoutSeconds = normalizeHitlTimeoutForChat(conf.timeoutSeconds, DEFAULT_HITL_TIMEOUT_SECONDS);
        const supported = Array.from(timeoutEl.options || []).some(function (option) {
            return Number(option.value) === timeoutSeconds;
        });
        timeoutEl.value = String(supported ? timeoutSeconds : DEFAULT_HITL_TIMEOUT_SECONDS);
    }
    updateHitlStatusUI(conf);
    refreshSessionSettingsSelects();
}

function bindHitlSidebarModeListener() {
    const modeEl = document.getElementById('hitl-mode-select');
    const timeoutEl = document.getElementById('hitl-timeout-select');
    [modeEl, timeoutEl].forEach(function (el) {
        if (!el || el.dataset.hitlModeBound === '1') return;
        el.dataset.hitlModeBound = '1';
        el.addEventListener('change', function () {
            applyHitlConfigToUI(readHitlConfigFromForm());
            refreshSessionSettingsSelects();
            scheduleHitlSidebarAutosave(0);
            updateChatReasoningSummary();
        });
    });
}

function refreshHitlConfigByCurrentConversation() {
    const cfg = getHitlConfigForConversation(currentConversationId || '');
    applyHitlConfigToUI(cfg);
}

async function waitForHitlConfigReady(conversationId) {
    const cid = String(conversationId || '').trim();
    if (cid && hitlConfigSyncConversationId === cid) {
        await hitlConfigSyncPromise;
        return;
    }
    const defaultReady = window.csaiHitlDefaultConfigReady || window.csaiHitlDefaultReviewerReady;
    if (!cid && defaultReady && typeof defaultReady.then === 'function') {
        await defaultReady.catch(function () {});
        if (!currentConversationId) refreshHitlConfigByCurrentConversation();
    }
}

function showHitlApplyFeedback(text, isError, partial) {
    const el = document.getElementById('hitl-apply-feedback');
    if (hitlApplyFeedbackTimer) {
        clearTimeout(hitlApplyFeedbackTimer);
        hitlApplyFeedbackTimer = null;
    }
    if (!el) {
        if (text && isError) {
            showChatToast(text, 'error');
        }
        return;
    }
    el.classList.toggle('hitl-apply-feedback--error', !!isError);
    el.classList.toggle('hitl-apply-feedback--partial', !!partial && !isError);
    if (!text) {
        el.textContent = '';
        el.style.display = 'none';
        el.classList.remove('hitl-apply-feedback--error', 'hitl-apply-feedback--partial');
        return;
    }
    el.textContent = text;
    el.style.display = 'block';
    if (!isError) {
        hitlApplyFeedbackTimer = setTimeout(function () {
            el.textContent = '';
            el.style.display = 'none';
            el.classList.remove('hitl-apply-feedback--error');
            el.classList.remove('hitl-apply-feedback--partial');
            hitlApplyFeedbackTimer = null;
        }, 3200);
    }
}

/** Sidebar HITL: autosave locally, merge for display, and sync to the server when possible */
async function applyHitlSidebarConfig() {
    const btn = document.getElementById('hitl-apply-btn');
    showHitlApplyFeedback('', false);
    if (btn) btn.disabled = true;
    try {
        const cfg = readHitlConfigFromForm();
        const cid = typeof currentConversationId === 'string' ? currentConversationId.trim() : '';
        saveHitlConfigForConversation(cid, cfg, { syncGlobalLast: true });

        const toolsArr = hitlToolsSplitToArray(cfg.sensitiveTools || '');

        let yamlMerged = false;
        if (!cid && toolsArr.length > 0 && typeof window.mergeHitlGlobalToolWhitelist === 'function') {
            const newGlobal = await window.mergeHitlGlobalToolWhitelist(toolsArr);
            if (Array.isArray(newGlobal)) {
                window.csaiHitlGlobalToolWhitelist = newGlobal;
            }
            yamlMerged = true;
        }

        applyHitlConfigToUI(cfg);

        if (cid && typeof window.saveHitlConversationConfig === 'function') {
            await window.saveHitlConversationConfig(cid, cfg);
            const ok = typeof window.t === 'function' ? window.t('chat.hitlApplyOkSync') : 'HITL configuration saved and synced to the server.';
            showHitlApplyFeedback(ok, false);
        } else if (typeof window.putHitlDefaultConfig === 'function') {
            await window.putHitlDefaultConfig(cfg);
            const okDefault = typeof window.t === 'function' ? window.t('chat.hitlApplyOkDefaultConfig') : 'Default HITL configuration written to config.yaml and in effect.';
            showHitlApplyFeedback(okDefault, false);
        } else if (yamlMerged) {
            const okYaml = typeof window.t === 'function' ? window.t('chat.hitlApplyOkWhitelistYaml') : 'Auto-approved tools merged into config.yaml and in effect. Session config is saved automatically.';
            showHitlApplyFeedback(okYaml, false);
        } else {
            const localOnly = typeof window.t === 'function' ? window.t('chat.hitlApplyOkLocal') : 'Saved to this browser.';
            showHitlApplyFeedback(localOnly, false);
        }
        if (typeof window.refreshHitlPageWhitelist === 'function') {
            window.refreshHitlPageWhitelist();
        }
    } catch (e) {
        console.warn('applyHitlSidebarConfig', e);
        const prefix = typeof window.t === 'function' ? window.t('chat.hitlApplyFail') : 'Failed to sync to server';
        const detail = (e && e.message) ? e.message : String(e);
        showHitlApplyFeedback(prefix + (detail ? '：' + detail : ''), true);
    } finally {
        if (btn) btn.disabled = false;
    }
}

function scheduleHitlSidebarAutosave(delayMs) {
    if (hitlAutoSaveTimer) {
        clearTimeout(hitlAutoSaveTimer);
        hitlAutoSaveTimer = null;
    }
    hitlAutoSaveTimer = setTimeout(function () {
        hitlAutoSaveTimer = null;
        applyHitlSidebarConfig();
    }, typeof delayMs === 'number' ? delayMs : 500);
}

function bindHitlSensitiveToolsAutosaveListener() {
    const toolsEl = document.getElementById('hitl-sensitive-tools');
    if (!toolsEl || toolsEl.dataset.hitlAutosaveBound === '1') return;
    toolsEl.dataset.hitlAutosaveBound = '1';
    toolsEl.addEventListener('input', function () {
        scheduleHitlSidebarAutosave(700);
    });
    toolsEl.addEventListener('blur', function () {
        scheduleHitlSidebarAutosave(0);
    });
}

/** Normalize localStorage to eino_single | deep | plan_execute | supervisor */
function chatAgentModeNormalizeStored(stored, cfg) {
    const pub = cfg && cfg.multi_agent ? cfg.multi_agent : null;
    const multiOn = !!(pub && pub.enabled);
    const s = stored;
    if (chatAgentModeIsEinoSingle(s)) return s;
    if (chatAgentModeIsEino(s)) {
        return multiOn ? s : CHAT_AGENT_MODE_EINO_SINGLE;
    }
    return CHAT_AGENT_MODE_EINO_SINGLE;
}

function normalizeConversationAgentModeForUI(mode) {
    const v = String(mode || '').trim().toLowerCase().replace(/-/g, '_');
    if (chatAgentModeIsEinoSingle(v)) return v;
    if (chatAgentModeIsEino(v)) {
        return multiAgentAPIEnabled ? v : CHAT_AGENT_MODE_EINO_SINGLE;
    }
    return '';
}

function conversationAgentModeStorageKey(conversationId) {
    return `${AGENT_MODE_CONVERSATION_STORAGE_PREFIX}:${String(conversationId || '').trim()}`;
}

function readConversationAgentModePreference(conversationId) {
    if (!conversationId) return '';
    try {
        return normalizeConversationAgentModeForUI(localStorage.getItem(conversationAgentModeStorageKey(conversationId)) || '');
    } catch (e) {
        return '';
    }
}

function saveConversationAgentModePreference(conversationId, mode) {
    const normalized = normalizeConversationAgentModeForUI(mode);
    if (!conversationId || !normalized) return;
    try {
        localStorage.setItem(conversationAgentModeStorageKey(conversationId), normalized);
    } catch (e) { /* ignore */ }
}

function applyConversationAgentMode(conversationId, conversation) {
    const saved = readConversationAgentModePreference(conversationId);
    const fromServer = normalizeConversationAgentModeForUI(conversation && (conversation.agentMode || conversation.agent_mode));
    const mode = saved || fromServer;
    if (!mode) return;
    syncAgentModeFromValue(mode);
}

if (typeof window !== 'undefined') {
    window.csaiHitlGlobalToolWhitelist = window.csaiHitlGlobalToolWhitelist || [];
    window.csaiHitlDefaultConfig = window.csaiHitlDefaultConfig || {
        mode: HITL_MODE_OFF,
        reviewer: 'human',
        timeoutSeconds: DEFAULT_HITL_TIMEOUT_SECONDS
    };
    window.csaiHitlDefaultReviewer = window.csaiHitlDefaultReviewer || 'human';
    window.csaiChatAgentMode = {
        EINO_MODES: CHAT_AGENT_EINO_MODES,
        EINO_SINGLE: CHAT_AGENT_MODE_EINO_SINGLE,
        isEino: chatAgentModeIsEino,
        isEinoSingle: chatAgentModeIsEinoSingle,
        normalizeStored: chatAgentModeNormalizeStored,
        normalizeOrchestration: normalizeOrchestrationClient
    };
    window.applyHitlSidebarConfig = applyHitlSidebarConfig;
    window.readHitlConfigFromForm = readHitlConfigFromForm;
    window.applyHitlConfigToUI = applyHitlConfigToUI;
    window.refreshHitlConfigByCurrentConversation = refreshHitlConfigByCurrentConversation;
    window.saveHitlConfigForConversation = saveHitlConfigForConversation;
    window.getHitlConfigForConversation = getHitlConfigForConversation;
    bindHitlSidebarModeListener();
    bindHitlReviewerToggleListeners();
    bindHitlSensitiveToolsAutosaveListener();
    window.setHitlReviewerUI = setHitlReviewerUI;
    window.onHitlReviewerChanged = onHitlReviewerChanged;
    window.bindHitlReviewerToggleListeners = bindHitlReviewerToggleListeners;
    window.hitlMergeToolsForDisplay = hitlMergeToolsForDisplay;
    window.hitlStripGlobalToolsFromFormString = hitlStripGlobalToolsFromFormString;
    window.hitlToolsSplitToArray = hitlToolsSplitToArray;
    window.updateHitlStatusUI = updateHitlStatusUI;
}

function syncHitlSidebarAriaExpanded() {
    var card = document.getElementById('hitl-sidebar-card');
    var toggle = document.getElementById('hitl-sidebar-toggle');
    if (!card || !toggle) return;
    toggle.setAttribute('aria-expanded', card.classList.contains('hitl-sidebar-collapsed') ? 'false' : 'true');
}

function closeHitlSidebarCard() {
    var card = document.getElementById('hitl-sidebar-card');
    if (!card || card.classList.contains('hitl-sidebar-collapsed')) return;
    card.classList.add('hitl-sidebar-collapsed');
    syncHitlSidebarAriaExpanded();
    try {
        localStorage.setItem('hitl-sidebar-collapsed', '1');
    } catch (e) {}
}

function toggleHitlSidebarCard() {
    var card = document.getElementById('hitl-sidebar-card');
    if (!card) return;
    card.classList.toggle('hitl-sidebar-collapsed');
    syncHitlSidebarAriaExpanded();
    try {
        localStorage.setItem('hitl-sidebar-collapsed', card.classList.contains('hitl-sidebar-collapsed') ? '1' : '0');
    } catch (e) {}
}
window.toggleHitlSidebarCard = toggleHitlSidebarCard;

document.addEventListener('DOMContentLoaded', function () {
    var card = document.getElementById('hitl-sidebar-card');
    if (card && localStorage.getItem('hitl-sidebar-collapsed') === '0') {
        card.classList.remove('hitl-sidebar-collapsed');
    }
    syncHitlSidebarAriaExpanded();
});

function getAgentModeLabelForValue(mode) {
    if (typeof window.t === 'function') {
        switch (mode) {
            case 'deep':
                return window.t('chat.agentModeDeep');
            case 'plan_execute':
                return window.t('chat.agentModePlanExecuteLabel');
            case 'supervisor':
                return window.t('chat.agentModeSupervisorLabel');
            case CHAT_AGENT_MODE_EINO_SINGLE:
                return window.t('chat.agentModeEinoSingle');
            default:
                return mode;
        }
    }
    switch (mode) {
        case CHAT_AGENT_MODE_EINO_SINGLE: return 'Eino single agent';
        case 'deep': return 'Deep';
        case 'plan_execute': return 'Plan-Execute';
        case 'supervisor': return 'Supervisor';
        default: return mode;
    }
}

function getAgentModeIconClassForValue(mode) {
    switch (mode) {
        case CHAT_AGENT_MODE_EINO_SINGLE: return 'eino';
        case 'deep': return 'deep';
        case 'plan_execute': return 'plan';
        case 'supervisor': return 'supervisor';
        default: return 'default';
    }
}

function renderAgentModeLogoMarkup() {
    return '<svg class="agent-mode-logo__svg" viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><path d="M8 16h.01"/><path d="M16 16h.01"/></svg>';
}

function syncAgentModeFromValue(value) {
    const hid = document.getElementById('agent-mode-select');
    const label = document.getElementById('agent-mode-text');
    const icon = document.getElementById('agent-mode-icon');
    if (hid) hid.value = value;
    if (label) label.textContent = getAgentModeLabelForValue(value);
    if (icon) {
        icon.className = 'role-selector-icon agent-mode-logo agent-mode-logo--' + getAgentModeIconClassForValue(value);
        icon.innerHTML = renderAgentModeLogoMarkup();
    }
    document.querySelectorAll('.agent-mode-option').forEach(function (el) {
        const v = el.getAttribute('data-value');
        el.classList.toggle('selected', v === value);
    });
    syncReasoningRowVisibility(value);
}

function syncReasoningRowVisibility(modeVal) {
    mountChatSessionSettingsPopover();
    const wrap = document.getElementById('chat-reasoning-wrapper');
    if (!wrap) return;
    const show = modeVal === CHAT_AGENT_MODE_EINO_SINGLE || (multiAgentAPIEnabled && chatAgentModeIsEino(modeVal));
    wrap.style.display = show ? '' : 'none';
    if (!show) {
        closeChatReasoningPanel();
    } else {
        syncChatReasoningBarHeight();
        updateChatReasoningSummary();
    }
}

function normalizeChatAIChannelId(s) {
    return String(s || '').trim().toLowerCase().replace(/_/g, '-').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function resolveChatAIChannelId(id) {
    const raw = String(id || '').trim();
    if (!raw) return '';
    if (chatAIChannels[raw]) return raw;
    const normalized = normalizeChatAIChannelId(raw);
    return normalized && chatAIChannelIdByNormalizedId[normalized] ? chatAIChannelIdByNormalizedId[normalized] : '';
}

function populateChatAIChannelSelect(ai) {
    const select = document.getElementById('chat-ai-channel-select');
    if (!select) return;
    const cfg = ai && typeof ai === 'object' ? ai : {};
    chatAIChannels = cfg.channels && typeof cfg.channels === 'object' ? cfg.channels : {};
    chatAIChannelIdByNormalizedId = {};
    Object.keys(chatAIChannels).forEach(function (id) {
        const normalized = normalizeChatAIChannelId(id);
        if (normalized && !chatAIChannelIdByNormalizedId[normalized]) {
            chatAIChannelIdByNormalizedId[normalized] = id;
        }
    });
    chatDefaultAIChannel = resolveChatAIChannelId(cfg.default_channel || '');
    select.innerHTML = '';
    const fallbackOpt = document.createElement('option');
    fallbackOpt.value = '';
    fallbackOpt.textContent = typeof window.t === 'function' ? window.t('chat.aiChannelDefault') : 'Follow default channel';
    select.appendChild(fallbackOpt);
    Object.keys(chatAIChannels).sort().forEach(function (id) {
        const ch = chatAIChannels[id] || {};
        const opt = document.createElement('option');
        opt.value = id;
        opt.textContent = (ch.name || id) + (ch.model ? ' · ' + ch.model : '');
        select.appendChild(opt);
    });
    let stored = '';
    try { stored = localStorage.getItem(AI_CHANNEL_STORAGE_KEY) || ''; } catch (e) {}
    stored = resolveChatAIChannelId(stored);
    select.value = stored || '';
    refreshSessionSettingsSelects();
    updateChatReasoningSummary();
}

function selectedChatAIChannelId() {
    const select = document.getElementById('chat-ai-channel-select');
    return resolveChatAIChannelId(select ? select.value : '');
}

function currentChatAIChannelLabel() {
    const id = selectedChatAIChannelId() || chatDefaultAIChannel;
    const ch = id ? chatAIChannels[id] : null;
    if (!ch) {
        return chatTranslate('chat.aiChannelDefaultShort', 'Default channel');
    }
    return ch.name || id;
}

function currentChatModelLabel() {
    const id = selectedChatAIChannelId() || chatDefaultAIChannel;
    const ch = id ? chatAIChannels[id] : null;
    const model = ch && typeof ch.model === 'string' ? ch.model.trim() : '';
    return model || currentChatAIChannelLabel();
}

function currentSystemModelLabel() {
    const ch = chatDefaultAIChannel ? chatAIChannels[chatDefaultAIChannel] : null;
    const model = ch && typeof ch.model === 'string' ? ch.model.trim() : '';
    return model || (ch && (ch.name || chatDefaultAIChannel)) || currentChatModelLabel();
}

function currentHitlAuditBackend() {
    const b = String(chatHitlAuditBackend || (typeof window !== 'undefined' && window.csaiHitlAuditBackend) || '').trim().toLowerCase();
    return (b === 'typesafe' || b === 'jev' || b === 'type-safe') ? 'typesafe' : 'openai';
}

function currentHitlAuditModelLabel() {
    if (currentHitlAuditBackend() === 'typesafe') {
        return chatHitlAuditModelName || 'jev-latest';
    }
    return chatHitlAuditModelName || currentSystemModelLabel();
}

function currentHitlAuditEngineLabel() {
    const engine = currentHitlAuditBackend() === 'typesafe'
        ? chatTranslate('settings.hitl.auditBackendTypeSafe', 'TypeSafe Jev')
        : chatTranslate('settings.hitl.auditBackendOpenAI', 'OpenAI-compatible model');
    const model = currentHitlAuditModelLabel();
    return engine + (model ? ' · ' + model : '');
}

function resolveChatPickerChannelId() {
    return selectedChatAIChannelId() || chatDefaultAIChannel;
}

function chatSystemModelConfigState(cfg, preferredChannelId) {
    const source = cfg && typeof cfg === 'object' ? cfg : {};
    const sourceAI = source.ai && typeof source.ai === 'object' ? source.ai : {};
    const channels = sourceAI.channels && typeof sourceAI.channels === 'object'
        ? { ...sourceAI.channels }
        : {};
    const resolveFromChannels = function (value) {
        const raw = String(value || '').trim();
        if (raw && channels[raw]) return raw;
        const normalized = normalizeChatAIChannelId(raw);
        return normalized
            ? Object.keys(channels).find(function (id) {
                return normalizeChatAIChannelId(id) === normalized;
            }) || ''
            : '';
    };
    let defaultChannelId = resolveFromChannels(sourceAI.default_channel);
    let channelId = resolveFromChannels(preferredChannelId) || defaultChannelId;
    if (!channels[channelId]) {
        channelId = Object.keys(channels)[0] || 'default';
    }
    if (!channels[channelId]) {
        const legacy = source.openai && typeof source.openai === 'object' ? source.openai : {};
        channels[channelId] = {
            name: channelId === 'default' ? 'Default' : channelId,
            provider: legacy.provider || 'openai',
            api_key: legacy.api_key || '',
            base_url: legacy.base_url || '',
            model: legacy.model || ''
        };
    }
    if (!defaultChannelId) defaultChannelId = channelId;
    return {
        ai: { ...sourceAI, default_channel: defaultChannelId, channels: channels },
        channelId: channelId,
        channel: channels[channelId]
    };
}

function chatSystemModelElements() {
    return {
        wrap: document.getElementById('chat-model-shortcut-wrap'),
        button: document.getElementById('chat-model-shortcut'),
        menu: document.getElementById('chat-system-model-menu'),
        main: document.getElementById('chat-system-model-main'),
        subview: document.getElementById('chat-system-model-subview'),
        subviewTitle: document.getElementById('chat-system-model-subview-title'),
        list: document.getElementById('chat-system-model-list'),
        status: document.getElementById('chat-system-model-status'),
        subviewStatus: document.getElementById('chat-system-model-subview-status'),
        channelValue: document.getElementById('chat-system-model-channel-value'),
        currentValue: document.getElementById('chat-system-model-current-value'),
        modeValue: document.getElementById('chat-system-model-mode-value'),
        effortValue: document.getElementById('chat-system-model-effort-value')
    };
}

function setChatSystemModelStatus(message, tone) {
    const ui = chatSystemModelElements();
    [ui.status, ui.subviewStatus].forEach(function (status) {
        if (!status) return;
        status.textContent = message || '';
        status.dataset.tone = tone || '';
    });
}

function chatReasoningEffortLabel(value) {
    switch (String(value || '').trim()) {
        case 'low': return 'low';
        case 'medium': return 'medium';
        case 'high': return 'high';
        case 'xhigh': return 'xhigh';
        case 'max': return 'max';
        default: return chatTranslate('chat.reasoningEffortUnset', 'Unspecified');
    }
}

function currentChatReasoningEffort() {
    const effort = document.getElementById('chat-reasoning-effort');
    return effort ? String(effort.value || '').trim() : '';
}

function currentChatReasoningMode() {
    const mode = document.getElementById('chat-reasoning-mode');
    const value = mode ? String(mode.value || 'default').trim() : 'default';
    return ['default', 'off', 'on', 'auto'].includes(value) ? value : 'default';
}

function currentChatReasoningMenuLabel() {
    const modeValue = currentChatReasoningMode();
    if (modeValue === 'off') return chatTranslate('chat.reasoningModeOff', 'Off');
    const effort = currentChatReasoningEffort();
    return effort ? chatReasoningEffortLabel(effort) : reasoningSummaryModeLabel(modeValue);
}

function updateChatSystemModelPickerValues() {
    const ui = chatSystemModelElements();
    const channel = currentChatAIChannelLabel();
    const model = currentChatModelLabel();
    const mode = reasoningSummaryModeLabel(currentChatReasoningMode());
    const effort = currentChatReasoningMenuLabel();
    if (ui.channelValue) ui.channelValue.textContent = channel;
    if (ui.currentValue) ui.currentValue.textContent = model;
    if (ui.modeValue) ui.modeValue.textContent = mode;
    if (ui.effortValue) ui.effortValue.textContent = effort;
    const composerEffort = document.getElementById('chat-model-shortcut-effort');
    if (composerEffort) composerEffort.textContent = effort;
}

function closeChatSystemModelPicker(force) {
    if (chatSystemModelSaving && !force) return;
    const ui = chatSystemModelElements();
    if (ui.menu) ui.menu.hidden = true;
    if (ui.button) {
        ui.button.classList.remove('active');
        ui.button.setAttribute('aria-expanded', 'false');
    }
    if (ui.main) ui.main.hidden = false;
    if (ui.subview) ui.subview.hidden = true;
    chatSystemModelRequestSeq += 1;
}

async function readChatSystemModelError(response, fallback) {
    try {
        const body = await response.json();
        return body.error || body.message || fallback;
    } catch (_) {
        return fallback;
    }
}

function renderChatSystemModelOptions(models, currentModel) {
    const ui = chatSystemModelElements();
    if (!ui.list) return 0;
    ui.list.innerHTML = '';
    const unique = [];
    const seen = new Set();
    [currentModel].concat(Array.isArray(models) ? models : []).forEach(function (value) {
        const model = String(value || '').trim();
        if (!model || seen.has(model)) return;
        seen.add(model);
        unique.push(model);
    });
    unique.forEach(function (model) {
        const option = document.createElement('button');
        option.type = 'button';
        option.className = 'chat-system-model-option';
        option.setAttribute('role', 'option');
        option.setAttribute('aria-selected', model === currentModel ? 'true' : 'false');
        option.dataset.model = model;

        const label = document.createElement('span');
        label.className = 'chat-system-model-option-label';
        label.textContent = model;
        option.appendChild(label);

        if (model === currentModel) {
            option.classList.add('is-selected');
            const current = document.createElement('span');
            current.className = 'chat-system-model-current';
            current.textContent = chatTranslate('chat.systemModelCurrent', 'Current');
            option.appendChild(current);
        }
        option.addEventListener('click', function (event) {
            event.preventDefault();
            event.stopPropagation();
            selectChatSystemModel(model);
        });
        ui.list.appendChild(option);
    });
    return unique.length;
}

function renderChatReasoningEffortOptions() {
    const ui = chatSystemModelElements();
    if (!ui.list) return;
    ui.list.innerHTML = '';
    const currentEffort = currentChatReasoningEffort();
    ['', 'low', 'medium', 'high', 'xhigh', 'max'].forEach(function (effort) {
        const option = document.createElement('button');
        option.type = 'button';
        option.className = 'chat-system-model-option';
        option.setAttribute('role', 'option');
        option.setAttribute('aria-selected', effort === currentEffort ? 'true' : 'false');
        if (effort === currentEffort) option.classList.add('is-selected');

        const label = document.createElement('span');
        label.className = 'chat-system-model-option-label chat-system-effort-option-label';
        label.textContent = chatReasoningEffortLabel(effort);
        option.appendChild(label);

        if (effort === currentEffort) {
            const current = document.createElement('span');
            current.className = 'chat-system-model-current';
            current.textContent = chatTranslate('chat.systemModelCurrent', 'Current');
            option.appendChild(current);
        }
        option.addEventListener('click', function (event) {
            event.preventDefault();
            event.stopPropagation();
            selectChatReasoningEffort(effort);
        });
        ui.list.appendChild(option);
    });
}

function renderChatReasoningModeOptions() {
    const ui = chatSystemModelElements();
    if (!ui.list) return;
    ui.list.innerHTML = '';
    const currentMode = currentChatReasoningMode();
    ['default', 'off', 'on', 'auto'].forEach(function (mode) {
        const option = document.createElement('button');
        option.type = 'button';
        option.className = 'chat-system-model-option';
        option.setAttribute('role', 'option');
        option.setAttribute('aria-selected', mode === currentMode ? 'true' : 'false');
        if (mode === currentMode) option.classList.add('is-selected');
        const label = document.createElement('span');
        label.className = 'chat-system-model-option-label chat-system-effort-option-label';
        label.textContent = reasoningSummaryModeLabel(mode);
        option.appendChild(label);
        if (mode === currentMode) {
            const current = document.createElement('span');
            current.className = 'chat-system-model-current';
            current.textContent = chatTranslate('chat.systemModelCurrent', 'Current');
            option.appendChild(current);
        }
        option.addEventListener('click', function (event) {
            event.preventDefault();
            event.stopPropagation();
            selectChatReasoningMode(mode);
        });
        ui.list.appendChild(option);
    });
}

function finishChatReasoningPickerUpdate() {
    persistChatReasoningPrefs();
    setChatSystemModelStatus(chatTranslate('chat.reasoningSessionUpdated', 'Session reasoning settings updated'), 'success');
    if (chatSystemModelCloseTimer) window.clearTimeout(chatSystemModelCloseTimer);
    chatSystemModelCloseTimer = window.setTimeout(function () {
        chatSystemModelSaving = false;
        closeChatSystemModelPicker(true);
    }, 450);
}

function selectChatReasoningMode(mode) {
    if (chatSystemModelSaving) return;
    const chosen = ['default', 'off', 'on', 'auto'].includes(String(mode || '').trim())
        ? String(mode || '').trim()
        : 'default';
    const modeControl = document.getElementById('chat-reasoning-mode');
    if (!modeControl) return;
    chatSystemModelSaving = true;
    modeControl.value = chosen;
    finishChatReasoningPickerUpdate();
}

function selectChatReasoningEffort(effort) {
    if (chatSystemModelSaving) return;
    const raw = String(effort || '').trim();
    const chosen = ['', 'low', 'medium', 'high', 'xhigh', 'max'].includes(raw) ? raw : '';
    const effortControl = document.getElementById('chat-reasoning-effort');
    if (!effortControl) return;
    chatSystemModelSaving = true;
    effortControl.value = chosen;
    finishChatReasoningPickerUpdate();
}

function renderChatSystemModelRetry() {
    const ui = chatSystemModelElements();
    if (!ui.list) return;
    ui.list.innerHTML = '';
    const retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'chat-system-model-retry';
    retry.textContent = chatTranslate('chat.systemModelRetry', 'Retry');
    retry.addEventListener('click', function (retryEvent) {
        retryEvent.preventDefault();
        retryEvent.stopPropagation();
        fetchChatSystemModelsForChannel(resolveChatPickerChannelId(), { force: true });
    });
    ui.list.appendChild(retry);
}

function renderChatAIChannelOptions() {
    const ui = chatSystemModelElements();
    if (!ui.list) return;
    ui.list.innerHTML = '';
    const selected = selectedChatAIChannelId();
    const choices = [{ id: '', label: chatTranslate('chat.aiChannelDefault', 'Follow default channel') }]
        .concat(Object.keys(chatAIChannels).sort().map(function (id) {
            const channel = chatAIChannels[id] || {};
            return { id: id, label: channel.name || id };
        }));
    choices.forEach(function (choice) {
        const option = document.createElement('button');
        option.type = 'button';
        option.className = 'chat-system-model-option';
        option.setAttribute('role', 'option');
        option.setAttribute('aria-selected', choice.id === selected ? 'true' : 'false');
        if (choice.id === selected) option.classList.add('is-selected');
        const label = document.createElement('span');
        label.className = 'chat-system-model-option-label chat-system-channel-option-label';
        label.textContent = choice.label;
        option.appendChild(label);
        if (choice.id === selected) {
            const current = document.createElement('span');
            current.className = 'chat-system-model-current';
            current.textContent = chatTranslate('chat.systemModelCurrent', 'Current');
            option.appendChild(current);
        }
        option.addEventListener('click', function (event) {
            event.preventDefault();
            event.stopPropagation();
            selectChatAIChannel(choice.id);
        });
        ui.list.appendChild(option);
    });
}

async function selectChatAIChannel(channelId) {
    const select = document.getElementById('chat-ai-channel-select');
    if (!select) return;
    const resolved = resolveChatAIChannelId(channelId);
    select.value = resolved || '';
    persistChatAIChannelPref();
    refreshSessionSettingsSelects();
    updateChatSystemModelPickerValues();
    openChatSystemModelView('main');
    setChatSystemModelStatus(chatTranslate('chat.systemModelLoading', 'Loading model list…'), 'loading');
    await fetchChatSystemModelsForChannel(resolveChatPickerChannelId(), { force: true });
}

function openChatSystemModelView(view, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const ui = chatSystemModelElements();
    if (!ui.main || !ui.subview || !ui.list) return;
    if (view === 'main') {
        ui.main.hidden = false;
        ui.subview.hidden = true;
        updateChatSystemModelPickerValues();
        return;
    }
    ui.main.hidden = true;
    ui.subview.hidden = false;
    ui.subview.dataset.view = view;
    if (view === 'channel') {
        if (ui.subviewTitle) ui.subviewTitle.textContent = chatTranslate('chat.aiChannelLabel', 'AI channel');
        setChatSystemModelStatus('', '');
        renderChatAIChannelOptions();
        return;
    }
    if (view === 'mode') {
        if (ui.subviewTitle) ui.subviewTitle.textContent = chatTranslate('chat.reasoningModeLabel', 'Reasoning mode');
        setChatSystemModelStatus('', '');
        renderChatReasoningModeOptions();
        return;
    }
    if (view === 'effort') {
        if (ui.subviewTitle) ui.subviewTitle.textContent = chatTranslate('chat.reasoningEffortLabel', 'Reasoning effort');
        setChatSystemModelStatus('', '');
        renderChatReasoningEffortOptions();
        return;
    }
    if (ui.subviewTitle) ui.subviewTitle.textContent = chatTranslate('chat.systemModelField', 'Model');
    if (chatSystemModelOptions.length) {
        const count = renderChatSystemModelOptions(chatSystemModelOptions, chatSystemModelCurrent);
        setChatSystemModelStatus(
            chatTranslate('chat.systemModelLoaded', 'Loaded {count} models').replace('{count}', String(count)),
            'success'
        );
    } else if (chatSystemModelLoadError) {
        renderChatSystemModelRetry();
        setChatSystemModelStatus(chatSystemModelLoadError, 'error');
    } else {
        ui.list.innerHTML = '';
        setChatSystemModelStatus(chatTranslate('chat.systemModelLoading', 'Loading model list…'), 'loading');
    }
}

async function selectChatSystemModel(model) {
    if (chatSystemModelSaving) return;
    if (typeof requirePermission === 'function' && !requirePermission('config:write')) return;
    const chosen = String(model || '').trim();
    if (!chosen) return;
    const ui = chatSystemModelElements();
    chatSystemModelSaving = true;
    if (ui.list) {
        ui.list.querySelectorAll('button').forEach(function (button) { button.disabled = true; });
    }
    setChatSystemModelStatus(chatTranslate('chat.systemModelSaving', 'Saving…'), 'loading');
    try {
        const latestResponse = await apiFetch('/api/config');
        if (!latestResponse.ok) {
            throw new Error(await readChatSystemModelError(latestResponse, chatTranslate('chat.systemModelSaveFailed', 'Save failed')));
        }
        const latest = await latestResponse.json();
        const state = chatSystemModelConfigState(latest, resolveChatPickerChannelId());
        state.ai.channels[state.channelId] = { ...state.channel, model: chosen };
        const updateResponse = await apiFetch('/api/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ai: state.ai })
        });
        if (!updateResponse.ok) {
            throw new Error(await readChatSystemModelError(updateResponse, chatTranslate('chat.systemModelSaveFailed', 'Save failed')));
        }
        const applyResponse = await apiFetch('/api/config/apply', { method: 'POST' });
        if (!applyResponse.ok) {
            throw new Error(await readChatSystemModelError(applyResponse, chatTranslate('chat.systemModelApplyFailed', 'Failed to apply model')));
        }
        chatAIChannels = state.ai.channels;
        chatDefaultAIChannel = resolveChatAIChannelId(state.ai.default_channel) || state.channelId;
        updateChatComposerSessionShortcuts();
        await initChatAgentModeFromConfig();
        chatSystemModelCurrent = chosen;
        chatSystemModelOptions = [chosen].concat(chatSystemModelOptions);
        updateChatSystemModelPickerValues();
        renderChatSystemModelOptions(chatSystemModelOptions, chosen);
        setChatSystemModelStatus(chatTranslate('chat.systemModelSaved', 'Saved automatically'), 'success');
        if (chatSystemModelCloseTimer) window.clearTimeout(chatSystemModelCloseTimer);
        chatSystemModelCloseTimer = window.setTimeout(function () {
            chatSystemModelSaving = false;
            closeChatSystemModelPicker(true);
        }, 650);
        return;
    } catch (error) {
        console.error('selectChatSystemModel', error);
        setChatSystemModelStatus(error.message || chatTranslate('chat.systemModelSaveFailed', 'Save failed'), 'error');
    }
    chatSystemModelSaving = false;
    if (ui.list) {
        ui.list.querySelectorAll('button').forEach(function (button) { button.disabled = false; });
    }
}

function chatSystemModelCacheKey(channelId, channel) {
    return [
        String(channelId || ''),
        String(channel && channel.provider || 'openai'),
        String(channel && channel.base_url || '').trim()
    ].join('|');
}

async function fetchChatSystemModelsForChannel(channelId, options) {
    const opts = options || {};
    const ui = chatSystemModelElements();
    if (!ui.menu || !ui.list || ui.menu.hidden) return;
    const resolvedChannelId = resolveChatAIChannelId(channelId) || chatDefaultAIChannel;
    const channel = resolvedChannelId ? chatAIChannels[resolvedChannelId] || {} : {};
    const cacheKey = chatSystemModelCacheKey(resolvedChannelId, channel);
    const cached = chatSystemModelCache.get(cacheKey);
    const requestId = ++chatSystemModelRequestSeq;
    chatSystemModelCurrent = String(channel.model || '').trim();
    chatSystemModelOptions = [];
    chatSystemModelLoadError = '';
    if (!opts.force && cached && Date.now() - cached.fetchedAt < CHAT_SYSTEM_MODEL_CACHE_TTL_MS) {
        chatSystemModelOptions = cached.models.slice();
        if (ui.subview && !ui.subview.hidden && ui.subview.dataset.view === 'model') {
            renderChatSystemModelOptions(chatSystemModelOptions, chatSystemModelCurrent);
        }
        const cachedCount = [chatSystemModelCurrent].concat(chatSystemModelOptions)
            .map(function (model) { return String(model || '').trim(); })
            .filter(function (model, index, all) { return model && all.indexOf(model) === index; })
            .length;
        setChatSystemModelStatus(
            chatTranslate('chat.systemModelLoaded', 'Loaded {count} models').replace('{count}', String(cachedCount)),
            'success'
        );
        return;
    }
    if (ui.subview && !ui.subview.hidden && ui.subview.dataset.view === 'model') {
        ui.list.innerHTML = '';
    }
    setChatSystemModelStatus(chatTranslate('chat.systemModelLoading', 'Loading model list…'), 'loading');
    try {
        if (!String(channel.api_key || '').trim()) {
            throw new Error(chatTranslate('chat.systemModelNeedApiKey', 'Configure an API key in system settings first'));
        }
        const listResponse = await apiFetch('/api/config/list-models', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                provider: channel.provider || 'openai',
                base_url: String(channel.base_url || '').trim(),
                api_key: String(channel.api_key || '').trim()
            })
        });
        const result = await listResponse.json().catch(function () { return {}; });
        if (!listResponse.ok || !result.success) {
            throw new Error(result.error || chatTranslate('chat.systemModelLoadFailed', 'Failed to get models'));
        }
        if (requestId !== chatSystemModelRequestSeq || ui.menu.hidden) return;
        chatSystemModelOptions = Array.isArray(result.models) ? result.models.slice() : [];
        chatSystemModelCache.set(cacheKey, {
            models: chatSystemModelOptions.slice(),
            fetchedAt: Date.now()
        });
        const count = [chatSystemModelCurrent].concat(chatSystemModelOptions)
            .map(function (model) { return String(model || '').trim(); })
            .filter(function (model, index, all) { return model && all.indexOf(model) === index; })
            .length;
        if (ui.subview && !ui.subview.hidden && ui.subview.dataset.view === 'model') {
            renderChatSystemModelOptions(chatSystemModelOptions, chatSystemModelCurrent);
        }
        setChatSystemModelStatus(
            chatTranslate('chat.systemModelLoaded', 'Loaded {count} models').replace('{count}', String(count)),
            'success'
        );
    } catch (error) {
        if (requestId !== chatSystemModelRequestSeq || ui.menu.hidden) return;
        chatSystemModelLoadError = error.message || chatTranslate('chat.systemModelLoadFailed', 'Failed to get models');
        if (ui.subview && !ui.subview.hidden && ui.subview.dataset.view === 'model') {
            renderChatSystemModelRetry();
        }
        setChatSystemModelStatus(chatSystemModelLoadError, 'error');
    }
}

async function openChatSystemModelPicker(event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const ui = chatSystemModelElements();
    if (!ui.menu || !ui.button || !ui.list) return;
    if (!ui.menu.hidden) {
        closeChatSystemModelPicker();
        return;
    }
    if (chatSystemModelCloseTimer) {
        window.clearTimeout(chatSystemModelCloseTimer);
        chatSystemModelCloseTimer = null;
    }
    if (typeof closeChatReasoningPanel === 'function') closeChatReasoningPanel();
    ui.menu.hidden = false;
    ui.button.classList.add('active');
    ui.button.setAttribute('aria-expanded', 'true');
    if (ui.main) ui.main.hidden = false;
    if (ui.subview) ui.subview.hidden = true;
    ui.list.innerHTML = '';
    updateChatSystemModelPickerValues();
    await fetchChatSystemModelsForChannel(resolveChatPickerChannelId());
}

function truncateChatAIChannelSummaryLabel(label) {
    const chars = Array.from(String(label || ''));
    if (chars.length <= CHAT_AI_CHANNEL_SUMMARY_NAME_MAX) return chars.join('');
    return chars.slice(0, CHAT_AI_CHANNEL_SUMMARY_NAME_MAX).join('') + '...';
}

function persistChatAIChannelPref() {
    const id = selectedChatAIChannelId();
    try {
        if (id) localStorage.setItem(AI_CHANNEL_STORAGE_KEY, id);
        else localStorage.removeItem(AI_CHANNEL_STORAGE_KEY);
    } catch (e) {}
    updateChatReasoningSummary();
    updateChatSystemModelPickerValues();
}

function reasoningSummaryModeLabel(mode) {
    const m = (mode || 'default').trim();
    switch (m) {
        case 'off': return chatTranslate('chat.reasoningModeOff', 'Off');
        case 'on': return chatTranslate('chat.reasoningModeOn', 'On');
        case 'auto': return chatTranslate('chat.reasoningModeAuto', 'Auto');
        default: return chatTranslate('chat.reasoningSummaryFollow', 'System');
    }
}

function updateChatReasoningSummary() {
    const el = document.getElementById('chat-reasoning-summary');
    const modeEl = document.getElementById('chat-reasoning-mode');
    const effEl = document.getElementById('chat-reasoning-effort');
    if (!el || !modeEl) return;
    const mode = (modeEl.value || 'default').trim();
    const effort = effEl && effEl.value ? String(effEl.value).trim() : '';
    const t = (typeof window.t === 'function') ? window.t : function (k) { return k; };
    const modePart = reasoningSummaryModeLabel(mode);
    const reasoningPart = effort || modePart || t('chat.reasoningSummaryDash');
    let hitlPart = '';
    try {
        const hitlCfg = readHitlConfigFromForm();
        hitlPart = getHitlModeLabel(hitlCfg.mode);
    } catch (e) {
        hitlPart = '';
    }
    const channelPart = currentChatAIChannelLabel();
    const modelPart = currentChatModelLabel();
    el.textContent = hitlPart;
    el.title = hitlPart;
    updateChatComposerSessionShortcuts({
        channel: channelPart,
        model: modelPart,
        reasoning: reasoningPart,
        hitl: hitlPart
    });
}

function updateChatComposerSessionShortcuts(summary) {
    const data = summary || {};
    const modelEl = document.getElementById('chat-model-shortcut-text');
    const hitlEl = document.getElementById('chat-hitl-shortcut-text');
    if (modelEl) {
        // Show the current session channel's model on the right of the input box; the approval model only appears in the HITL entry.
        const label = currentChatModelLabel();
        modelEl.textContent = truncateChatAIChannelSummaryLabel(label);
        modelEl.title = label;
        const shortcut = document.getElementById('chat-model-shortcut');
        if (shortcut) {
            const channel = currentChatAIChannelLabel();
            const effort = currentChatReasoningMenuLabel();
            const action = chatTranslate('chat.modelSettingsAria', 'Choose AI channel, model and reasoning settings');
            shortcut.setAttribute('aria-label', action + '：' + channel + ' · ' + label + ' · ' + effort);
            shortcut.title = action + '：' + channel + ' · ' + label + ' · ' + effort;
        }
        updateChatSystemModelPickerValues();
    }
    if (hitlEl) {
        const cfg = readHitlConfigFromForm();
        const auditAgent = normalizeHitlReviewer(cfg.reviewer) === 'audit_agent';
        const prefix = auditAgent
            ? chatTranslate('chat.sessionShortcutAuditAgent', 'Agent review')
            : chatTranslate('chat.sessionShortcutHuman', 'Manual approval');
        const modeLabel = data.hitl || getHitlModeLabel(cfg.mode);
        const approvalModel = auditAgent ? currentHitlAuditEngineLabel() : '';
        const label = prefix + '：' + modeLabel + (approvalModel ? ' · ' + approvalModel : '');
        hitlEl.textContent = label;
        hitlEl.title = label;
    }
}

function openChatSessionSettings(section, event) {
    if (event && typeof event.stopPropagation === 'function') event.stopPropagation();
    mountChatSessionSettingsPopover();
    const wrap = document.getElementById('chat-reasoning-wrapper');
    const toggle = document.getElementById('conversation-reasoning-toggle');
    if (!wrap || !toggle || wrap.style.display === 'none') return;
    syncChatReasoningBarHeight();
    wrap.classList.remove('conversation-reasoning-collapsed');
    syncChatSessionSettingsLayerState();
    toggle.setAttribute('aria-expanded', 'true');
    if (typeof closeAgentModePanel === 'function') closeAgentModePanel();
    if (typeof closeRoleSelectionPanel === 'function') closeRoleSelectionPanel();
    if (typeof closeChatProjectPanel === 'function') closeChatProjectPanel();
    updateChatReasoningSummary();

    let target = null;
    if (section === 'hitl') target = document.getElementById('hitl-mode-select');
    else if (section === 'reasoning') target = document.getElementById('chat-reasoning-mode');
    else target = document.getElementById('chat-ai-channel-select');
    const group = target && target.closest('.session-settings-group');
    if (group && typeof group.scrollIntoView === 'function') {
        group.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
    const customTrigger = target && target.closest('.session-settings-select')
        ? target.closest('.session-settings-select').querySelector('.session-settings-select-trigger')
        : null;
    window.setTimeout(function () {
        if (customTrigger) customTrigger.focus({ preventScroll: true });
        else if (target) target.focus({ preventScroll: true });
    }, 180);
}

function getVisibleChatConversationId() {
    return typeof currentConversationId === 'string' && currentConversationId.trim()
        ? currentConversationId.trim()
        : '';
}

function shouldTreatLiveChatTaskAsCurrent(liveConversationId, visibleConversationId, hasVisibleProgress) {
    const liveId = String(liveConversationId || '').trim();
    const visibleId = String(visibleConversationId || '').trim();
    if (liveId) return !!visibleId && liveId === visibleId;
    return hasVisibleProgress === true;
}

function ownsLiveChatStream(liveStream) {
    return !!liveStream && window.__csAgentLiveStream === liveStream;
}

function shouldIgnoreLiveChatStreamEvent(
    liveStream,
    activeLiveStream = window.__csAgentLiveStream,
    navigationSeq = chatConversationNavigationSeq
) {
    return !liveStream ||
        activeLiveStream !== liveStream ||
        liveStream.active !== true ||
        liveStream.detached === true ||
        liveStream.navigationSeq !== navigationSeq;
}

function clearLiveChatStreamIfOwned(liveStream) {
    if (!ownsLiveChatStream(liveStream)) return false;
    liveStream.active = false;
    window.__csAgentLiveStream = { active: false, conversationId: null, progressId: null };
    updateChatPrimaryActionState();
    return true;
}

/**
* When leaving a conversation whose main POST stream is being read, only disconnect the browser-side response stream; the backend task is not stopped.
* The backend task uses detachedAgentContext and keeps running; when re-entering the conversation,
* the task-events mirror stream takes over. This way, running multiple conversations at once only occupies one foreground long connection,
* so it does not exhaust the browser's per-host connection slots and block ordinary GET/POST requests.
 */
function detachLiveChatStreamForNavigation(nextConversationId, force = false) {
    const liveStream = window.__csAgentLiveStream;
    if (!liveStream || !liveStream.active) return false;
    const liveConversationId = String(liveStream.conversationId || '').trim();
    const nextId = String(nextConversationId || '').trim();
    if (!force && liveConversationId && liveConversationId === nextId) return false;
    if (!force && !liveConversationId && !nextId) return false;

    liveStream.detached = true;
    liveStream.active = false;
    const controller = liveStream.abortController;
    if (controller && !controller.signal.aborted) {
        controller.abort();
    }
    if (ownsLiveChatStream(liveStream)) {
        updateChatPrimaryActionState();
    }
    return true;
}

function cancelPendingConversationLoad() {
    if (!loadConversationAbortController) return false;
    if (!loadConversationAbortController.signal.aborted) {
        loadConversationAbortController.abort();
    }
    loadConversationAbortController = null;
    return true;
}

function isLiveChatTaskVisible(live, visibleConversationId) {
    if (!live || !live.active) return false;
    const progress = live.progressId ? document.getElementById(live.progressId) : null;
    const hasVisibleProgress = !!(progress && progress.closest('#chat-messages'));
    return shouldTreatLiveChatTaskAsCurrent(
        live.conversationId,
        visibleConversationId,
        hasVisibleProgress
    );
}

function getCurrentChatTaskConversationId() {
    const visibleConversationId = getVisibleChatConversationId();
    if (visibleConversationId) return visibleConversationId;
    return '';
}

function isCurrentChatTaskActive() {
    const live = window.__csAgentLiveStream;
    const visibleConversationId = getVisibleChatConversationId();
    if (isLiveChatTaskVisible(live, visibleConversationId)) return true;
    return !!visibleConversationId &&
        typeof isConversationTaskRunning === 'function' &&
        isConversationTaskRunning(visibleConversationId);
}

function updateChatPrimaryActionState() {
    const button = document.getElementById('chat-send-btn');
    if (!button) return;
    const running = isCurrentChatTaskActive();
    const label = running
        ? chatTranslate('tasks.stopTask', 'Stop task')
        : chatTranslate('chat.send', 'Send');
    button.classList.toggle('is-task-running', running);
    button.setAttribute('aria-label', label);
    button.setAttribute('title', label);
    const labelElement = button.querySelector('.send-btn-label');
    if (labelElement) labelElement.textContent = label;
}

function handleChatPrimaryAction(event) {
    if (event) event.preventDefault();
    if (!isCurrentChatTaskActive()) {
        sendMessage();
        return;
    }

    const live = window.__csAgentLiveStream;
    const conversationId = getCurrentChatTaskConversationId();
    if (conversationId && typeof cancelActiveTask === 'function') {
        cancelActiveTask(conversationId);
        return;
    }
    if (live && live.progressId && typeof cancelProgressTask === 'function') {
        cancelProgressTask(live.progressId);
    }
}

function initChatPrimaryActionButton() {
    const button = document.getElementById('chat-send-btn');
    if (!button) return;
    if (!button.querySelector('.send-btn-stop-icon')) {
        const stopIcon = document.createElement('span');
        stopIcon.className = 'send-btn-stop-icon';
        stopIcon.setAttribute('aria-hidden', 'true');
        button.appendChild(stopIcon);
    }
    button.onclick = handleChatPrimaryAction;
    updateChatPrimaryActionState();
}

document.addEventListener('DOMContentLoaded', initChatPrimaryActionButton);

function closeChatReasoningPanel() {
    const wrap = document.getElementById('chat-reasoning-wrapper');
    const toggle = document.getElementById('conversation-reasoning-toggle');
    if (wrap) wrap.classList.add('conversation-reasoning-collapsed');
    syncChatSessionSettingsLayerState();
    if (toggle) toggle.setAttribute('aria-expanded', 'false');
}

function toggleConversationReasoningCard() {
    const wrap = document.getElementById('chat-reasoning-wrapper');
    const toggle = document.getElementById('conversation-reasoning-toggle');
    if (!wrap || !toggle) return;
    syncChatReasoningBarHeight();
    wrap.classList.toggle('conversation-reasoning-collapsed');
    syncChatSessionSettingsLayerState();
    const collapsed = wrap.classList.contains('conversation-reasoning-collapsed');
    toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    if (!collapsed) {
        if (typeof closeAgentModePanel === 'function') {
            closeAgentModePanel();
        }
        if (typeof closeRoleSelectionPanel === 'function') {
            closeRoleSelectionPanel();
        }
        updateChatReasoningSummary();
    }
}

function toggleChatReasoningPanel() {
    toggleConversationReasoningCard();
}

function restoreChatReasoningControlsFromStorage() {
    try {
        const m = document.getElementById('chat-reasoning-mode');
        const e = document.getElementById('chat-reasoning-effort');
        if (m) {
            const v = localStorage.getItem(REASONING_MODE_LS);
            if (v && ['default', 'off', 'on', 'auto'].indexOf(v) !== -1) {
                m.value = v;
            }
        }
        if (e) {
            const v = localStorage.getItem(REASONING_EFFORT_LS);
            if (v !== null && ['', 'low', 'medium', 'high', 'max', 'xhigh'].indexOf(v) !== -1) {
                e.value = v;
            }
        }
        refreshSessionSettingsSelects();
        updateChatReasoningSummary();
    } catch (err) { /* ignore */ }
}

function persistChatReasoningPrefs() {
    try {
        const m = document.getElementById('chat-reasoning-mode');
        const elEff = document.getElementById('chat-reasoning-effort');
        if (m) localStorage.setItem(REASONING_MODE_LS, m.value || 'default');
        if (elEff) localStorage.setItem(REASONING_EFFORT_LS, elEff.value || '');
        refreshSessionSettingsSelects();
        updateChatReasoningSummary();
    } catch (err) { /* ignore */ }
}

/** Reused by WebShell etc.: returns the reasoning request fragment on the Eino path, or undefined */
function buildReasoningRequestPayload() {
    const wrap = document.getElementById('chat-reasoning-wrapper');
    if (!wrap || wrap.style.display === 'none') {
        return undefined;
    }
    const modeEl = document.getElementById('chat-reasoning-mode');
    const effEl = document.getElementById('chat-reasoning-effort');
    if (!modeEl) return undefined;
    const mode = (modeEl.value || 'default').trim();
    const effort = effEl && effEl.value ? String(effEl.value).trim() : '';
    if (mode === 'default' && !effort) {
        return undefined;
    }
    const o = {};
    if (mode !== 'default') o.mode = mode;
    if (effort) o.effort = effort;
    return Object.keys(o).length ? o : undefined;
}

if (typeof window !== 'undefined') {
    window.persistChatAIChannelPref = persistChatAIChannelPref;
    window.populateChatAIChannelSelect = populateChatAIChannelSelect;
    window.persistChatReasoningPrefs = persistChatReasoningPrefs;
    window.buildReasoningRequestPayload = buildReasoningRequestPayload;
    window.closeChatReasoningPanel = closeChatReasoningPanel;
    window.toggleChatReasoningPanel = toggleChatReasoningPanel;
    window.toggleConversationReasoningCard = toggleConversationReasoningCard;
    window.updateChatReasoningSummary = updateChatReasoningSummary;
    window.updateChatComposerSessionShortcuts = updateChatComposerSessionShortcuts;
    window.openChatSessionSettings = openChatSessionSettings;
    window.openChatSystemModelPicker = openChatSystemModelPicker;
    window.openChatSystemModelView = openChatSystemModelView;
    window.closeChatSystemModelPicker = closeChatSystemModelPicker;
    window.refreshSessionSettingsSelects = refreshSessionSettingsSelects;
    window.updateChatPrimaryActionState = updateChatPrimaryActionState;
}

function closeAgentModePanel() {
    const panel = document.getElementById('agent-mode-panel');
    const btn = document.getElementById('agent-mode-btn');
    if (panel) panel.style.display = 'none';
    if (btn) {
        btn.classList.remove('active');
        btn.setAttribute('aria-expanded', 'false');
    }
}

function toggleAgentModePanel() {
    const panel = document.getElementById('agent-mode-panel');
    const btn = document.getElementById('agent-mode-btn');
    if (!panel || !btn) return;
    const isOpen = panel.style.display === 'flex';
    if (isOpen) {
        closeAgentModePanel();
        return;
    }
    if (typeof closeChatReasoningPanel === 'function') {
        closeChatReasoningPanel();
    }
    if (typeof closeRoleSelectionPanel === 'function') {
        closeRoleSelectionPanel();
    }
    if (typeof closeChatProjectPanel === 'function') {
        closeChatProjectPanel();
    }
    panel.style.display = 'flex';
    btn.classList.add('active');
    btn.setAttribute('aria-expanded', 'true');
}

function selectAgentMode(mode) {
    const ok = chatAgentModeIsEinoSingle(mode) || chatAgentModeIsEino(mode);
    if (!ok) return;
    saveConversationAgentModePreference(currentConversationId, mode);
    try {
        localStorage.setItem(AGENT_MODE_STORAGE_KEY, mode);
    } catch (e) { /* ignore */ }
    syncAgentModeFromValue(mode);
    closeAgentModePanel();
}

async function initChatAgentModeFromConfig() {
    const wrap = document.getElementById('agent-mode-wrapper');
    const sel = document.getElementById('agent-mode-select');
    if (!wrap || !sel) return;

    // Show the basic mode first, so a brief config API failure on first login does not hide the entry.
    wrap.style.display = '';
    let stored = localStorage.getItem(AGENT_MODE_STORAGE_KEY);
    if (!(chatAgentModeIsEinoSingle(stored) || chatAgentModeIsEino(stored))) {
        stored = CHAT_AGENT_MODE_EINO_SINGLE;
    }
    sel.value = stored;
    syncAgentModeFromValue(stored);
    document.querySelectorAll('.agent-mode-option').forEach(function (el) {
        const v = el.getAttribute('data-value');
        if (v === 'deep' || v === 'plan_execute' || v === 'supervisor') {
            el.style.display = 'none';
        } else {
            el.style.display = '';
        }
    });
    restoreChatReasoningControlsFromStorage();
    syncReasoningRowVisibility(stored);

    try {
        const r = await apiFetch('/api/config');
        if (!r.ok) return;
        const cfg = await r.json();
        multiAgentAPIEnabled = !!(cfg.multi_agent && cfg.multi_agent.enabled);
        populateChatAIChannelSelect(cfg.ai || {});
        const hitlAuditModel = cfg.hitl && cfg.hitl.audit_model;
        chatHitlAuditBackend = cfg.hitl && typeof cfg.hitl.audit_backend === 'string'
            ? cfg.hitl.audit_backend.trim().toLowerCase()
            : '';
        chatHitlAuditModelName = hitlAuditModel && typeof hitlAuditModel.model === 'string'
            ? hitlAuditModel.model.trim()
            : '';
        if (typeof window !== 'undefined') {
            window.csaiHitlAuditBackend = chatHitlAuditBackend;
            window.csaiHitlAuditModel = chatHitlAuditModelName;
            if (typeof window.renderHitlPageAuditEngine === 'function') {
                window.renderHitlPageAuditEngine();
            }
            if (typeof window.renderHitlStrategyJevHint === 'function') {
                window.renderHitlStrategyJevHint();
            }
        }
        updateChatReasoningSummary();
        if (typeof window !== 'undefined') {
            window.__csaiMultiAgentPublic = cfg.multi_agent || null;
            const tw = cfg.hitl && cfg.hitl.tool_whitelist;
            if (Array.isArray(tw)) {
                window.csaiHitlGlobalToolWhitelist = tw.slice();
            }
        }
        if (typeof window.refreshHitlPageWhitelist === 'function') {
            window.refreshHitlPageWhitelist();
        }
        document.querySelectorAll('.agent-mode-option').forEach(function (el) {
            const v = el.getAttribute('data-value');
            if (v === 'deep' || v === 'plan_execute' || v === 'supervisor') {
                el.style.display = multiAgentAPIEnabled ? '' : 'none';
            } else {
                el.style.display = '';
            }
        });
        stored = chatAgentModeNormalizeStored(stored, cfg);
        try {
            localStorage.setItem(AGENT_MODE_STORAGE_KEY, stored);
        } catch (e) { /* ignore */ }
        sel.value = stored;
        syncAgentModeFromValue(stored);
        restoreChatReasoningControlsFromStorage();
        syncReasoningRowVisibility(stored);
    } catch (e) {
        console.warn('initChatAgentModeFromConfig', e);
    }
}

document.addEventListener('languagechange', function () {
    const hid = document.getElementById('agent-mode-select');
    if (!hid) return;
    const v = hid.value;
    if (chatAgentModeIsEinoSingle(v) || chatAgentModeIsEino(v)) {
        syncAgentModeFromValue(v);
    }
    if (typeof updateChatReasoningSummary === 'function') {
        updateChatReasoningSummary();
    }
});

// Save input draft to localStorage (debounced version)
function saveChatDraftDebounced(content) {
    // Clear the previous timer
    if (draftSaveTimer) {
        clearTimeout(draftSaveTimer);
    }

    // Set new timer
    draftSaveTimer = setTimeout(() => {
        saveChatDraft(content);
    }, DRAFT_SAVE_DELAY);
}

// Save input draft to localStorage
function saveChatDraft(content) {
    try {
        const chatInput = document.getElementById('chat-input');
        const placeholderText = chatInput ? (chatInput.getAttribute('placeholder') || '').trim() : '';
        const trimmed = (content || '').trim();

        // Do not save the placeholder hint itself as a draft
        if (trimmed && (!placeholderText || trimmed !== placeholderText)) {
            localStorage.setItem(DRAFT_STORAGE_KEY, content);
        } else {
            // If content is empty or equals the placeholder hint, clear the saved draft
            localStorage.removeItem(DRAFT_STORAGE_KEY);
        }
    } catch (error) {
        // localStorage may be full or unavailable; fail silently
        console.warn('Failed to save draft:', error);
    }
}

// Restore input draft from localStorage
function restoreChatDraft() {
    try {
        const chatInput = document.getElementById('chat-input');
        if (!chatInput) {
            return;
        }
        const placeholderText = (chatInput.getAttribute('placeholder') || '').trim();
        // If the current value equals the placeholder, the hint was mistaken for content; clear it so the placeholder displays correctly
        if (placeholderText && chatInput.value.trim() === placeholderText) {
            chatInput.value = '';
        }
        // If the input box already has content, do not restore the draft (to avoid overwriting user input)
        if (chatInput.value && chatInput.value.trim().length > 0) {
            return;
        }

        const draft = localStorage.getItem(DRAFT_STORAGE_KEY);
        const trimmedDraft = draft ? draft.trim() : '';

        // If the draft content is the same as the placeholder hint, treat it as an invalid draft and do not restore it
        if (trimmedDraft && (!placeholderText || trimmedDraft !== placeholderText)) {
            chatInput.value = draft;
            // Adjust input box height to fit content
            adjustTextareaHeight(chatInput);
        } else if (trimmedDraft && placeholderText && trimmedDraft === placeholderText) {
            // Clean up the invalid draft to avoid interfering later
            localStorage.removeItem(DRAFT_STORAGE_KEY);
        }
    } catch (error) {
        console.warn('Failed to restore draft:', error);
    }
}

// Clear saved draft
function clearChatDraft() {
    try {
        // Clear synchronously to ensure it takes effect immediately
        localStorage.removeItem(DRAFT_STORAGE_KEY);
    } catch (error) {
        console.warn('Failed to clear draft:', error);
    }
}

// Adjust textarea height to fit content
function adjustTextareaHeight(textarea) {
    if (!textarea) return;

    // Reset height to auto first, then immediately set a fixed value to ensure an accurate scrollHeight
    textarea.style.height = 'auto';
    // Force the browser to recalculate layout
    void textarea.offsetHeight;

    // Calculate new height (min 40px, max 300px)
    const scrollHeight = textarea.scrollHeight;
    const newHeight = Math.min(Math.max(scrollHeight, 40), 300);
    textarea.style.height = newHeight + 'px';

    // If content is empty or very little, reset to minimum height immediately
    if (!textarea.value || textarea.value.trim().length === 0) {
        textarea.style.height = '40px';
    }
}

// Send message
async function sendMessage(options = {}) {
    const input = document.getElementById('chat-input');
    let message = input.value.trim();
    const hasAttachments = chatAttachments && chatAttachments.length > 0;
    const requestConversationId = currentConversationId;
    const requestNavigationSeq = chatConversationNavigationSeq;

    if (!message && !hasAttachments) {
        return;
    }

    // A restored conversation renders from the local cache first, while its
    // authoritative HITL config is fetched separately. Do not let a fast send
    // reuse the temporary/default reviewer (historically "human") before that
    // fetch completes, otherwise refreshing could turn Audit Agent review into
    // a human approval for the next tool call.
    const hitlConversationAtSendStart = String(currentConversationId || '').trim();
    await waitForHitlConfigReady(hitlConversationAtSendStart);
    if (String(currentConversationId || '').trim() !== hitlConversationAtSendStart) return;

    // Enter calls sendMessage directly; when the same conversation has already started a task in another tab,
    // an authoritative state sync must be done before rendering the user bubble and starting the POST, to avoid generating a bogus "task already running" exchange.
    if (currentConversationId && typeof loadActiveTasks === 'function') {
        await loadActiveTasks();
    }
    if (isCurrentChatTaskActive()) {
        updateChatPrimaryActionState();
        showChatToast(chatTranslate('chat.taskAlreadyRunning', 'A task is already running in this conversation. Wait for it to finish or stop it first.'), 'info');
        return;
    }

    if (hasAttachments) {
        const needWait = chatAttachments.some((a) => a.uploading);
        if (needWait) {
            const waitLabel = (typeof window.t === 'function')
                ? window.t('chat.waitingAttachmentsUpload')
                : 'Waiting for attachment uploads to finish…';
            chatAttachmentProgressSet(true, 0, waitLabel);
        }
        try {
            await Promise.all(chatAttachments.map((a) => (a.uploadPromise ? a.uploadPromise : Promise.resolve())));
        } finally {
            refreshChatAttachmentUploadProgress();
        }
        const bad = chatAttachments.filter((a) => !a.serverPath);
        if (bad.length) {
            const hint = (typeof window.t === 'function')
                ? window.t('chat.attachmentsUploadIncomplete')
                : 'Some attachments failed to upload. Remove the failed items or reselect files before sending.';
            alert(hint);
            return;
        }
    }

    // When there are attachments and the user has typed nothing, send a short default prompt (the backend concatenates paths and file contents for the LLM)
    if (hasAttachments && !message) {
        message = CHAT_FILE_DEFAULT_PROMPT;
    }

    // Pre-send task-status and attachment checks may involve async waits. If the user has already switched conversations,
    // keep the current page and do not write this not-yet-sent request into the newly visible conversation.
    if (requestNavigationSeq !== chatConversationNavigationSeq) {
        return;
    }

    // Show user message (including attachment names so the user can confirm)
    const displayMessage = hasAttachments
        ? message + '\n' + chatAttachments.map(a => '📎 ' + a.fileName).join('\n')
        : message;
    if (window.VeritySecChatScroll) {
        window.VeritySecChatScroll.onUserSendMessage();
    }
    addMessage('user', displayMessage, null, null, null, { scroll: 'none' });
    if (currentConversationId) {
        invalidateConversationLiteCache(currentConversationId);
    }

    // Clear the debounce timer to prevent re-saving the draft after clearing the input box
    if (draftSaveTimer) {
        clearTimeout(draftSaveTimer);
        draftSaveTimer = null;
    }

    // Clear the draft immediately to prevent restoration on page refresh
    clearChatDraft();
    // Use a synchronous method to ensure the draft is cleared
    try {
        localStorage.removeItem(DRAFT_STORAGE_KEY);
    } catch (e) {
        // Ignore errors
    }

    // Clear the input box and draft immediately (before sending the request)
    input.value = '';
    // Force reset the input box height to the initial height (40px)
    input.style.height = '40px';

    // Build request body (including attachments)
    const body = {
        message: message,
        conversationId: requestConversationId,
        role: typeof getCurrentRole === 'function' ? getCurrentRole() : ''
    };
    if (window.__csNextChatFinalizationPolicy && typeof window.__csNextChatFinalizationPolicy === 'object') {
        body.finalization = window.__csNextChatFinalizationPolicy;
        window.__csNextChatFinalizationPolicy = null;
    }
    let streamConversationId = body.conversationId ? String(body.conversationId) : null;
    const isStreamStillVisibleForRequest = function () {
        if (!document.getElementById(progressId)) return false;
        if (!streamConversationId) return currentConversationId === body.conversationId;
        return currentConversationId === streamConversationId;
    };
    if (!currentConversationId && typeof getActiveProjectId === 'function') {
        const pid = getActiveProjectId();
        if (pid) body.projectId = pid;
    }
    const aiChannelId = selectedChatAIChannelId();
    if (aiChannelId) {
        body.aiChannelId = aiChannelId;
    }
    const hitlCfg = readHitlConfigFromForm();
    if (normalizeHitlMode(hitlCfg.mode) !== HITL_MODE_OFF) {
        const sensitiveTools = hitlToolsSplitToArray(hitlCfg.sensitiveTools || '');
        body.hitl = {
            enabled: true,
            mode: normalizeHitlMode(hitlCfg.mode),
            reviewer: normalizeHitlReviewer(hitlCfg.reviewer),
            sensitiveTools: sensitiveTools,
            timeoutSeconds: normalizeHitlTimeoutForChat(hitlCfg.timeoutSeconds, DEFAULT_HITL_TIMEOUT_SECONDS)
        };
    }
    if (hasAttachments) {
        body.attachments = chatAttachments.map((a) => ({
            fileName: a.fileName,
            mimeType: a.mimeType || '',
            serverPath: a.serverPath
        }));
    }
    const reasoningPayload = buildReasoningRequestPayload();
    if (reasoningPayload) {
        body.reasoning = reasoningPayload;
    }
    // Clear the attachment list after sending
    chatAttachments = [];
    renderChatFileChips();

    // Create progress message container (uses detailed progress display)
    const progressId = addProgressMessage();
    if (window.VeritySecChatScroll) {
        window.VeritySecChatScroll.markProgressStreaming(true, progressId);
        window.VeritySecChatScroll.onUserSendMessage();
    }
    const progressElement = document.getElementById(progressId);
    registerProgressTask(progressId, streamConversationId);
    const requestAbortController = new AbortController();
    const liveStreamState = {
        active: true,
        conversationId: streamConversationId || null,
        progressId: progressId,
        abortController: requestAbortController,
        detached: false,
        navigationSeq: requestNavigationSeq
    };
    window.__csAgentLiveStream = liveStreamState;
    if (streamConversationId && typeof window.notifyConversationTaskStarted === 'function') {
        window.notifyConversationTaskStarted(streamConversationId);
    }
    updateChatPrimaryActionState();
    loadActiveTasks();
    let assistantMessageId = null;
    let mcpExecutionIds = [];

    try {
        const modeSel = document.getElementById('agent-mode-select');
        let modeVal = modeSel ? modeSel.value : CHAT_AGENT_MODE_EINO_SINGLE;
        saveConversationAgentModePreference(streamConversationId || currentConversationId, modeVal);
        const useMulti = multiAgentAPIEnabled && chatAgentModeIsEino(modeVal);
        const streamPath = useMulti ? '/api/multi-agent/stream' : '/api/eino-agent/stream';
        if (useMulti && modeVal) {
            body.orchestration = modeVal;
        }
        const response = await apiFetch(streamPath, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
            signal: requestAbortController.signal,
        });

        if (!response.ok) {
            throw new Error('Request failed: ' + response.status);
        }

        if (typeof options.onRequestAccepted === 'function') options.onRequestAccepted();

        liveStreamState.conversationId = streamConversationId || null;
        try {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';
            let streamSawDone = false;
            const dispatchStreamEvent = function (eventData) {
                if (eventData && eventData.type === 'done') {
                    streamSawDone = true;
                }
                const eventConvId = eventData && eventData.data && eventData.data.conversationId
                    ? String(eventData.data.conversationId)
                    : '';
                let justBoundConversation = false;
                if (eventConvId) {
                    if (streamConversationId && streamConversationId !== eventConvId) {
                        return;
                    }
                    if (!streamConversationId) {
                        streamConversationId = eventConvId;
                        liveStreamState.conversationId = eventConvId;
                        justBoundConversation = true;
                    }
                }
                // After switching conversations you may still receive buffered conversation and response_start
                // or response events from the old response stream. They can only fill in background task ownership and must not reclaim the current conversation.
                if (shouldIgnoreLiveChatStreamEvent(liveStreamState)) {
                    if (eventConvId) updateProgressConversation(progressId, eventConvId);
                    return;
                }
                if (!justBoundConversation && !isStreamStillVisibleForRequest()) {
                    return;
                }
                handleStreamEvent(eventData, progressElement, progressId,
                    () => assistantMessageId, (id) => { assistantMessageId = id; },
                    () => mcpExecutionIds, (ids) => { mcpExecutionIds = ids; },
                    { conversationId: streamConversationId });
            };
            const processSseLines = typeof processSseDataLinesYielding === 'function'
                ? processSseDataLinesYielding
                : async function (lines, onEvent) {
                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            try {
                                onEvent(JSON.parse(line.slice(6)));
                            } catch (e) {
                                console.error('Failed to parse event data:', e, line);
                            }
                        }
                    }
                };

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop(); // Keep the last incomplete line

                await processSseLines(lines, dispatchStreamEvent);
            }
            // Flush decoder internal buffer to avoid losing the final partial UTF-8 code point.
            buffer += decoder.decode();

            // Process remaining buffer
            if (buffer.trim()) {
                const lines = buffer.split('\n');
                await processSseLines(lines, dispatchStreamEvent);
            }
            if (!streamSawDone) {
                if (typeof loadActiveTasks === 'function') {
                    loadActiveTasks();
                }
                const convId = streamConversationId || (body && body.conversationId) || null;
                let attached = false;
                if (
                    convId &&
                    ownsLiveChatStream(liveStreamState) &&
                    !liveStreamState.detached &&
                    isStreamStillVisibleForRequest() &&
                    typeof window.attachRunningTaskEventStream === 'function'
                ) {
                    clearLiveChatStreamIfOwned(liveStreamState);
                    attached = await window.attachRunningTaskEventStream(convId).catch(() => false);
                }
                if (!attached && isStreamStillVisibleForRequest()) {
                    const hint = typeof window.t === 'function'
                        ? window.t('chat.streamEndedWithoutDone')
                        : 'The connection ended early without a task-completion signal. The task may still be running on the backend; check the running tasks at the top or refresh the current conversation.';
                    addMessage('system', hint);
                }
            }
        } finally {
            const clearedOwnedStream = clearLiveChatStreamIfOwned(liveStreamState);
            if (clearedOwnedStream && !liveStreamState.detached && window.VeritySecChatScroll) {
                window.VeritySecChatScroll.onStreamEnd();
            }
        }

        // After the message is sent successfully, make sure the draft is cleared again
        clearChatDraft();
        try {
            localStorage.removeItem(DRAFT_STORAGE_KEY);
        } catch (e) {
            // Ignore errors
        }

    } catch (error) {
        clearLiveChatStreamIfOwned(liveStreamState);
        if (liveStreamState.detached || !isStreamStillVisibleForRequest()) {
            if (typeof loadActiveTasks === 'function') {
                loadActiveTasks();
            }
            return;
        }
        removeMessage(progressId);
        const msg = error && error.message != null ? String(error.message) : String(error);
        const isNetwork = /network|fetch|Failed to fetch|aborted|AbortError|load failed|NetworkError/i.test(msg);
        if (isNetwork && typeof window.t === 'function') {
            addMessage('system', window.t('chat.streamNetworkErrorHint', { detail: msg }));
        } else if (isNetwork) {
            addMessage('system', 'Connection interrupted (' + msg + '). Long-running tasks may still be executing on the backend; check the running tasks at the top or refresh the conversation later.');
        } else {
            addMessage('system', 'Error: ' + msg);
        }
        if (typeof loadActiveTasks === 'function') {
            loadActiveTasks();
        }
        // On send failure, do not restore the draft, because the message is already shown in the conversation
    }
}

// ---------- Chat file upload ----------
function renderChatFileChips() {
    const list = document.getElementById('chat-file-list');
    if (!list) return;
    list.innerHTML = '';
    if (!chatAttachments.length) return;
    chatAttachments.forEach((a, i) => {
        const chip = document.createElement('div');
        chip.className = 'chat-file-chip';
        if (a.uploading) chip.classList.add('chat-file-chip--uploading');
        if (a.uploadError) chip.classList.add('chat-file-chip--error');
        chip.setAttribute('role', 'listitem');
        const name = document.createElement('span');
        name.className = 'chat-file-chip-name';
        name.title = a.fileName;
        let label = a.fileName;
        if (a.uploading) {
            label += ' · ' + ((typeof window.t === 'function') ? window.t('chat.attachmentUploading') : 'Uploading…');
        } else if (a.uploadError) {
            label += ' · ' + ((typeof window.t === 'function') ? window.t('chat.attachmentUploadFailed') : 'Failed');
        }
        name.textContent = label;
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'chat-file-chip-remove';
        remove.title = typeof window.t === 'function' ? window.t('common.remove') : 'Remove';
        remove.innerHTML = '×';
        remove.setAttribute('aria-label', 'Remove ' + a.fileName);
        remove.addEventListener('click', () => removeChatAttachment(i));
        chip.appendChild(name);
        chip.appendChild(remove);
        list.appendChild(chip);
    });
}

function removeChatAttachment(index) {
    chatAttachments.splice(index, 1);
    renderChatFileChips();
    refreshChatAttachmentUploadProgress();
}

// When there are attachments and the input box is empty, fill in a default prompt (editable); the backend separately concatenates paths and contents for the LLM
function appendChatFilePrompt() {
    const input = document.getElementById('chat-input');
    if (!input || !chatAttachments.length) return;
    if (!input.value.trim()) {
        input.value = CHAT_FILE_DEFAULT_PROMPT;
        adjustTextareaHeight(input);
    }
}

function chatAttachmentProgressSet(visible, percent, detailText) {
    const wrap = document.getElementById('chat-attachment-progress');
    const fill = document.getElementById('chat-attachment-progress-fill');
    const label = document.getElementById('chat-attachment-progress-label');
    if (!wrap || !fill || !label) return;
    if (!visible) {
        wrap.hidden = true;
        fill.style.width = '0%';
        label.textContent = '';
        return;
    }
    wrap.hidden = false;
    const p = Math.min(100, Math.max(0, Math.round(percent)));
    fill.style.width = p + '%';
    label.textContent = detailText || '';
}

function refreshChatAttachmentUploadProgress() {
    if (!chatAttachments.length) {
        chatAttachmentProgressSet(false);
        return;
    }
    const uploading = chatAttachments.filter((a) => a.uploading);
    if (!uploading.length) {
        chatAttachmentProgressSet(false);
        return;
    }
    let sum = 0;
    chatAttachments.forEach((a) => {
        sum += a.uploading ? (a.uploadPercent || 0) : 100;
    });
    const overall = Math.round(sum / chatAttachments.length);
    const line = (typeof window.t === 'function')
        ? window.t('chat.uploadingAttachmentsDetail', {
            done: chatAttachments.length - uploading.length,
            total: chatAttachments.length,
            percent: overall
        })
        : ('Uploading attachments ' + (chatAttachments.length - uploading.length) + '/' + chatAttachments.length + ' · ' + overall + '%');
    chatAttachmentProgressSet(true, overall, line);
}

async function uploadOneChatAttachment(entry, file) {
    const form = new FormData();
    form.append('file', file);
    const conv = currentConversationId;
    if (conv && String(conv).trim()) {
        form.append('conversationId', String(conv).trim());
    }
    const entryId = entry.id;
    try {
        const res = typeof apiUploadWithProgress === 'function'
            ? await apiUploadWithProgress('/api/chat-uploads', form, {
                onProgress: function (p) {
                    const cur = chatAttachments.find((x) => x.id === entryId);
                    if (cur) {
                        cur.uploadPercent = p.percent;
                        refreshChatAttachmentUploadProgress();
                    }
                }
            })
            : await apiFetch('/api/chat-uploads', { method: 'POST', body: form });
        if (!res.ok) {
            throw new Error(await res.text());
        }
        const data = await res.json().catch(() => ({}));
        const abs = data.absolutePath ? String(data.absolutePath).trim() : '';
        if (!abs) {
            throw new Error('no absolutePath in response');
        }
        const cur = chatAttachments.find((x) => x.id === entryId);
        if (cur) {
            cur.serverPath = abs;
            cur.uploading = false;
            cur.uploadPercent = 100;
            cur.uploadError = null;
        }
    } catch (e) {
        const msg = (e && e.message) ? e.message : String(e);
        const cur = chatAttachments.find((x) => x.id === entryId);
        if (cur) {
            cur.uploading = false;
            cur.uploadError = msg;
            cur.serverPath = null;
        }
        alert(((typeof window.t === 'function') ? window.t('chat.attachmentUploadAlert', { name: file.name }) : ('Upload failed: ' + file.name)) + '\n' + msg);
    }
    renderChatFileChips();
    refreshChatAttachmentUploadProgress();
}

async function addFilesToChat(files) {
    if (!files || !files.length) return;
    const next = Array.from(files);
    if (chatAttachments.length + next.length > MAX_CHAT_FILES) {
        alert('Up to ' + MAX_CHAT_FILES + ' files can be uploaded at once; currently selected: ' + chatAttachments.length + '.');
        return;
    }
    next.forEach((file) => {
        const id = ++chatAttachmentSeq;
        const entry = {
            id: id,
            fileName: file.name,
            mimeType: file.type || '',
            serverPath: null,
            uploading: true,
            uploadPercent: 0,
            uploadPromise: null,
            uploadError: null
        };
        entry.uploadPromise = uploadOneChatAttachment(entry, file);
        chatAttachments.push(entry);
    });
    renderChatFileChips();
    refreshChatAttachmentUploadProgress();
    appendChatFilePrompt();
}

function setupChatFileUpload() {
    const inputEl = document.getElementById('chat-file-input');
    const container = document.getElementById('chat-input-container') || document.querySelector('.chat-input-container');
    if (!inputEl || !container) return;

    inputEl.addEventListener('change', function () {
        const files = this.files;
        if (files && files.length) {
            addFilesToChat(files).catch(function () { /* addFilesToChat already showed a hint */ });
        }
        this.value = '';
    });

    container.addEventListener('dragover', function (e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.add('drag-over');
    });
    container.addEventListener('dragleave', function (e) {
        e.preventDefault();
        e.stopPropagation();
        if (!this.contains(e.relatedTarget)) {
            this.classList.remove('drag-over');
        }
    });
    container.addEventListener('drop', function (e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.remove('drag-over');
        const files = e.dataTransfer && e.dataTransfer.files;
        if (files && files.length) addFilesToChat(files).catch(function () { /* addFilesToChat already showed a hint */ });
    });
}

// Ensure chat-input-container has an id (if the template did not set one)
function ensureChatInputContainerId() {
    const c = document.querySelector('.chat-input-container');
    if (c && !c.id) c.id = 'chat-input-container';
}

function setupMentionSupport() {
    mentionSuggestionsEl = document.getElementById('mention-suggestions');
    if (mentionSuggestionsEl) {
        mentionSuggestionsEl.style.display = 'none';
        mentionSuggestionsEl.addEventListener('mousedown', (event) => {
            // Prevent the input box from losing focus when a suggestion is clicked
            event.preventDefault();
        });
    }
    ensureMentionToolsLoaded().catch(() => {
        // Ignore load errors; can retry later
    });
}

// Refresh tool list (reset loaded state, force reload)
function refreshMentionTools() {
    mentionToolsLoaded = false;
    mentionTools = [];
    externalMcpNames = [];
    mentionToolsLoadingPromise = null;
    // If the @ feature is currently in use, trigger a reload immediately
    if (mentionState.active) {
        ensureMentionToolsLoaded().catch(() => {
            // Ignore load errors
        });
    }
}

// Expose the refresh function on the window object for other modules to call
if (typeof window !== 'undefined') {
    window.refreshMentionTools = refreshMentionTools;
}

function ensureMentionToolsLoaded() {
    // Check whether the role changed; if so, force reload
    if (typeof window !== 'undefined' && window._mentionToolsRoleChanged) {
        mentionToolsLoaded = false;
        mentionTools = [];
        delete window._mentionToolsRoleChanged;
    }

    if (mentionToolsLoaded) {
        return Promise.resolve(mentionTools);
    }
    if (mentionToolsLoadingPromise) {
        return mentionToolsLoadingPromise;
    }
    mentionToolsLoadingPromise = fetchMentionTools().finally(() => {
        mentionToolsLoadingPromise = null;
    });
    return mentionToolsLoadingPromise;
}

// Generate a unique identifier for tools, to distinguish tools with the same name but different sources
function getToolKeyForMention(tool) {
    // For external tools, use external_mcp::tool.name as the unique identifier
    // For internal tools, use tool.name as the identifier
    if (tool.is_external && tool.external_mcp) {
        return `${tool.external_mcp}::${tool.name}`;
    }
    return tool.name;
}

async function fetchMentionTools() {
    const pageSize = 100;
    let page = 1;
    let totalPages = 1;
    const seen = new Set();
    const collected = [];

    try {
        // Get the currently selected role (from the function in roles.js)
        const roleName = typeof getCurrentRole === 'function' ? getCurrentRole() : '';

        // Also fetch the external MCP list
        try {
            const mcpResponse = await apiFetch('/api/external-mcp');
            if (mcpResponse.ok) {
                const mcpData = await mcpResponse.json();
                externalMcpNames = Object.keys(mcpData.servers || {}).filter(name => {
                    const server = mcpData.servers[name];
                    // Only include connected and enabled MCPs
                    return server.status === 'connected' &&
                           (server.config.external_mcp_enable || (server.config.enabled && !server.config.disabled));
                });
            }
        } catch (mcpError) {
            console.warn('Failed to load external MCP list:', mcpError);
            externalMcpNames = [];
        }

        while (page <= totalPages && page <= 20) {
            // Build the API URL; if a role is specified, add the role query parameter
            let url = `/api/config/tools?page=${page}&page_size=${pageSize}`;
            if (roleName && roleName !== 'default') {
                url += `&role=${encodeURIComponent(roleName)}`;
            }

            const response = await apiFetch(url);
            if (!response.ok) {
                break;
            }
            const result = await response.json();
            const tools = Array.isArray(result.tools) ? result.tools : [];
            tools.forEach(tool => {
                if (!tool || !tool.name) {
                    return;
                }
                // De-duplicate using the unique identifier rather than only the tool name
                const toolKey = getToolKeyForMention(tool);
                if (seen.has(toolKey)) {
                    return;
                }
                seen.add(toolKey);

                // Determine the tool's enabled state in the current role
                // If there is a role_enabled field, use it (indicates a role was specified)
                // Otherwise use the enabled field (indicates no role or all tools)
                let roleEnabled = tool.enabled !== false;
                if (tool.role_enabled !== undefined && tool.role_enabled !== null) {
                    roleEnabled = tool.role_enabled;
                }

                collected.push({
                    name: tool.name,
                    description: tool.description || '',
                    enabled: tool.enabled !== false, // The tool's own enabled state
                    roleEnabled: roleEnabled, // Enabled state in the current role
                    isExternal: !!tool.is_external,
                    externalMcp: tool.external_mcp || '',
                    toolKey: toolKey, // Save unique identifier
                });
            });
            totalPages = result.total_pages || 1;
            page += 1;
            if (page > totalPages) {
                break;
            }
        }
        mentionTools = collected;
        mentionToolsLoaded = true;
    } catch (error) {
        console.warn('Failed to load tool list; @ mention may be unavailable:', error);
    }
    return mentionTools;
}

function handleChatInputInput(event) {
    const textarea = event.target;
    updateMentionStateFromInput(textarea);
    // Automatically adjust input box height
    // Use requestAnimationFrame to adjust immediately after DOM updates, especially when content is deleted
    requestAnimationFrame(() => {
        adjustTextareaHeight(textarea);
    });
    // Save input content to localStorage (debounced)
    saveChatDraftDebounced(textarea.value);
}

function handleChatInputClick(event) {
    updateMentionStateFromInput(event.target);
}

function handleChatInputKeydown(event) {
    // While using an IME, Enter should confirm the candidate, not send the message
    // Safari may fire compositionend before the Enter keydown when confirming a candidate,
    // so both the global state and keyCode 229 are used as a fallback here.
    if (event.isComposing || isComposing || event.keyCode === 229) {
        return;
    }

    if (mentionState.active && mentionSuggestionsEl && mentionSuggestionsEl.style.display !== 'none') {
        if (event.key === 'ArrowDown') {
            event.preventDefault();
            moveMentionSelection(1);
            return;
        }
        if (event.key === 'ArrowUp') {
            event.preventDefault();
            moveMentionSelection(-1);
            return;
        }
        if (event.key === 'Enter' || event.key === 'Tab') {
            event.preventDefault();
            applyMentionSelection();
            return;
        }
        if (event.key === 'Escape') {
            event.preventDefault();
            deactivateMentionState();
            return;
        }
    }

    // Enter sends directly; Shift+Enter keeps the native textarea line-break behavior.
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        void sendMessage();
    }
}

function updateMentionStateFromInput(textarea) {
    if (!textarea) {
        deactivateMentionState();
        return;
    }
    const caret = textarea.selectionStart || 0;
    const textBefore = textarea.value.slice(0, caret);
    const atIndex = textBefore.lastIndexOf('@');

    if (atIndex === -1) {
        deactivateMentionState();
        return;
    }

    // The trigger character must be preceded by whitespace or be at the start
    if (atIndex > 0) {
        const boundaryChar = textBefore[atIndex - 1];
        if (boundaryChar && !/\s/.test(boundaryChar) && !'([{，。,.;:!?'.includes(boundaryChar)) {
            deactivateMentionState();
            return;
        }
    }

    const querySegment = textBefore.slice(atIndex + 1);

    if (querySegment.includes(' ') || querySegment.includes('\n') || querySegment.includes('\t') || querySegment.includes('@')) {
        deactivateMentionState();
        return;
    }

    if (querySegment.length > 60) {
        deactivateMentionState();
        return;
    }

    mentionState.active = true;
    mentionState.startIndex = atIndex;
    mentionState.query = querySegment.toLowerCase();
    mentionState.selectedIndex = 0;

    if (!mentionToolsLoaded) {
        renderMentionSuggestions({ showLoading: true });
    } else {
        updateMentionCandidates();
        renderMentionSuggestions();
    }

    ensureMentionToolsLoaded().then(() => {
        if (mentionState.active) {
            updateMentionCandidates();
            renderMentionSuggestions();
        }
    });
}

function updateMentionCandidates() {
    if (!mentionState.active) {
        mentionFilteredTools = [];
        return;
    }
    const normalizedQuery = (mentionState.query || '').trim().toLowerCase();
    let filtered = mentionTools;

    if (normalizedQuery) {
        // Check whether it exactly matches an external MCP name
        const exactMatchedMcp = externalMcpNames.find(mcpName =>
            mcpName.toLowerCase() === normalizedQuery
        );

        if (exactMatchedMcp) {
            // If it exactly matches an MCP name, show only that MCP's tools
            filtered = mentionTools.filter(tool => {
                return tool.externalMcp && tool.externalMcp.toLowerCase() === exactMatchedMcp.toLowerCase();
            });
        } else {
            // Check whether it partially matches an MCP name
            const partialMatchedMcps = externalMcpNames.filter(mcpName =>
                mcpName.toLowerCase().includes(normalizedQuery)
            );

            // Normal matching: filter by tool name and description, also matching MCP name
            filtered = mentionTools.filter(tool => {
                const nameMatch = tool.name.toLowerCase().includes(normalizedQuery);
                const descMatch = tool.description && tool.description.toLowerCase().includes(normalizedQuery);
                const mcpMatch = tool.externalMcp && tool.externalMcp.toLowerCase().includes(normalizedQuery);

                // If it partially matches an MCP name, also include all of that MCP's tools
                const mcpPartialMatch = partialMatchedMcps.some(mcpName =>
                    tool.externalMcp && tool.externalMcp.toLowerCase() === mcpName.toLowerCase()
                );

                return nameMatch || descMatch || mcpMatch || mcpPartialMatch;
            });
        }
    }

    filtered = filtered.slice().sort((a, b) => {
        // If a role is specified, prioritize tools enabled in the current role
        if (a.roleEnabled !== undefined || b.roleEnabled !== undefined) {
            const aRoleEnabled = a.roleEnabled !== undefined ? a.roleEnabled : a.enabled;
            const bRoleEnabled = b.roleEnabled !== undefined ? b.roleEnabled : b.enabled;
            if (aRoleEnabled !== bRoleEnabled) {
                return aRoleEnabled ? -1 : 1; // Enabled tools are listed first
            }
        }

        if (normalizedQuery) {
            // Tools exactly matching an MCP name are shown first
            const aMcpExact = a.externalMcp && a.externalMcp.toLowerCase() === normalizedQuery;
            const bMcpExact = b.externalMcp && b.externalMcp.toLowerCase() === normalizedQuery;
            if (aMcpExact !== bMcpExact) {
                return aMcpExact ? -1 : 1;
            }

            const aStarts = a.name.toLowerCase().startsWith(normalizedQuery);
            const bStarts = b.name.toLowerCase().startsWith(normalizedQuery);
            if (aStarts !== bStarts) {
                return aStarts ? -1 : 1;
            }
        }
        // If a role is specified use roleEnabled; otherwise use enabled
        const aEnabled = a.roleEnabled !== undefined ? a.roleEnabled : a.enabled;
        const bEnabled = b.roleEnabled !== undefined ? b.roleEnabled : b.enabled;
        if (aEnabled !== bEnabled) {
            return aEnabled ? -1 : 1;
        }
        return a.name.localeCompare(b.name, 'zh-CN');
    });

    mentionFilteredTools = filtered;
    if (mentionFilteredTools.length === 0) {
        mentionState.selectedIndex = 0;
    } else if (mentionState.selectedIndex >= mentionFilteredTools.length) {
        mentionState.selectedIndex = 0;
    }
}

function renderMentionSuggestions({ showLoading = false } = {}) {
    if (!mentionSuggestionsEl || !mentionState.active) {
        hideMentionSuggestions();
        return;
    }

    const currentQuery = mentionState.query || '';
    const existingList = mentionSuggestionsEl.querySelector('.mention-suggestions-list');
    const canPreserveScroll = !showLoading &&
        existingList &&
        mentionSuggestionsEl.dataset.lastMentionQuery === currentQuery;
    const previousScrollTop = canPreserveScroll ? existingList.scrollTop : 0;

    if (showLoading) {
        mentionSuggestionsEl.innerHTML = '<div class="mention-empty">' + (typeof window.t === 'function' ? window.t('chat.loadingTools') : 'Loading tools...') + '</div>';
        mentionSuggestionsEl.style.display = 'block';
        delete mentionSuggestionsEl.dataset.lastMentionQuery;
        return;
    }

    if (!mentionFilteredTools.length) {
        mentionSuggestionsEl.innerHTML = '<div class="mention-empty">' + (typeof window.t === 'function' ? window.t('chat.noMatchTools') : 'No matching tools') + '</div>';
        mentionSuggestionsEl.style.display = 'block';
        mentionSuggestionsEl.dataset.lastMentionQuery = currentQuery;
        return;
    }

    const itemsHtml = mentionFilteredTools.map((tool, index) => {
        const activeClass = index === mentionState.selectedIndex ? 'active' : '';
        // If the tool has a roleEnabled field (role specified), use it; otherwise use enabled
        const toolEnabled = tool.roleEnabled !== undefined ? tool.roleEnabled : tool.enabled;
        const disabledClass = toolEnabled ? '' : 'disabled';
        const badge = tool.isExternal ? '<span class="mention-item-badge">External</span>' : '<span class="mention-item-badge internal">Built-in</span>';
        const nameHtml = escapeHtml(tool.name);
        const description = tool.description && tool.description.length > 0 ? escapeHtml(tool.description) : (typeof window.t === 'function' ? window.t('chat.noDescription') : 'No description');
        const descHtml = `<div class="mention-item-desc">${description}</div>`;
        // Show the status label based on the tool's enabled state in the current role
        const statusLabel = toolEnabled ? 'Available' : (tool.roleEnabled !== undefined ? 'Disabled (current role)' : 'Disabled');
        const statusClass = toolEnabled ? 'enabled' : 'disabled';
        const originLabel = tool.isExternal
            ? (tool.externalMcp ? `Source: ${escapeHtml(tool.externalMcp)}` : 'Source: external MCP')
            : 'Source: built-in tool';

        return `
            <button type="button" class="mention-item ${activeClass} ${disabledClass}" data-index="${index}">
                <div class="mention-item-name">
                    <span class="mention-item-icon">🔧</span>
                    <span class="mention-item-text">@${nameHtml}</span>
                    ${badge}
                </div>
                ${descHtml}
                <div class="mention-item-meta">
                    <span class="mention-status ${statusClass}">${statusLabel}</span>
                    <span class="mention-origin">${originLabel}</span>
                </div>
            </button>
        `;
    }).join('');

    const listWrapper = document.createElement('div');
    listWrapper.className = 'mention-suggestions-list';
    listWrapper.innerHTML = itemsHtml;

    mentionSuggestionsEl.innerHTML = '';
    mentionSuggestionsEl.appendChild(listWrapper);
    mentionSuggestionsEl.style.display = 'block';
    mentionSuggestionsEl.dataset.lastMentionQuery = currentQuery;

    if (canPreserveScroll) {
        listWrapper.scrollTop = previousScrollTop;
    }

    listWrapper.querySelectorAll('.mention-item').forEach(item => {
        item.addEventListener('mousedown', (event) => {
            event.preventDefault();
            const idx = parseInt(item.dataset.index, 10);
            if (!Number.isNaN(idx)) {
                mentionState.selectedIndex = idx;
            }
            applyMentionSelection();
        });
    });

    scrollMentionSelectionIntoView();
}

function hideMentionSuggestions() {
    if (mentionSuggestionsEl) {
        mentionSuggestionsEl.style.display = 'none';
        mentionSuggestionsEl.innerHTML = '';
        delete mentionSuggestionsEl.dataset.lastMentionQuery;
    }
}

function deactivateMentionState() {
    mentionState.active = false;
    mentionState.startIndex = -1;
    mentionState.query = '';
    mentionState.selectedIndex = 0;
    mentionFilteredTools = [];
    hideMentionSuggestions();
}

function moveMentionSelection(direction) {
    if (!mentionFilteredTools.length) {
        return;
    }
    const max = mentionFilteredTools.length - 1;
    let nextIndex = mentionState.selectedIndex + direction;
    if (nextIndex < 0) {
        nextIndex = max;
    } else if (nextIndex > max) {
        nextIndex = 0;
    }
    mentionState.selectedIndex = nextIndex;
    updateMentionActiveHighlight();
}

function updateMentionActiveHighlight() {
    if (!mentionSuggestionsEl) {
        return;
    }
    const items = mentionSuggestionsEl.querySelectorAll('.mention-item');
    if (!items.length) {
        return;
    }
    items.forEach(item => item.classList.remove('active'));

    let targetIndex = mentionState.selectedIndex;
    if (targetIndex < 0) {
        targetIndex = 0;
    }
    if (targetIndex >= items.length) {
        targetIndex = items.length - 1;
        mentionState.selectedIndex = targetIndex;
    }

    const activeItem = items[targetIndex];
    if (activeItem) {
        activeItem.classList.add('active');
        scrollMentionSelectionIntoView(activeItem);
    }
}

function scrollMentionSelectionIntoView(targetItem = null) {
    if (!mentionSuggestionsEl) {
        return;
    }
    const activeItem = targetItem || mentionSuggestionsEl.querySelector('.mention-item.active');
    if (activeItem && typeof activeItem.scrollIntoView === 'function') {
        activeItem.scrollIntoView({
            block: 'nearest',
            inline: 'nearest',
            behavior: 'auto'
        });
    }
}

function applyMentionSelection() {
    const textarea = document.getElementById('chat-input');
    if (!textarea || mentionState.startIndex === -1 || !mentionFilteredTools.length) {
        deactivateMentionState();
        return;
    }

    const selectedTool = mentionFilteredTools[mentionState.selectedIndex] || mentionFilteredTools[0];
    if (!selectedTool) {
        deactivateMentionState();
        return;
    }

    const caret = textarea.selectionStart || 0;
    const before = textarea.value.slice(0, mentionState.startIndex);
    const after = textarea.value.slice(caret);
    const mentionText = `@${selectedTool.name}`;
    const needsSpace = after.length === 0 || !/^\s/.test(after);
    const insertText = mentionText + (needsSpace ? ' ' : '');

    textarea.value = before + insertText + after;
    const newCaret = before.length + insertText.length;
    textarea.focus();
    textarea.setSelectionRange(newCaret, newCaret);

    // Adjust input box height and save draft
    adjustTextareaHeight(textarea);
    saveChatDraftDebounced(textarea.value);

    deactivateMentionState();
}

function initializeChatUI() {
    const chatInputEl = document.getElementById('chat-input');
    if (chatInputEl) {
        // Set the correct height on initialization
        adjustTextareaHeight(chatInputEl);
        // Restore the saved draft (only when the input box is empty, to avoid overwriting user input)
        if (!chatInputEl.value || chatInputEl.value.trim() === '') {
            // Check whether there is a recent message in the conversation (within 30 seconds); if so, it may have just been sent, so do not restore the draft
            const messagesDiv = document.getElementById('chat-messages');
            let shouldRestoreDraft = true;
            if (messagesDiv && messagesDiv.children.length > 0) {
                // Check the time of the last message
                const lastMessage = messagesDiv.lastElementChild;
                if (lastMessage) {
                    const timeDiv = lastMessage.querySelector('.message-time');
                    if (timeDiv && timeDiv.textContent) {
                        // If the last message is a user message and very recent, do not restore the draft
                        const isUserMessage = lastMessage.classList.contains('user');
                        if (isUserMessage) {
                            // Check message time; if within the last 30 seconds, do not restore the draft
                            const now = new Date();
                            const messageTimeText = timeDiv.textContent;
                            // Simple check: if the message time shows the current time (format HH:MM) and it is a user message, do not restore the draft
                            // A more precise approach would check the message creation time, but it must be read from the message element
                            // Here a simple strategy is used: if the last message is a user message and the input box is empty, it may have just been sent, so do not restore the draft
                            shouldRestoreDraft = false;
                        }
                    }
                }
            }
            if (shouldRestoreDraft) {
                restoreChatDraft();
            } else {
                // Even if the draft is not restored, clear it from localStorage to avoid mistakenly restoring it next time
                clearChatDraft();
            }
        }
    }

    const messagesDiv = document.getElementById('chat-messages');
    if (messagesDiv && messagesDiv.childElementCount === 0) {
        renderChatWelcomeEmptyState();
    }

    addAttackChainButton(currentConversationId);
    loadActiveTasks(true);
    if (activeTaskInterval) {
        clearInterval(activeTaskInterval);
    }
    activeTaskInterval = setInterval(() => loadActiveTasks(), ACTIVE_TASK_REFRESH_INTERVAL);
    setupMentionSupport();
    ensureChatInputContainerId();
    setupChatFileUpload();
}

// Message counter to ensure unique IDs
let messageCounter = 0;

// Add an independent scroll container for tables in message bubbles
function wrapTablesInBubble(bubble) {
    const tables = bubble.querySelectorAll('table');
    tables.forEach(table => {
        // Check whether the table already has a wrapper container
        if (table.parentElement && table.parentElement.classList.contains('table-wrapper')) {
            return;
        }

        // Create table wrapper container
        const wrapper = document.createElement('div');
        wrapper.className = 'table-wrapper';

        // Move the table into the wrapper container
        table.parentNode.insertBefore(wrapper, table);
        wrapper.appendChild(table);
    });
}

const PROJECT_NAME_DISPLAY_MAX_CHARACTERS = 12;

/** Only limits how the project name is displayed in the UI; the saved name is not modified. */
function formatProjectNameForDisplay(value) {
    const fullName = String(value == null ? '' : value);
    const characters = Array.from(fullName);
    if (characters.length <= PROJECT_NAME_DISPLAY_MAX_CHARACTERS) return fullName;
    return `${characters.slice(0, PROJECT_NAME_DISPLAY_MAX_CHARACTERS).join('')}…`;
}

function applyProjectNameDisplay(element, value, fallback = '') {
    if (!element) return '';
    const fullName = String(value || fallback || '');
    element.textContent = formatProjectNameForDisplay(fullName);
    element.dataset.fullName = fullName;
    element.title = fullName;
    return fullName;
}

window.formatProjectNameForDisplay = formatProjectNameForDisplay;
window.applyProjectNameDisplay = applyProjectNameDisplay;

function getChatWelcomeProjectName() {
    const projectElement = document.getElementById('chat-project-text');
    const projectText = (projectElement?.dataset?.fullName || projectElement?.textContent || '').trim();
    return projectText || (typeof window.t === 'function' ? window.t('projects.noProject') : 'No project');
}

function getChatWelcomeText() {
    const project = getChatWelcomeProjectName();
    const noProject = typeof window.t === 'function' ? window.t('projects.noProject') : 'No project';
    if (!project || project === noProject) {
        return typeof window.t === 'function'
            ? window.t('chat.noProjectWelcomeMessage')
            : 'No project is selected. Enter your testing requirements; the system will run the appropriate security tests automatically.';
    }
    return typeof window.t === 'function'
        ? window.t('chat.projectWelcomeMessage', { project })
        : `Current project: ${project}. Enter your testing requirements; the system will run the appropriate security tests automatically.`;
}

function updateChatWelcomeTitle(title) {
    if (!title) return;
    const project = getChatWelcomeProjectName();
    const noProject = typeof window.t === 'function' ? window.t('projects.noProject') : 'No project';
    const subtitle = title.parentElement?.querySelector('.chat-welcome-empty-state-subtitle');

    if (project === noProject) {
        title.textContent = typeof window.t === 'function'
            ? window.t('chat.noProjectWelcomeTitle')
            : 'What do you want to test?';
    } else {
        const prefix = typeof window.t === 'function'
            ? window.t('chat.projectWelcomeTitlePrefix')
            : 'In ';
        const suffix = typeof window.t === 'function'
            ? window.t('chat.projectWelcomeTitleSuffix')
            : ' project, what do you want to test?';
        const projectName = document.createElement('span');
        projectName.className = 'chat-welcome-project-name';
        applyProjectNameDisplay(projectName, project);
        title.replaceChildren(document.createTextNode(prefix), projectName, document.createTextNode(suffix));
    }

    if (subtitle) {
        subtitle.textContent = typeof window.t === 'function'
            ? window.t('chat.welcomeSubtitle')
            : 'Enter your testing requirements; the system will run the appropriate security tests automatically.';
    }
}

function renderChatWelcomeEmptyState() {
    const messagesDiv = document.getElementById('chat-messages');
    if (!messagesDiv) return null;
    messagesDiv.querySelectorAll('.chat-welcome-empty-state').forEach((node) => node.remove());
    const state = document.createElement('div');
    state.className = 'chat-welcome-empty-state';
    state.setAttribute('role', 'status');
    state.setAttribute('aria-live', 'polite');
    state.innerHTML = '<p class="chat-welcome-empty-state-title"></p><p class="chat-welcome-empty-state-subtitle"></p>';
    updateChatWelcomeTitle(state.querySelector('.chat-welcome-empty-state-title'));
    messagesDiv.appendChild(state);
    return state;
}

/** Update the welcome empty state for a new conversation, and stay compatible with the legacy system-ready message left by older versions on refresh. */
function refreshSystemReadyMessageBubbles() {
    const text = getChatWelcomeText();
    const welcome = document.querySelector('.chat-welcome-empty-state-title');
    if (welcome) updateChatWelcomeTitle(welcome);
    const escapeHtmlLocal = (s) => {
        if (!s) return '';
        const div = document.createElement('div');
        div.textContent = s;
        return div.innerHTML;
    };
    let formattedContent;
    if (typeof window.csMarkdownSanitize !== 'undefined') {
        formattedContent = window.csMarkdownSanitize.formatMarkdownToHtml(text, { profile: 'chat' });
    } else {
        formattedContent = escapeHtmlLocal(text).replace(/\n/g, '<br>');
    }

    document.querySelectorAll('.message.assistant[data-system-ready-message]').forEach(function (messageDiv) {
        const bubble = messageDiv.querySelector('.message-bubble');
        if (!bubble) return;
        const copyBtn = bubble.querySelector('.message-copy-btn');
        if (copyBtn) copyBtn.remove();
        bubble.innerHTML = formattedContent;
        if (typeof wrapTablesInBubble === 'function') wrapTablesInBubble(bubble);
        messageDiv.dataset.originalContent = text;
        appendMessageCopyButton(messageDiv);
    });
}

function ensureMessageMetaFooter(content) {
    if (!content) return null;
    let footer = content.querySelector('.message-meta-footer');
    if (footer) return footer;
    const timeDiv = content.querySelector('.message-time');
    footer = document.createElement('div');
    footer.className = 'message-meta-footer';
    if (timeDiv && timeDiv.parentNode === content) {
        timeDiv.parentNode.insertBefore(footer, timeDiv);
        footer.appendChild(timeDiv);
    } else {
        content.appendChild(footer);
    }
    return footer;
}

function appendMessageCopyButton(messageDiv) {
    if (!messageDiv) return null;
    if (!messageDiv.classList || (!messageDiv.classList.contains('assistant') && !messageDiv.classList.contains('user'))) {
        return null;
    }
    const content = messageDiv.querySelector('.message-content');
    const footer = ensureMessageMetaFooter(content);
    if (!footer) return null;

    messageDiv.querySelectorAll('.message-bubble .message-copy-btn').forEach((btn) => btn.remove());
    let copyBtn = footer.querySelector('.message-copy-btn');
    if (copyBtn) return copyBtn;

    copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'message-copy-btn';
    copyBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg><span>' + (typeof window.t === 'function' ? window.t('common.copy') : 'Copy') + '</span>';
    copyBtn.title = typeof window.t === 'function' ? window.t('chat.copyMessageTitle') : 'Copy message content';
    copyBtn.setAttribute('aria-label', copyBtn.title);
    copyBtn.onclick = function(e) {
        e.stopPropagation();
        copyMessageToClipboard(messageDiv, this);
    };
    const deleteBtn = footer.querySelector('.message-delete-turn-btn');
    if (deleteBtn) {
        footer.insertBefore(copyBtn, deleteBtn);
    } else {
        footer.appendChild(copyBtn);
    }
    return copyBtn;
}
window.appendMessageCopyButton = appendMessageCopyButton;
window.ensureMessageMetaFooter = ensureMessageMetaFooter;

// Add message (when options.systemReadyMessage is true, switching language refreshes this text)
function addMessage(role, content, mcpExecutionIds = null, progressId = null, createdAt = null, options = null) {
    const messagesDiv = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');
    messageCounter++;
    const id = 'msg-' + Date.now() + '-' + messageCounter + '-' + Math.random().toString(36).substr(2, 9);
    messageDiv.id = id;
    messageDiv.className = 'message ' + role;

    messagesDiv.querySelector('.chat-welcome-empty-state')?.remove();

    // Create message content container
    const contentWrapper = document.createElement('div');
    contentWrapper.className = 'message-content';

    // Create message bubble
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';

    // Parse Markdown or HTML format
    let formattedContent;
    const escapeHtml = (text) => {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    // Internationalize known error prefixes in assistant messages
    let displayContent = content;
    if (role === 'assistant' && typeof displayContent === 'string' && typeof window.t === 'function') {
        if (displayContent.indexOf('Execution failed: ') === 0) {
            displayContent = window.t('chat.executeFailed') + ': ' + displayContent.slice('Execution failed: '.length);
        }
        if (displayContent.indexOf('OpenAI call failed:') !== -1) {
            displayContent = displayContent.replace(/OpenAI call failed:/g, window.t('chat.callOpenAIFailed') + ':');
        }
    }

    // For user messages, escape HTML directly without Markdown parsing, to preserve all special characters
    if (role === 'user') {
        formattedContent = escapeHtml(content).replace(/\n/g, '<br>');
    } else if (typeof window.csMarkdownSanitize !== 'undefined') {
        formattedContent = window.csMarkdownSanitize.formatMarkdownToHtml(
            role === 'assistant' ? displayContent : content,
            { profile: 'chat' }
        );
    } else {
        const rawForEscape = role === 'assistant' ? displayContent : content;
        formattedContent = escapeHtml(rawForEscape).replace(/\n/g, '<br>');
    }

    bubble.innerHTML = formattedContent;

    // When refresh restores a running conversation, the backend body may still be the persisted placeholder value "Processing...".
    // Keep the message node so iteration details and the final reply can reuse it, but do not show the placeholder value as the assistant body.
    if (role === 'assistant' && options && options.hideAssistantPlaceholder) {
        messageDiv.classList.add('assistant-placeholder-content');
        bubble.hidden = true;
    }

    if (typeof window.csMarkdownSanitize !== 'undefined') {
        window.csMarkdownSanitize.stripSuspiciousImages(bubble);
    }

    // Add an independent scroll container for each table
    wrapTablesInBubble(bubble);

    contentWrapper.appendChild(bubble);

    // Save the original content to the message element, for the copy feature
    if (role === 'assistant' || role === 'user') {
        messageDiv.dataset.originalContent = content;
    }

    // Add timestamp
    const timeDiv = document.createElement('div');
    timeDiv.className = 'message-time';
    // Use the passed creation time if available; otherwise use the current time
    let messageTime;
    if (createdAt) {
        // Handle string or Date objects
        if (typeof createdAt === 'string') {
            messageTime = new Date(createdAt);
        } else if (createdAt instanceof Date) {
            messageTime = createdAt;
        } else {
            messageTime = new Date(createdAt);
        }
        // If parsing fails, use the current time
        if (isNaN(messageTime.getTime())) {
            messageTime = new Date();
        }
    } else {
        messageTime = new Date();
    }
    const msgTimeLocale = (typeof window.uiLocale === 'function' ? window.uiLocale() : 'en-US');
    const msgTimeOpts = { hour: '2-digit', minute: '2-digit' };
    if (msgTimeLocale === 'zh-CN' || msgTimeLocale === 'ru-RU') msgTimeOpts.hour12 = false;
    timeDiv.textContent = messageTime.toLocaleTimeString(msgTimeLocale, msgTimeOpts);
    try {
        timeDiv.dataset.messageTime = messageTime.toISOString();
    } catch (e) { /* ignore */ }
    const metaFooter = document.createElement('div');
    metaFooter.className = 'message-meta-footer';
    metaFooter.appendChild(timeDiv);
    contentWrapper.appendChild(metaFooter);
    messageDiv.appendChild(contentWrapper);

    // Add a copy button for user and assistant messages (copies the entire message content)
    if (role === 'assistant' || role === 'user') {
        appendMessageCopyButton(messageDiv);
    }

    // Show the call button when there is an MCP execution record and the message is not a streaming placeholder; streaming placeholders with progressId do not get it (consistent with the progress card; created by integrate when finished)
    if (role === 'assistant' && (mcpExecutionIds && Array.isArray(mcpExecutionIds) && mcpExecutionIds.length > 0) && !progressId) {
        if (options && options.deferMcpButtons) {
            try {
                const ids = cacheMcpExecutionIds(messageDiv, mcpExecutionIds);
                messageDiv.dataset.pendingMcpExecutionIds = JSON.stringify(ids);
            } catch (e) { /* ignore */ }
        } else {
            setMcpCallExecutionIds(messageDiv, mcpExecutionIds);
        }
    }

    // Mark the "system ready" placeholder message so its text can be refreshed after a language switch
    if (options && options.systemReadyMessage) {
        messageDiv.setAttribute('data-system-ready-message', '1');
    }
    messagesDiv.appendChild(messageDiv);
    if (window.VeritySecChatScroll) {
        window.VeritySecChatScroll.applyMessageScroll(options);
    } else {
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
    return id;
}

// Copy message content to clipboard (uses the original Markdown format)
function copyMessageToClipboard(messageDiv, button) {
    try {
        // Get the saved original Markdown content
        const originalContent = messageDiv.dataset.originalContent;

        // Unified copy handler
        const doCopy = (text) => {
            // Prefer the modern Clipboard API (requires HTTPS or localhost)
            if (navigator.clipboard && navigator.clipboard.writeText) {
                return navigator.clipboard.writeText(text).then(() => {
                    showCopySuccess(button);
                }).catch(err => {
                    console.error('Clipboard API copy failed:', err);
                    fallbackCopy(text);
                });
            } else {
                // Fallback: use the legacy execCommand method (for HTTP environments)
                return fallbackCopy(text);
            }
        };

        // Fallback copy function (uses document.execCommand)
        const fallbackCopy = (text) => {
            try {
                const textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.style.position = 'fixed';
                textArea.style.left = '-999999px';
                textArea.style.top = '-999999px';
                textArea.style.opacity = '0';
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();

                const successful = document.execCommand('copy');
                document.body.removeChild(textArea);

                if (successful) {
                    showCopySuccess(button);
                } else {
                    throw new Error('execCommand copy failed');
                }
            } catch (execErr) {
                console.error('Fallback copy failed:', execErr);
                alert(typeof window.t === 'function' ? window.t('chat.copyFailedManual') : 'Copy failed; please select the content and copy it manually');
            }
        };

        if (!originalContent) {
            // If no original content was saved, try extracting from the rendered HTML (fallback)
            const bubble = messageDiv.querySelector('.message-bubble');
            if (bubble) {
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = bubble.innerHTML;

                // Remove the copy button itself (to avoid copying its text)
                const copyBtnInTemp = tempDiv.querySelector('.message-copy-btn');
                if (copyBtnInTemp) {
                    copyBtnInTemp.remove();
                }

                // Extract plain text content
                let textContent = tempDiv.textContent || tempDiv.innerText || '';
                textContent = textContent.replace(/\n{3,}/g, '\n\n').trim();

                doCopy(textContent);
            }
            return;
        }

        // Use the original Markdown content
        doCopy(originalContent);
    } catch (error) {
        console.error('Error copying message:', error);
        alert(typeof window.t === 'function' ? window.t('chat.copyFailedManual') : 'Copy failed; please select the content and copy it manually');
    }
}

// Show copy success hint
function showCopySuccess(button) {
    if (button) {
        const originalText = button.innerHTML;
        button.dataset.copySuccessActive = '1';
        button.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 6L9 17l-5-5" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg><span>' + (typeof window.t === 'function' ? window.t('common.copied') : 'Copied') + '</span>';
        button.style.color = '#10b981';
        button.style.background = 'rgba(16, 185, 129, 0.1)';
        button.style.borderColor = 'rgba(16, 185, 129, 0.3)';
        setTimeout(() => {
            delete button.dataset.copySuccessActive;
            button.innerHTML = originalText;
            button.style.color = '';
            button.style.background = '';
            button.style.borderColor = '';
        }, 2000);
    }
}

/** Claude extended thinking internal suffix (consistent with backend DisplayReasoningContent; not shown in the UI) */
const CLAUDE_REASONING_UI_SUFFIX = '\n---CSAI_CLAUDE_THINKING_BLOCKS---\n';

function normalizeReasoningContentForDisplay(text) {
    if (text == null) return '';
    let s = String(text).trim();
    if (!s) return '';
    const idx = s.lastIndexOf(CLAUDE_REASONING_UI_SUFFIX);
    if (idx >= 0) {
        s = s.slice(0, idx).trim();
    }
    return s;
}

function setMessageReasoningContent(messageIdOrEl, reasoningContent) {
    const el = typeof messageIdOrEl === 'string' ? document.getElementById(messageIdOrEl) : messageIdOrEl;
    if (!el || !el.dataset) return;
    const rc = normalizeReasoningContentForDisplay(reasoningContent);
    if (rc) {
        el.dataset.reasoningContent = rc;
    } else {
        delete el.dataset.reasoningContent;
    }
}

function getMessageReasoningContent(messageIdOrEl) {
    const el = typeof messageIdOrEl === 'string' ? document.getElementById(messageIdOrEl) : messageIdOrEl;
    if (!el || !el.dataset) return '';
    return normalizeReasoningContentForDisplay(el.dataset.reasoningContent || '');
}

function reasoningTextAlreadyInProcessDetails(processDetails, rc) {
    if (!rc) return true;
    const list = Array.isArray(processDetails) ? processDetails : [];
    for (let i = 0; i < list.length; i++) {
        const d = list[i];
        if (!d) continue;
        const et = d.eventType || '';
        if (et !== 'reasoning_chain' && et !== 'thinking') continue;
        const msg = normalizeReasoningContentForDisplay(d.message || '');
        if (!msg) continue;
        if (msg === rc || msg.includes(rc) || rc.includes(msg)) {
            return true;
        }
    }
    return false;
}

/** Merge messages.reasoningContent and reasoning_chain from process_details; read and display both (after de-duplication) */
function mergeMessageReasoningContentIntoProcessDetails(processDetails, reasoningContent) {
    const rc = normalizeReasoningContentForDisplay(reasoningContent);
    const details = Array.isArray(processDetails) ? processDetails.slice() : [];
    if (!rc || reasoningTextAlreadyInProcessDetails(details, rc)) {
        return details;
    }
    details.push({
        eventType: 'reasoning_chain',
        message: rc,
        data: { source: 'message.reasoningContent' }
    });
    return details;
}

async function syncAssistantReasoningContentFromServer(backendMessageId, domAssistantId) {
    if (!backendMessageId || !domAssistantId || !currentConversationId || typeof apiFetch !== 'function') {
        return;
    }
    try {
        const convRes = await apiFetch(`/api/conversations/${encodeURIComponent(currentConversationId)}?include_process_details=0`);
        const conv = await convRes.json().catch(() => ({}));
        if (!convRes.ok || !Array.isArray(conv.messages)) return;
        const msg = conv.messages.find((m) => m && String(m.id) === String(backendMessageId));
        if (!msg || !msg.reasoningContent) return;
        setMessageReasoningContent(domAssistantId, msg.reasoningContent);
        // After the final reply arrives, process details must also be fully restored; the no-argument API returns only the first 50 entries by default,
        // otherwise this would overwrite the full timeline restored by task-events with the first page again.
        if (typeof window.loadProcessDetailsPaginated === 'function') {
            await window.loadProcessDetailsPaginated(domAssistantId, String(backendMessageId));
        } else {
            const pdRes = await apiFetch(
                `/api/messages/${encodeURIComponent(String(backendMessageId))}/process-details?full=1`
            );
            const pdJson = await pdRes.json().catch(() => ({}));
            const details = pdRes.ok && Array.isArray(pdJson.processDetails) ? pdJson.processDetails : [];
            if (typeof renderProcessDetails === 'function') {
                renderProcessDetails(domAssistantId, details);
            }
        }
    } catch (e) {
        console.warn('syncAssistantReasoningContentFromServer failed', e);
    }
}

window.normalizeReasoningContentForDisplay = normalizeReasoningContentForDisplay;
window.setMessageReasoningContent = setMessageReasoningContent;
window.getMessageReasoningContent = getMessageReasoningContent;
window.filterNoiseProcessDetails = filterNoiseProcessDetails;
window.mergeMessageReasoningContentIntoProcessDetails = mergeMessageReasoningContentIntoProcessDetails;
window.syncAssistantReasoningContentFromServer = syncAssistantReasoningContentFromServer;

/** Keep only one of adjacent process-detail entries with identical type, body and data (consistent with backend de-duplication, avoiding duplicate blocks in the timeline) */
function isEinoAgentHeartbeatProgress(detail) {
    if (!detail || detail.eventType !== 'progress') return false;
    const msg = String(detail.message != null ? detail.message : '').trim();
    return /^\[Eino\]\s+\S/.test(msg);
}

function hasModelOutputRecoveryMarker(value) {
    if (!value) return false;
    let obj = value;
    if (typeof obj === 'string') {
        const text = obj.trim();
        if (!text || text.indexOf('_veritysec_model_output_recovery') === -1) return false;
        try {
            obj = JSON.parse(text);
        } catch (e) {
            return false;
        }
    }
    return !!(obj && typeof obj === 'object' && obj._veritysec_model_output_recovery);
}

function isModelOutputRecoveryToolCallDetail(detail) {
    if (!detail || detail.eventType !== 'tool_call') return false;
    const data = detail.data && typeof detail.data === 'object' ? detail.data : {};
    return hasModelOutputRecoveryMarker(data.argumentsObj) || hasModelOutputRecoveryMarker(data.arguments);
}

function isAnonymousTaskFragmentToolCallDetail(detail) {
    if (!detail || detail.eventType !== 'tool_call') return false;
    const data = detail.data && typeof detail.data === 'object' ? detail.data : {};
    const toolName = String(data.toolName || '').trim().toLowerCase();
    if (toolName && toolName !== 'task' && toolName !== 'unknown') return false;

    let raw = null;
    const argsObj = data.argumentsObj && typeof data.argumentsObj === 'object' ? data.argumentsObj : null;
    if (argsObj) {
        const keys = Object.keys(argsObj);
        if (keys.length === 1 && keys[0] === '_raw') {
            raw = String(argsObj._raw != null ? argsObj._raw : '').trim();
        }
    }
    if (raw == null && typeof data.arguments === 'string') {
        raw = data.arguments.trim();
    }
    if (raw == null) return false;
    if (!raw) return true;
    return !(raw.startsWith('{') && raw.endsWith('}'));
}

function isInternalEinoDiagnosticDetail(detail) {
    if (!detail) return false;
    if (detail.eventType === 'model_output_rejected') return true;
    if (detail.eventType !== 'progress') return false;
    const msg = String(detail.message != null ? detail.message : '').trim();
    if (msg === 'Eino TurnLoop persistent multi-turn runtime has taken over this conversation turn.' ||
        msg === 'Eino TurnLoop has switched to the next turn after user supplement at a safe point.' ||
        msg === 'User supplement pushed into Eino TurnLoop, waiting for safe-point switch...') {
        return true;
    }
    const data = detail.data && typeof detail.data === 'object' ? detail.data : {};
    const kind = String(data.kind || '').trim();
    return kind === 'turn_loop_takeover' || kind === 'turn_loop_preempted';
}

function filterNoiseProcessDetails(details) {
    if (!Array.isArray(details)) return details;
    return details.filter(function (d) {
        if (isEinoAgentHeartbeatProgress(d)) return false;
        if (isModelOutputRecoveryToolCallDetail(d)) return false;
        if (isAnonymousTaskFragmentToolCallDetail(d)) return false;
        if (isInternalEinoDiagnosticDetail(d)) return false;
        return !(d && d.eventType === 'tool_calls_detected');
    });
}

function dedupeConsecutiveProcessDetailRows(details) {
    if (!Array.isArray(details) || details.length < 2) {
        return details;
    }
    const out = [details[0]];
    for (let i = 1; i < details.length; i++) {
        const cur = details[i];
        if (processDetailRowFingerprint(out[out.length - 1]) === processDetailRowFingerprint(cur)) {
            continue;
        }
        out.push(cur);
    }
    return out;
}

function processDetailRowFingerprint(d) {
    if (!d || typeof d !== 'object') {
        return '';
    }
    const et = String(d.eventType || '');
    const msg = String(d.message != null ? d.message : '').trim();
    let dataKey = '';
    try {
        if (d.data != null) {
            dataKey = JSON.stringify(d.data);
        }
    } catch (e) {
        dataKey = String(d.data);
    }
    return et + '\0' + msg + '\0' + dataKey;
}

function compactWorkflowProcessDetails(details) {
    if (!Array.isArray(details) || details.length === 0) return details || [];
    return details.filter((detail) => {
        const eventType = detail && detail.eventType ? String(detail.eventType) : '';
        // workflow_node_start already represents node entry; these events are only for live status, and adding them to details would make Agent nodes look like they started twice.
        return eventType !== 'workflow_agent_start';
    });
}

function isProcessDetailsUserExpanded(messageId) {
    const container = document.getElementById('process-details-' + messageId);
    return !!(container && container.dataset && container.dataset.userExpanded === '1');
}

function messageHasConversationContent(messageElement) {
    if (!messageElement || !messageElement.classList || !messageElement.classList.contains('assistant')) return false;
    if (messageElement.hasAttribute('data-system-ready-message')) return false;
    if (messageElement.dataset && String(messageElement.dataset.backendMessageId || '').trim()) return true;
    const raw = messageElement.dataset ? String(messageElement.dataset.originalContent || '').trim() : '';
    if (raw) return true;
    const bubble = messageElement.querySelector('.message-bubble');
    if (!bubble) return false;
    const clone = bubble.cloneNode(true);
    clone.querySelectorAll('.message-copy-btn').forEach((btn) => btn.remove());
    return String(clone.textContent || '').trim().length > 0;
}

function syncProcessDetailButtonLabels(messageId, expanded) {
    const expandT = typeof window.t === 'function' ? window.t('chat.expandDetail') : 'Expand details';
    const collapseT = typeof window.t === 'function' ? window.t('tasks.collapseDetail') : 'Collapse details';
    const label = expanded ? collapseT : expandT;
    document.querySelectorAll('#' + messageId + ' .process-detail-btn').forEach((btn) => {
        btn.innerHTML = '<span>' + label + '</span>';
    });
    if (typeof window.syncAssistantTurnSummary === 'function') {
        window.syncAssistantTurnSummary(document.getElementById(messageId));
    }
}

/** The lazy-load placeholder hint is clickable, consistent with the toolbar "Expand details" behavior */
function bindProcessDetailsLazyHint(hostEl, messageId) {
    if (!hostEl || !messageId) return;
    const emptyEl = hostEl.classList && hostEl.classList.contains('progress-timeline-empty')
        ? hostEl
        : hostEl.querySelector('.progress-timeline-empty');
    if (!emptyEl || emptyEl.dataset.lazyHintBound === '1') return;
    emptyEl.dataset.lazyHintBound = '1';
    emptyEl.classList.add('progress-timeline-lazy-clickable');
    emptyEl.setAttribute('role', 'button');
    emptyEl.setAttribute('tabindex', '0');
    const activate = () => {
        if (typeof toggleProcessDetails === 'function') {
            toggleProcessDetails(null, messageId);
        }
    };
    emptyEl.addEventListener('click', activate);
    emptyEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            activate();
        }
    });
}
window.bindProcessDetailsLazyHint = bindProcessDetailsLazyHint;

// Render process details
// When options.append=true, append by page; when options.markLoaded=false, keep the lazy marker (page loading in progress)
function renderProcessDetails(messageId, processDetails, options) {
    const renderOpts = options || {};
    const appendMode = !!renderOpts.append;
    const prependMode = !!renderOpts.prepend;
    const markLoaded = renderOpts.markLoaded !== false;
    const toolStatusByProcessDetailId = new Map();
    if (Array.isArray(renderOpts.toolExecutions)) {
        renderOpts.toolExecutions.forEach((execution) => {
            if (!execution || !execution.processDetailId) return;
            toolStatusByProcessDetailId.set(String(execution.processDetailId), String(execution.status || '').toLowerCase());
        });
    }
    const messageElement = document.getElementById(messageId);
    if (!messageElement) {
        return;
    }
    const isLazyRequest = (processDetails === null);
    const reasoningFromMessage = getMessageReasoningContent(messageElement);
    const backendId = messageElement.dataset ? String(messageElement.dataset.backendMessageId || '').trim() : '';
    const hasConversationContent = !!renderOpts.force || messageHasConversationContent(messageElement);
    if (isLazyRequest && !reasoningFromMessage && !backendId && getMcpExecutionCount(messageElement) <= 0 && !hasConversationContent) {
        pruneEmptyMcpCallSection(messageElement);
        return;
    }

    // Find or create the MCP area (toolbar + tool list + iteration timeline sections)
    const chrome = ensureMcpCallSectionChrome(messageElement, messageId);
    if (!chrome) return;
    const { mcpSection, toolbar: buttonsContainer } = chrome;

    // Add process details button (if not already present)
    let processDetailBtn = buttonsContainer.querySelector('.process-detail-btn');
    if (!processDetailBtn) {
        processDetailBtn = document.createElement('button');
        processDetailBtn.className = 'mcp-detail-btn process-detail-btn';
        processDetailBtn.innerHTML = '<span>' + (typeof window.t === 'function' ? window.t('chat.expandDetail') : 'Expand details') + '</span>';
        processDetailBtn.onclick = () => toggleProcessDetails(null, messageId);
        buttonsContainer.appendChild(processDetailBtn);
    }
    if (backendId && typeof openRunWorkspace === 'function' && !buttonsContainer.querySelector('.run-workspace-btn')) {
        const rwBtn = document.createElement('button');
        rwBtn.type = 'button';
        rwBtn.className = 'mcp-detail-btn run-workspace-btn';
        rwBtn.innerHTML = '<span>Run workspace</span>';
        rwBtn.onclick = () => openRunWorkspace(backendId);
        buttonsContainer.appendChild(rwBtn);
    }
    syncMcpToolsToggleButton(messageElement);

    // Create process details container (placed after the tool list)
    const detailsId = 'process-details-' + messageId;
    let detailsContainer = document.getElementById(detailsId);
    const toolListEl = chrome.toolList;

    if (!detailsContainer) {
        detailsContainer = document.createElement('div');
        detailsContainer.id = detailsId;
        detailsContainer.className = 'process-details-container';
        if (toolListEl) {
            toolListEl.after(detailsContainer);
        } else if (buttonsContainer.nextSibling) {
            mcpSection.insertBefore(detailsContainer, buttonsContainer.nextSibling);
        } else {
            mcpSection.appendChild(detailsContainer);
        }
    }

    // Create timeline (even without processDetails, so the expand-details button works)
    const timelineId = detailsId + '-timeline';
    let timeline = document.getElementById(timelineId);

    if (!timeline) {
        const contentDiv = document.createElement('div');
        contentDiv.className = 'process-details-content';

        timeline = document.createElement('div');
        timeline.id = timelineId;
        timeline.className = 'progress-timeline';

        contentDiv.appendChild(timeline);
        detailsContainer.appendChild(contentDiv);
    }
    if (typeof window.ensureProcessDetailsReturnLatestControl === 'function') {
        window.ensureProcessDetailsReturnLatestControl(timeline);
    }

    // processDetails === null means "not loaded yet (lazy)"; messages.reasoningContent can be shown first
    const isLazyNotLoaded = isLazyRequest;
    if (isLazyNotLoaded && !reasoningFromMessage) {
        detailsContainer.dataset.lazyNotLoaded = '1';
        detailsContainer.dataset.loaded = '0';
        const expandLabel = typeof window.t === 'function' ? window.t('chat.expandDetail') : 'Expand details';
        let lazyHint = expandLabel + ' (click to load iteration details)';
        timeline.innerHTML = '<div class="progress-timeline-empty">' + lazyHint + '</div>';
        bindProcessDetailsLazyHint(timeline, messageId);
        timeline.classList.remove('expanded');
        if (typeof window.updateProcessDetailsReturnLatestControl === 'function') {
            window.updateProcessDetailsReturnLatestControl(timeline);
        }
        prefetchProcessDetailsSummaryHint(messageId, messageElement);
        return;
    }
    if (isLazyNotLoaded) {
        detailsContainer.dataset.lazyNotLoaded = '1';
        detailsContainer.dataset.loaded = '0';
        processDetails = [];
        if (!appendMode) {
            prefetchProcessDetailsSummaryHint(messageId, messageElement);
        }
    } else if (markLoaded) {
        detailsContainer.dataset.lazyNotLoaded = '0';
        detailsContainer.dataset.loaded = '1';
    }
    const turnUsageFromDetails = extractAssistantTurnTokenUsage(processDetails);
    if (turnUsageFromDetails) {
        setAssistantTurnTokenUsage(messageElement, turnUsageFromDetails);
    }
    processDetails = mergeMessageReasoningContentIntoProcessDetails(processDetails, reasoningFromMessage);
    processDetails = filterNoiseProcessDetails(processDetails);
    processDetails = dedupeConsecutiveProcessDetailRows(processDetails);
    const renderedMcpIds = collectMcpExecutionIdsFromProcessDetails(processDetails);
    if (renderedMcpIds.length > 0) {
        setPendingMcpExecutionIds(messageElement, renderedMcpIds);
        setMcpExecutionSummaryCount(messageElement, renderedMcpIds.length);
    }
    if (typeof window.coalesceProcessDetailsToolPairs === 'function') {
        processDetails = window.coalesceProcessDetailsToolPairs(processDetails);
    }
    processDetails = compactWorkflowProcessDetails(processDetails);
    // If there are no processDetails or they are empty, show the empty state
    if (!processDetails || processDetails.length === 0) {
        if (!appendMode && !prependMode) {
            timeline.innerHTML = '<div class="progress-timeline-empty">' + (typeof window.t === 'function' ? window.t('chat.noProcessDetail') : 'No process details (execution may have been too fast or no detailed events were triggered)') + '</div>';
            if (!isProcessDetailsUserExpanded(messageId)) {
                timeline.classList.remove('expanded');
            }
            if (typeof window.updateProcessDetailsReturnLatestControl === 'function') {
                window.updateProcessDetailsReturnLatestControl(timeline);
            }
        }
        return;
    }

    const prependAnchor = prependMode ? timeline.firstChild : null;
    const prependScrollBox = prependMode ? document.getElementById('chat-messages') : null;
    const prependScrollHeight = prependScrollBox ? prependScrollBox.scrollHeight : 0;
    const prependScrollTop = prependScrollBox ? prependScrollBox.scrollTop : 0;
    const prependedIds = [];

    if (!appendMode && !prependMode) {
        timeline.innerHTML = '';
    }


    function processDetailAgentPrefix(d) {
        if (!d || d.einoAgent == null) return '';
        const s = String(d.einoAgent).trim();
        return s ? ('[' + s + '] ') : '';
    }

    function formatProcessDetailEinoRunRetryKind(kind) {
        if (typeof window.formatEinoRunRetryKind === 'function') {
            return window.formatEinoRunRetryKind(kind);
        }
        const key = String(kind || '').trim();
        if (!key) return '';
        const labels = {
            rate_limit: 'Rate limited / too many requests',
            retryable_http: 'Retryable HTTP error',
            upstream_server: 'Upstream service error',
            http_error: 'HTTP error',
            upstream_busy: 'Upstream busy',
            network: 'Network connection error',
            stream: 'Stream read error',
            transient: 'Transient error'
        };
        if (typeof window.t === 'function') {
            const translated = window.t('chat.einoRunRetryKind_' + key);
            if (translated && translated !== 'chat.einoRunRetryKind_' + key) return translated;
        }
        return labels[key] || key;
    }

    function formatProcessDetailEinoRunRetryTitle(data) {
        if (typeof window.formatEinoRunRetryTitle === 'function') {
            return window.formatEinoRunRetryTitle(data);
        }
        const d = data && typeof data === 'object' ? data : {};
        const base = typeof window.t === 'function'
            ? window.t('chat.einoRunRetryTitle')
            : '🔁 Retrying after transient error';
        const attempt = Number(d.attempt || 0);
        const maxAttempts = Number(d.maxAttempts || 0);
        if (Number.isFinite(attempt) && attempt > 0 && Number.isFinite(maxAttempts) && maxAttempts > 0) {
            return base + '（' + attempt + '/' + maxAttempts + '）';
        }
        return base;
    }

    function formatProcessDetailEinoRunRetryMessage(message, data) {
        if (typeof window.formatEinoRunRetryMessage === 'function') {
            return window.formatEinoRunRetryMessage(message, data);
        }
        const d = data && typeof data === 'object' ? data : {};
        const base = String(message || '').trim();
        const errRaw = d.errorSummary != null && String(d.errorSummary).trim() !== ''
            ? String(d.errorSummary).trim()
            : (d.error != null ? String(d.error).trim() : '');
        const lines = [];
        if (base) lines.push(base);
        const attempt = Number(d.attempt || 0);
        const maxAttempts = Number(d.maxAttempts || 0);
        const backoffSec = Number(d.backoffSec || 0);
        const kind = formatProcessDetailEinoRunRetryKind(d.errorKind);
        if (Number.isFinite(attempt) && attempt > 0 && Number.isFinite(maxAttempts) && maxAttempts > 0) {
            const retryPlan = typeof window.t === 'function'
                ? window.t('chat.einoRunRetryPlan', { attempt: attempt, maxAttempts: maxAttempts, backoffSec: Number.isFinite(backoffSec) && backoffSec > 0 ? backoffSec : '-' })
                : ('Retry progress: attempt ' + attempt + '/' + maxAttempts + ', waiting ' + (Number.isFinite(backoffSec) && backoffSec > 0 ? backoffSec : '-') + ' s');
            if (!base || base.indexOf(String(attempt) + '/' + String(maxAttempts)) === -1) {
                lines.push(retryPlan);
            }
        }
        if (kind) {
            const kindLabel = typeof window.t === 'function'
                ? window.t('chat.einoRunRetryReasonKind')
                : 'Reason type';
            lines.push(kindLabel + '：' + kind);
        }
        if (errRaw && (!base || base.indexOf(errRaw) === -1)) {
            const detailLabel = typeof window.t === 'function'
                ? window.t('chat.einoRunRetryErrorDetail')
                : 'Error details';
            lines.push(detailLabel + '：' + errRaw);
        }
        return lines.join('\n');
    }

    function renderOneProcessDetail(detail) {
        const eventType = detail.eventType || '';
        const title = detail.message || '';
        const data = detail.data || {};
        const agPx = processDetailAgentPrefix(data);

        let itemTitle = title;
        if (eventType === 'workflow_start') {
            const name = data.workflowName || data.workflowId || '';
            itemTitle = '🧭 Workflow started' + (name ? (' · ' + name) : '');
        } else if (eventType === 'workflow_done') {
            const name = data.workflowName || data.workflowId || '';
            itemTitle = '✅ Workflow completed' + (name ? (' · ' + name) : '');
        } else if (eventType === 'workflow_node_start') {
            const label = data.label || title || data.nodeId || '';
            itemTitle = '▶ Node started' + (label ? (' · ' + label) : '');
        } else if (eventType === 'workflow_node_result') {
            const label = data.label || data.nodeId || '';
            const status = data.status || '';
            const nodeType = data.nodeType != null ? String(data.nodeType).toLowerCase() : '';
            if (nodeType === 'condition') {
                const matched = data.matched === true || data.matched === 'true' || (data.output && (data.output.matched === true || data.output.matched === 'true'));
                itemTitle = (matched ? '✅' : '🔀') + ' Condition' + (label ? (' · ' + label) : '') + ' → ' + (matched ? 'yes' : 'no');
            } else {
                const icon = status === 'failed' ? '❌' : (status === 'skipped' ? '⏭️' : '✅');
                itemTitle = icon + ' Node completed' + (label ? (' · ' + label) : '') + (status ? (' (' + status + ')') : '');
            }
        } else if (eventType === 'workflow_branch_taken' || eventType === 'workflow_branch_skipped') {
            const branch = data.branchLabel || '';
            const target = data.targetLabel || data.targetId || '';
            const taken = eventType === 'workflow_branch_taken';
            itemTitle = (taken ? '➡️' : '⏭️') + (taken ? ' Run branch' : ' Skip branch') + (branch ? (' · ' + branch) : '') + (target ? (' → ' + target) : '');
        } else if (eventType === 'workflow_tool_start') {
            const tool = data.tool || data.toolName || '';
            itemTitle = '🔧 Tool node' + (tool ? (' · ' + tool) : '');
        } else if (eventType === 'workflow_agent_output') {
            const label = data.label || data.nodeId || '';
            itemTitle = '🤖 Agent output' + (label ? (' · ' + label) : '');
        } else if (eventType === 'workflow_hitl_checkpoint') {
            itemTitle = '🧑‍⚖️ Human confirmation checkpoint';
        } else if (eventType === 'workflow_hitl_waiting') {
            itemTitle = '🧑‍⚖️ Workflow awaiting approval';
        } else if (eventType === 'workflow_paused') {
            itemTitle = '⏸️ Workflow paused';
        } else if (eventType === 'iteration') {
            const n = data.iteration || 1;
            if (data.orchestration === 'plan_execute' && data.einoScope === 'main') {
                const phase = typeof window.translatePlanExecuteAgentName === 'function'
                    ? window.translatePlanExecuteAgentName(data.einoAgent) : (data.einoAgent || '');
                itemTitle = (typeof window.t === 'function'
                    ? window.t('chat.einoPlanExecuteRound', { n: n, phase: phase })
                    : ('Plan-Execute · round ' + n + ' · ' + phase));
            } else if (data.einoScope === 'main') {
                itemTitle = agPx + (typeof window.t === 'function'
                    ? window.t('chat.einoOrchestratorRound', { n: n })
                    : ('Main agent · round ' + n));
            } else if (data.einoScope === 'sub') {
                const agent = data.einoAgent != null ? String(data.einoAgent).trim() : '';
                itemTitle = agPx + (typeof window.t === 'function'
                    ? window.t('chat.einoSubAgentStep', { n: n, agent: agent })
                    : ('Sub-agent · ' + agent + ' · step ' + n));
            } else {
                itemTitle = agPx + (typeof window.t === 'function' ? window.t('chat.iterationRound', { n: n }) : 'Iteration ' + n);
            }
        } else if (eventType === 'thinking') {
            itemTitle = agPx + '🤔 ' + (typeof window.t === 'function' ? window.t('chat.aiThinking') : 'AI thinking');
        } else if (eventType === 'reasoning_chain') {
            itemTitle = agPx + '🔗 ' + (typeof window.t === 'function' ? window.t('chat.reasoningChain') : 'Reasoning');
        } else if (eventType === 'planning') {
            if (typeof window.einoMainStreamPlanningTitle === 'function') {
                itemTitle = window.einoMainStreamPlanningTitle(data);
            } else {
                itemTitle = agPx + '📝 ' + (typeof window.t === 'function' ? window.t('chat.planning') : 'Planning');
            }
        } else if (eventType === 'tool_calls_detected') {
            itemTitle = agPx + '🔧 ' + (typeof window.t === 'function' ? window.t('chat.toolCallsDetected', { count: data.count || 0 }) : 'Detected ' + (data.count || 0) + ' tool calls');
        } else if (eventType === 'tool_call') {
            const toolName = data.toolName || (typeof window.t === 'function' ? window.t('chat.unknownTool') : 'Unknown tool');
            const index = data.index || 0;
            const total = data.total || 0;
            const callTitle = typeof window.formatToolCallTimelineTitle === 'function'
                ? window.formatToolCallTimelineTitle(toolName, index, total)
                : (typeof window.t === 'function' ? window.t('chat.callTool', { name: escapeHtml(toolName), index: index, total: total }) : 'Calling tool: ' + escapeHtml(toolName) + ' (' + index + '/' + total + ')');
            itemTitle = agPx + '🔧 ' + callTitle;
        } else if (eventType === 'tool_result') {
            const toolName = data.toolName || (typeof window.t === 'function' ? window.t('chat.unknownTool') : 'Unknown tool');
            const noResultText = typeof window.t === 'function' ? window.t('timeline.noResult') : 'No result';
            const result = data.result != null ? data.result : (data.error != null ? data.error : (data.resultPreview != null ? data.resultPreview : noResultText));
            const resultStr = typeof result === 'string' ? result : JSON.stringify(result);
            const displayState = typeof window.getToolResultDisplayState === 'function'
                ? window.getToolResultDisplayState(data, { rawText: resultStr })
                : { kind: (data.success !== false ? 'success' : 'error'), isError: data.success === false };
            const backgroundRunning = displayState.kind === 'background_running';
            const success = !displayState.isError && !backgroundRunning;
            const statusIcon = displayState.kind === 'blocked' ? '🛡' : (backgroundRunning ? '⏳' : (success ? '✅' : '❌'));
            const execText = displayState.kind === 'blocked'
                ? (typeof window.t === 'function' ? window.t('chat.toolExecBlocked', { name: escapeHtml(toolName) }) : 'Tool ' + escapeHtml(toolName) + ' blocked')
                : backgroundRunning
                ? ((typeof window.getBackgroundRunningToolLabel === 'function' ? window.getBackgroundRunningToolLabel() : 'Running in background') + ': ' + escapeHtml(toolName))
                : (success ? (typeof window.t === 'function' ? window.t('chat.toolExecComplete', { name: escapeHtml(toolName) }) : 'Tool ' + escapeHtml(toolName) + ' completed') : (typeof window.t === 'function' ? window.t('chat.toolExecFailed', { name: escapeHtml(toolName) }) : 'Tool ' + escapeHtml(toolName) + ' failed'));
            let execLine = statusIcon + ' ' + execText;
            if (toolName === BuiltinTools.SEARCH_KNOWLEDGE_BASE && success) {
                execLine = '📚 ' + execLine + ' - ' + (typeof window.t === 'function' ? window.t('chat.knowledgeRetrievalTag') : 'Knowledge retrieval');
            }
            itemTitle = agPx + execLine;
        } else if (eventType === 'eino_agent_reply') {
            itemTitle = agPx + '💬 ' + (typeof window.t === 'function' ? window.t('chat.einoAgentReplyTitle') : 'Sub-agent reply');
        } else if (eventType === 'eino_empty_response_continue') {
            itemTitle = typeof window.t === 'function'
                ? window.t('chat.einoEmptyResponseContinueTitle')
                : '🔁 Auto-continue (no assistant text)';
        } else if (eventType === 'eino_run_retry') {
            itemTitle = formatProcessDetailEinoRunRetryTitle(data);
            detail.message = formatProcessDetailEinoRunRetryMessage(title, data);
        } else if (eventType === 'knowledge_retrieval') {
            itemTitle = '📚 ' + (typeof window.t === 'function' ? window.t('chat.knowledgeRetrieval') : 'Knowledge retrieval');
        } else if (eventType === 'error') {
            itemTitle = '❌ ' + (typeof window.t === 'function' ? window.t('chat.error') : 'Error');
        } else if (eventType === 'cancelled') {
            itemTitle = '⛔ ' + (typeof window.t === 'function' ? window.t('chat.taskCancelled') : 'Task cancelled');
        } else if (eventType === 'hitl_interrupt') {
            const hitlMsg = (detail.message && String(detail.message).trim()) ? String(detail.message).trim() : (typeof window.t === 'function' ? window.t('hitl.pendingTitle') : 'Pending approval');
            itemTitle = agPx + '🧑‍⚖️ HITL · ' + hitlMsg;
        } else if (eventType === 'hitl_audit_agent_started') {
            itemTitle = agPx + 'Audit agent is reviewing';
        } else if (eventType === 'hitl_audit_agent') {
            itemTitle = agPx + 'Audit agent has finished reviewing';
        } else if (eventType === 'hitl_resumed') {
            itemTitle = agPx + 'Approval granted';
        } else if (eventType === 'hitl_rejected') {
            itemTitle = agPx + 'Approval rejected';
        } else if (eventType === 'progress') {
            itemTitle = typeof window.translateProgressMessage === 'function' ? window.translateProgressMessage(detail.message || '') : (detail.message || '');
        } else if (eventType === 'user_interrupt_continue') {
            itemTitle = typeof window.t === 'function'
                ? window.t('chat.userInterruptContinueTitle')
                : '⏸️ User interrupted and continued';
        }

        if (eventType === 'hitl_interrupt' || eventType === 'hitl_audit_agent_started' ||
            eventType === 'hitl_audit_agent' || eventType === 'hitl_resumed' || eventType === 'hitl_rejected') {
            const hitlTarget = typeof findToolCallItemForHitl === 'function'
                ? findToolCallItemForHitl(timeline, data)
                : null;
            if (hitlTarget && hitlTarget.id) {
                if (eventType === 'hitl_interrupt' || eventType === 'hitl_audit_agent_started') {
                    renderInlineHitlApproval(hitlTarget.id, Object.assign({}, data, {
                        reviewer: eventType === 'hitl_audit_agent_started' ? 'audit_agent' : (data.reviewer || 'human'),
                        status: eventType === 'hitl_audit_agent_started' ? 'audit_running' : (data.status || 'pending')
                    }));
                } else {
                    const decision = eventType === 'hitl_rejected' || data.decision === 'reject' ? 'reject' : 'approve';
                    resolveInlineHitlDecision(timeline, Object.assign({}, data, {
                        reviewer: data.reviewer || data.decidedBy || (eventType === 'hitl_audit_agent' ? 'audit_agent' : 'human'),
                        status: 'decided'
                    }), decision, detail.message || '');
                }
                return;
            }
        }

        const processDetailId = detail.id || data.processDetailId || '';
        const timelineOpts = {
            title: itemTitle,
            message: detail.message || '',
            data: data,
            processDetailId: processDetailId,
            createdAt: detail.createdAt
        };
        if (eventType === 'tool_call' && data._mergedResult) {
            timelineOpts.mergedResult = data._mergedResult;
            if (typeof window.getToolResultDisplayState === 'function') {
                const displayState = window.getToolResultDisplayState(data._mergedResult);
                if (displayState && displayState.kind === 'background_running') {
                    timelineOpts.toolStatus = 'background_running';
                }
            }
        }
        if (eventType === 'tool_call' && detail.id && toolStatusByProcessDetailId.has(String(detail.id))) {
            timelineOpts.toolStatus = toolStatusByProcessDetailId.get(String(detail.id));
        }
        const itemId = addTimelineItem(timeline, eventType, timelineOpts);
        if (itemId && (eventType === 'hitl_interrupt' || eventType === 'hitl_audit_agent_started')) {
            renderInlineHitlApproval(itemId, Object.assign({}, data, {
                reviewer: eventType === 'hitl_audit_agent_started' ? 'audit_agent' : (data.reviewer || 'human'),
                status: eventType === 'hitl_audit_agent_started' ? 'audit_running' : (data.status || 'pending')
            }));
        } else if (itemId && (eventType === 'hitl_audit_agent' || eventType === 'hitl_resumed' || eventType === 'hitl_rejected')) {
            renderInlineHitlApproval(itemId, Object.assign({}, data, {
                resolved: true,
                decision: eventType === 'hitl_rejected' || data.decision === 'reject' ? 'reject' : 'approve',
                reviewer: data.reviewer || data.decidedBy || (eventType === 'hitl_audit_agent' ? 'audit_agent' : 'human'),
                status: 'decided'
            }));
        }
        if (prependMode && itemId) {
            prependedIds.push(itemId);
        }
    }

    function finishPrependRender() {
        if (!prependMode || prependedIds.length === 0) return;
        const fragment = document.createDocumentFragment();
        prependedIds.forEach((id) => {
            const node = document.getElementById(id);
            if (node) fragment.appendChild(node);
        });
        timeline.insertBefore(fragment, prependAnchor || timeline.firstChild);
        if (prependScrollBox) {
            const delta = prependScrollBox.scrollHeight - prependScrollHeight;
            prependScrollBox.scrollTop = prependScrollTop + delta;
        }
    }

    const TIMELINE_RENDER_BATCH = 40;
    const renderTimelineBatch = (startIdx) => {
        const endIdx = Math.min(startIdx + TIMELINE_RENDER_BATCH, processDetails.length);
        for (let i = startIdx; i < endIdx; i++) {
            renderOneProcessDetail(processDetails[i]);
        }
        if (endIdx < processDetails.length) {
            requestAnimationFrame(() => renderTimelineBatch(endIdx));
        } else if (markLoaded) {
            finishPrependRender();
            finishProcessDetailsRender(messageElement, processDetails, isLazyNotLoaded, timeline);
        } else {
            finishPrependRender();
        }
    };
    if (processDetails.length > TIMELINE_RENDER_BATCH) {
        renderTimelineBatch(0);
    } else {
        processDetails.forEach(renderOneProcessDetail);
        finishPrependRender();
        if (markLoaded) {
            finishProcessDetailsRender(messageElement, processDetails, isLazyNotLoaded, timeline);
        }
    }
}

function finishProcessDetailsRender(messageElement, processDetails, isLazyNotLoaded, timeline) {
    if (isLazyNotLoaded && getMessageReasoningContent(messageElement)) {
        const lazyHint = document.createElement('div');
        lazyHint.className = 'progress-timeline-empty progress-timeline-lazy-hint';
        lazyHint.textContent = (typeof window.t === 'function' ? window.t('chat.expandDetail') : 'Expand details') +
            ' (click to load full process details)';
        timeline.appendChild(lazyHint);
        bindProcessDetailsLazyHint(lazyHint, messageElement.id);
    }

    const hasPendingHitlInDetails = processDetails.some(d => d && d.eventType === 'hitl_interrupt');
    const hasPendingWorkflowHitl = processDetails.some(d => d && d.eventType === 'workflow_hitl_waiting');
    const hasErrorOrCancelled = processDetails.some(d =>
        d.eventType === 'error' || d.eventType === 'cancelled'
    );
    const userExpanded = isProcessDetailsUserExpanded(messageElement.id);
    if (userExpanded) {
        timeline.classList.add('expanded');
        syncProcessDetailButtonLabels(messageElement.id, true);
    } else if (hasErrorOrCancelled && !hasPendingHitlInDetails && !hasPendingWorkflowHitl) {
        timeline.classList.remove('expanded');
        syncProcessDetailButtonLabels(messageElement.id, false);
    }
    if (hasPendingWorkflowHitl && messageElement && messageElement.id) {
        const convId = typeof window.currentConversationId === 'string' ? window.currentConversationId : '';
        if (convId && typeof window.restoreWorkflowHitlInlineForConversation === 'function') {
            window.restoreWorkflowHitlInlineForConversation(convId);
        }
    }
    if (typeof window.ensureProcessDetailsReturnLatestControl === 'function') {
        window.ensureProcessDetailsReturnLatestControl(timeline);
    }
    if (typeof window.updateProcessDetailsReturnLatestControl === 'function') {
        window.updateProcessDetailsReturnLatestControl(timeline);
    }
}

/** Lazy-load collapsed state: fetch summary in the background and show the iteration scale without loading full details */
function prefetchProcessDetailsSummaryHint(messageId, messageElement) {
    if (!messageElement || !messageElement.dataset || !messageElement.dataset.backendMessageId) return;
    const backendId = String(messageElement.dataset.backendMessageId).trim();
    if (!backendId || typeof apiFetch !== 'function') return;
    const detailsContainer = document.getElementById('process-details-' + messageId);
    if (!detailsContainer || detailsContainer.dataset.summaryFetched === '1') return;
    detailsContainer.dataset.summaryFetched = '1';
    apiFetch('/api/messages/' + encodeURIComponent(backendId) + '/process-details?summary=1')
        .then(async (res) => {
            const j = await res.json().catch(() => ({}));
            if (!res.ok || !j.summary) return;
            const s = j.summary;
            if (typeof window.setAssistantTurnTiming === 'function') {
                window.setAssistantTurnTiming(messageElement, {
                    startedAt: s.startedAt,
                    completedAt: s.completedAt,
                    durationMs: s.durationMs,
                    status: s.status || 'completed'
                });
            }
            const summaryMcpIds = Array.isArray(s.mcpExecutionIds) ? s.mcpExecutionIds : [];
            const summaryTools = Array.isArray(s.toolExecutions) ? s.toolExecutions : [];
            if (summaryTools.length > 0) {
                setPendingToolExecutionSummaries(messageElement, summaryTools);
            }
            if (summaryMcpIds.length > 0) {
                setPendingMcpExecutionIds(messageElement, summaryMcpIds);
            }
            const summaryToolExecutionCount = summaryTools
                .map(normalizeToolExecutionSummaryForButton)
                .filter((item) => item.executionId)
                .length;
            const buttonToolCount = summaryToolExecutionCount > 0 ? summaryToolExecutionCount : summaryMcpIds.length;
            if (buttonToolCount > 0) {
                setMcpExecutionSummaryCount(messageElement, buttonToolCount);
            }
            const timeline = detailsContainer.querySelector('.progress-timeline');
            if (!timeline || detailsContainer.dataset.loaded === '1') return;
            const expandLabel = typeof window.t === 'function' ? window.t('chat.expandDetail') : 'Expand details';
            let hint = expandLabel + ' (click to load iteration details)';
            if (s.maxIteration > 0) {
                hint = expandLabel + ' (' + s.maxIteration + ' iterations, ' + (s.total || 0) + ' entries)';
            } else if (s.total > 0) {
                hint = expandLabel + ' (' + (s.total || 0) + ' entries)';
            }
            const empty = timeline.querySelector('.progress-timeline-empty');
            if (empty) {
                empty.textContent = hint;
                bindProcessDetailsLazyHint(timeline, messageId);
            }
        })
        .catch(() => {});
}

// Remove message
function removeMessage(id) {
    const messageDiv = document.getElementById(id);
    if (messageDiv) {
        messageDiv.remove();
    }
}

// Input box event binding (Enter to send, Shift+Enter for newline / @ mention)
const chatInput = document.getElementById('chat-input');
if (chatInput) {
    chatInput.addEventListener('keydown', handleChatInputKeydown);
    chatInput.addEventListener('input', handleChatInputInput);
    chatInput.addEventListener('click', handleChatInputClick);
    chatInput.addEventListener('focus', handleChatInputClick);
    // IME event listeners for tracking IME state
    chatInput.addEventListener('compositionstart', () => {
        if (compositionEndTimer) {
            clearTimeout(compositionEndTimer);
            compositionEndTimer = null;
        }
        isComposing = true;
    });
    chatInput.addEventListener('compositionend', () => {
        if (compositionEndTimer) {
            clearTimeout(compositionEndTimer);
        }
        compositionEndTimer = setTimeout(() => {
            isComposing = false;
            compositionEndTimer = null;
        }, 0);
    });
    chatInput.addEventListener('blur', () => {
        setTimeout(() => {
            if (!chatInput.matches(':focus')) {
                deactivateMentionState();
            }
        }, 120);
        // Save draft immediately on blur (no debounce wait)
        if (chatInput.value) {
            saveChatDraft(chatInput.value);
        }
    });
}

// Save draft immediately on page unload
window.addEventListener('beforeunload', () => {
    const chatInput = document.getElementById('chat-input');
    if (chatInput && chatInput.value) {
        // Save immediately, without debounce
        saveChatDraft(chatInput.value);
    }
});

function getPendingMcpExecutionCount(messageElement) {
    if (!messageElement || !messageElement.dataset || !messageElement.dataset.pendingMcpExecutionIds) {
        return 0;
    }
    try {
        const ids = JSON.parse(messageElement.dataset.pendingMcpExecutionIds);
        return Array.isArray(ids) ? ids.length : 0;
    } catch (e) {
        return 0;
    }
}

function getPendingToolExecutionSummaryCount(messageElement) {
    if (!messageElement || !messageElement.dataset || !messageElement.dataset.pendingToolExecutionSummaries) {
        return 0;
    }
    try {
        const tools = JSON.parse(messageElement.dataset.pendingToolExecutionSummaries);
        return Array.isArray(tools)
            ? tools.map(normalizeToolExecutionSummaryForButton).filter((item) => item.executionId).length
            : 0;
    } catch (e) {
        return 0;
    }
}

function getMcpExecutionCount(messageElement) {
    const pendingSummaries = getPendingToolExecutionSummaryCount(messageElement);
    if (pendingSummaries > 0) return pendingSummaries;
    const toolList = messageElement && messageElement.querySelector('.mcp-tool-list');
    if (toolList) {
        const rendered = toolList.querySelectorAll('.mcp-detail-btn').length;
        if (rendered > 0) return rendered;
    }
    if (messageElement && messageElement.dataset && messageElement.dataset.mcpExecutionCount) {
        const summaryCount = parseInt(messageElement.dataset.mcpExecutionCount, 10) || 0;
        if (summaryCount > 0) return summaryCount;
    }
    const pending = getPendingMcpExecutionCount(messageElement);
    if (pending > 0) return pending;
    return 0;
}

function getExistingMcpCallSectionChrome(messageElement) {
    if (!messageElement) return null;
    const mcpSection = messageElement.querySelector('.mcp-call-section');
    if (!mcpSection) return null;
    return {
        mcpSection: mcpSection,
        toolbar: mcpSection.querySelector('.mcp-call-toolbar'),
        toolList: mcpSection.querySelector('.mcp-tool-list')
    };
}

function pruneEmptyMcpCallSection(messageElement) {
    const chrome = getExistingMcpCallSectionChrome(messageElement);
    if (!chrome || !chrome.mcpSection) return;
    const hasDetails = !!chrome.mcpSection.querySelector('.process-details-container');
    const hasProcessDetailButton = !!(chrome.toolbar && chrome.toolbar.querySelector('.process-detail-btn'));
    const hasToolButtons = !!(chrome.toolList && chrome.toolList.querySelector('.mcp-detail-btn'));
    const hasPendingTools = getPendingMcpExecutionCount(messageElement) > 0 ||
        getPendingToolExecutionSummaryCount(messageElement) > 0 ||
        getMcpExecutionCount(messageElement) > 0;
    if (!hasDetails && !hasProcessDetailButton && !hasToolButtons && !hasPendingTools) {
        chrome.mcpSection.remove();
    }
}

function collectMcpExecutionIdsFromProcessDetails(processDetails) {
    if (!Array.isArray(processDetails)) return [];
    const seen = new Set();
    const ids = [];
    const add = (value) => {
        const id = value == null ? '' : String(value).trim();
        if (!id || seen.has(id)) return;
        seen.add(id);
        ids.push(id);
    };
    processDetails.forEach((detail) => {
        const data = detail && detail.data && typeof detail.data === 'object' ? detail.data : null;
        if (!data) return;
        add(data.executionId);
        const merged = data._mergedResult && typeof data._mergedResult === 'object' ? data._mergedResult : null;
        if (merged) add(merged.executionId);
    });
    return ids;
}

function normalizeMcpExecutionIds(executionIds) {
    if (!Array.isArray(executionIds)) return [];
    const seen = new Set();
    return executionIds.reduce((ids, value) => {
        const id = value == null ? '' : String(value).trim();
        if (id && !seen.has(id)) {
            seen.add(id);
            ids.push(id);
        }
        return ids;
    }, []);
}

function cacheMcpExecutionIds(messageElement, executionIds) {
    if (!messageElement || !messageElement.dataset) return [];
    const ids = normalizeMcpExecutionIds(executionIds);
    if (ids.length > 0) {
        messageElement.dataset.mcpExecutionIds = JSON.stringify(ids);
    } else {
        delete messageElement.dataset.mcpExecutionIds;
    }
    return ids;
}

function getCachedMcpExecutionIds(messageElement) {
    if (!messageElement || !messageElement.dataset || !messageElement.dataset.mcpExecutionIds) return [];
    try {
        return normalizeMcpExecutionIds(JSON.parse(messageElement.dataset.mcpExecutionIds));
    } catch (e) {
        delete messageElement.dataset.mcpExecutionIds;
        return [];
    }
}

function setPendingMcpExecutionIds(messageElement, executionIds) {
    if (!messageElement || !messageElement.dataset || !Array.isArray(executionIds)) return;
    const ids = cacheMcpExecutionIds(messageElement, executionIds);
    if (ids.length > 0) {
        messageElement.dataset.pendingMcpExecutionIds = JSON.stringify(ids);
    } else {
        delete messageElement.dataset.pendingMcpExecutionIds;
    }
    const renderedToolList = messageElement.querySelector('.mcp-tool-list');
    if (ids.length > 0 && renderedToolList && renderedToolList.querySelector('.mcp-detail-btn')) {
        renderMcpCallButtons(messageElement);
    }
    if (typeof syncMcpToolsToggleButton === 'function') {
        syncMcpToolsToggleButton(messageElement);
    }
}

function normalizeToolExecutionSummaryForButton(raw) {
    const data = raw && typeof raw === 'object' ? raw : {};
	return {
	    toolName: data.toolName || data.name || '',
	    status: data.status || '',
	    executionId: data.executionId || '',
	    toolCallId: data.toolCallId || '',
	    processDetailId: data.processDetailId || '',
	    resultDetailId: data.resultDetailId || ''
	};
}

function cacheToolExecutionSummaries(messageElement, summaries) {
    if (!messageElement || !messageElement.dataset || !Array.isArray(summaries)) return [];
    const normalized = summaries
        .map(normalizeToolExecutionSummaryForButton)
        .filter((item) => item.executionId);
    if (normalized.length > 0) {
        messageElement.dataset.toolExecutionSummaries = JSON.stringify(normalized);
    } else {
        delete messageElement.dataset.toolExecutionSummaries;
    }
    return normalized;
}

function getCachedToolExecutionSummaries(messageElement) {
    if (!messageElement || !messageElement.dataset || !messageElement.dataset.toolExecutionSummaries) return [];
    try {
        const parsed = JSON.parse(messageElement.dataset.toolExecutionSummaries);
        return Array.isArray(parsed) ? parsed.map(normalizeToolExecutionSummaryForButton) : [];
    } catch (e) {
        delete messageElement.dataset.toolExecutionSummaries;
        return [];
    }
}

function selectToolExecutionSummariesForButtons(summaries, executionIds) {
    const normalizedSummaries = Array.isArray(summaries)
        ? summaries.map(normalizeToolExecutionSummaryForButton)
        : [];
    const normalizedIds = normalizeMcpExecutionIds(executionIds);
    if (normalizedSummaries.length > 0) return normalizedSummaries;
    if (normalizedIds.length === 0) return normalizedSummaries;
    return normalizedIds.map((executionId) => normalizeToolExecutionSummaryForButton({ executionId }));
}

function setPendingToolExecutionSummaries(messageElement, summaries) {
    if (!messageElement || !messageElement.dataset || !Array.isArray(summaries)) return;
    const normalized = cacheToolExecutionSummaries(messageElement, summaries);
    if (normalized.length > 0) {
        messageElement.dataset.pendingToolExecutionSummaries = JSON.stringify(normalized);
    } else {
        delete messageElement.dataset.pendingToolExecutionSummaries;
    }
    const renderedToolList = messageElement.querySelector('.mcp-tool-list');
    if (normalized.length > 0 && renderedToolList && renderedToolList.querySelector('.mcp-detail-btn')) {
        setMcpCallSummaries(messageElement, normalized);
        delete messageElement.dataset.pendingToolExecutionSummaries;
    }
    if (typeof syncMcpToolsToggleButton === 'function') {
        syncMcpToolsToggleButton(messageElement);
    }
}

function setMcpExecutionSummaryCount(messageElement, count) {
    if (!messageElement || !messageElement.dataset) return;
    const n = parseInt(count, 10) || 0;
    if (n > 0) {
        messageElement.dataset.mcpExecutionCount = String(n);
    } else {
        delete messageElement.dataset.mcpExecutionCount;
    }
    if (typeof syncMcpToolsToggleButton === 'function') {
        syncMcpToolsToggleButton(messageElement);
    }
}

function formatMcpToolsToggleLabel(count, expanded) {
    if (expanded) {
        if (typeof window.t === 'function') {
            const s = window.t('chat.collapseToolExecutions');
            if (s && s !== 'chat.collapseToolExecutions') return s;
        }
        return 'Collapse tool executions';
    }
    if (typeof window.t === 'function') {
        const s = window.t('chat.toolExecutionsCount', { n: count });
        if (s && s !== 'chat.toolExecutionsCount') return s;
    }
    return count + ' tool executions';
}

function formatAssistantTurnDuration(durationMs) {
    const totalSeconds = Math.max(0, Math.floor((Number(durationMs) || 0) / 1000));
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) {
        return typeof window.t === 'function'
            ? window.t('chat.turnDurationHours', { hours: hours, minutes: minutes })
            : hours + ' h ' + minutes + ' min';
    }
    if (minutes > 0) {
        return typeof window.t === 'function'
            ? window.t('chat.turnDurationMinutes', { minutes: minutes, seconds: seconds })
            : minutes + ' min ' + seconds + ' s';
    }
    return typeof window.t === 'function'
        ? window.t('chat.turnDurationSeconds', { seconds: seconds })
        : seconds + ' s';
}

function assistantTurnUsageNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.round(n) : 0;
}

function normalizeAssistantTurnTokenUsage(data) {
    const source = data && typeof data === 'object' ? data : {};
    const usage = {
        modelCalls: assistantTurnUsageNumber(source.modelCalls),
        promptTokens: assistantTurnUsageNumber(source.promptTokens),
        completionTokens: assistantTurnUsageNumber(source.completionTokens),
        totalTokens: assistantTurnUsageNumber(source.totalTokens),
        cachedTokens: assistantTurnUsageNumber(source.cachedTokens),
        cacheWriteTokens: assistantTurnUsageNumber(source.cacheWriteTokens),
        reasoningTokens: assistantTurnUsageNumber(source.reasoningTokens),
        model: source.model != null ? String(source.model).trim() : ''
    };
    if (usage.totalTokens <= 0 && (usage.promptTokens > 0 || usage.completionTokens > 0)) {
        usage.totalTokens = usage.promptTokens + usage.completionTokens;
    }
    return usage.totalTokens > 0 ? usage : null;
}

function mergeAssistantTurnTokenUsage(target, usage) {
    if (!usage) return target || null;
    const out = target || {
        modelCalls: 0,
        promptTokens: 0,
        completionTokens: 0,
        totalTokens: 0,
        cachedTokens: 0,
        cacheWriteTokens: 0,
        reasoningTokens: 0,
        model: ''
    };
    out.modelCalls += usage.modelCalls || 0;
    out.promptTokens += usage.promptTokens || 0;
    out.completionTokens += usage.completionTokens || 0;
    out.totalTokens += usage.totalTokens || 0;
    out.cachedTokens += usage.cachedTokens || 0;
    out.cacheWriteTokens += usage.cacheWriteTokens || 0;
    out.reasoningTokens += usage.reasoningTokens || 0;
    if (!out.model && usage.model) out.model = usage.model;
    return out.totalTokens > 0 ? out : null;
}

function extractAssistantTurnTokenUsage(processDetails) {
    if (!Array.isArray(processDetails)) return null;
    let total = null;
    processDetails.forEach((detail) => {
        if (!detail || String(detail.eventType || '').trim() !== 'eino_usage_summary') return;
        const usage = normalizeAssistantTurnTokenUsage(detail.data);
        total = mergeAssistantTurnTokenUsage(total, usage);
    });
    return total;
}

function setAssistantTurnTokenUsage(messageElementOrId, usage) {
    const messageElement = typeof messageElementOrId === 'string'
        ? document.getElementById(messageElementOrId)
        : messageElementOrId;
    if (!messageElement || !messageElement.dataset) return;
    const normalized = normalizeAssistantTurnTokenUsage(usage);
    if (!normalized) {
        delete messageElement.dataset.turnModelCalls;
        delete messageElement.dataset.turnPromptTokens;
        delete messageElement.dataset.turnCompletionTokens;
        delete messageElement.dataset.turnTotalTokens;
        delete messageElement.dataset.turnCachedTokens;
        delete messageElement.dataset.turnCacheWriteTokens;
        delete messageElement.dataset.turnReasoningTokens;
        delete messageElement.dataset.turnModel;
        syncAssistantTurnSummary(messageElement);
        return;
    }
    messageElement.dataset.turnModelCalls = String(normalized.modelCalls || 0);
    messageElement.dataset.turnPromptTokens = String(normalized.promptTokens || 0);
    messageElement.dataset.turnCompletionTokens = String(normalized.completionTokens || 0);
    messageElement.dataset.turnTotalTokens = String(normalized.totalTokens || 0);
    messageElement.dataset.turnCachedTokens = String(normalized.cachedTokens || 0);
    messageElement.dataset.turnCacheWriteTokens = String(normalized.cacheWriteTokens || 0);
    messageElement.dataset.turnReasoningTokens = String(normalized.reasoningTokens || 0);
    if (normalized.model) {
        messageElement.dataset.turnModel = normalized.model;
    } else {
        delete messageElement.dataset.turnModel;
    }
    syncAssistantTurnSummary(messageElement);
}

function getAssistantTurnTokenUsage(messageElement) {
    if (!messageElement || !messageElement.dataset) return null;
    return normalizeAssistantTurnTokenUsage({
        modelCalls: messageElement.dataset.turnModelCalls,
        promptTokens: messageElement.dataset.turnPromptTokens,
        completionTokens: messageElement.dataset.turnCompletionTokens,
        totalTokens: messageElement.dataset.turnTotalTokens,
        cachedTokens: messageElement.dataset.turnCachedTokens,
        cacheWriteTokens: messageElement.dataset.turnCacheWriteTokens,
        reasoningTokens: messageElement.dataset.turnReasoningTokens,
        model: messageElement.dataset.turnModel
    });
}

function formatAssistantTurnTokenCount(value) {
    const n = assistantTurnUsageNumber(value);
    if (n >= 1000000) return (n / 1000000).toFixed(n >= 10000000 ? 0 : 1).replace(/\.0$/, '') + 'M';
    if (n >= 1000) return (n / 1000).toFixed(n >= 100000 ? 0 : 1).replace(/\.0$/, '') + 'K';
    return String(n);
}

function formatAssistantTurnTokenUsageLabel(usage) {
    const tokens = formatAssistantTurnTokenCount(usage && usage.totalTokens);
    return typeof window.t === 'function'
        ? window.t('chat.turnTokenUsageLabel', { tokens: tokens })
        : tokens + ' tokens';
}

function formatAssistantTurnTokenUsageTitle(usage) {
    const safeUsage = usage || {};
    const values = {
        total: formatAssistantTurnTokenCount(safeUsage.totalTokens),
        prompt: formatAssistantTurnTokenCount(safeUsage.promptTokens),
        completion: formatAssistantTurnTokenCount(safeUsage.completionTokens),
        cached: formatAssistantTurnTokenCount(safeUsage.cachedTokens),
        cacheWrite: formatAssistantTurnTokenCount(safeUsage.cacheWriteTokens),
        reasoning: formatAssistantTurnTokenCount(safeUsage.reasoningTokens),
        calls: formatAssistantTurnTokenCount(safeUsage.modelCalls),
        model: safeUsage.model || ''
    };
    return typeof window.t === 'function'
        ? window.t('chat.turnTokenUsageTitle', values)
        : 'Token usage: ' + values.total + ' (input ' + values.prompt + ', output ' + values.completion + ')';
}

function assistantTurnTimestamp(value) {
    if (value == null || value === '') return NaN;
    const n = new Date(value).getTime();
    return Number.isFinite(n) ? n : NaN;
}

// Continue button for a stopped assistant reply (error, cancelled, timeout, or a final reply check that did not pass).
function assistantReplyStopped(processDetails, content) {
    if (Array.isArray(processDetails)) {
        for (let i = processDetails.length - 1; i >= 0; i--) {
            const d = processDetails[i] || {};
            const et = String(d.eventType || '').trim().toLowerCase();
            if (et === 'finalization_check') {
                let data = d.data;
                if (typeof data === 'string') {
                    try { data = JSON.parse(data); } catch (e) { data = {}; }
                }
                return !(data && data.finalized === true);
            }
            if (et === 'error' || et === 'cancelled' || et === 'timeout') return true;
        }
    }
    return false;
}

function addContinueButton(messageEl, backendMessageId) {
    if (!messageEl || !backendMessageId || messageEl.querySelector('.message-continue-btn')) return;
    const footer = messageEl.querySelector('.message-meta-footer') || messageEl.querySelector('.message-content');
    if (!footer) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn-secondary message-continue-btn';
    btn.setAttribute('data-require-permission', 'chat:write');
    btn.textContent = (typeof window.t === 'function' && window.t('chat.continueReply') !== 'chat.continueReply')
        ? window.t('chat.continueReply') : 'Continue';
    btn.addEventListener('click', async () => {
        btn.disabled = true;
        try {
            const res = await apiFetch('/api/messages/' + encodeURIComponent(backendMessageId) + '/continue', { method: 'POST' });
            const body = await res.json().catch(() => ({}));
            if (!res.ok) {
                throw new Error(body && body.error ? body.error : ('HTTP ' + res.status));
            }
            btn.remove();
            const convId = body.conversationId || currentConversationId;
            if (convId) {
                await loadConversation(convId);
            }
        } catch (err) {
            btn.disabled = false;
            showChatToast('Continue failed: ' + (err && err.message ? err.message : String(err)), 'error');
        }
    });
    footer.appendChild(btn);
}

async function maybeShowContinueButton(messageEl, backendMessageId, processDetails, content) {
    try {
        let details = processDetails;
        if (details === null) {
            const r = await apiFetch('/api/messages/' + encodeURIComponent(backendMessageId) + '/process-details?full=1');
            const j = r.ok ? await r.json().catch(() => ({})) : {};
            details = Array.isArray(j.processDetails) ? j.processDetails : [];
        }
        if (assistantReplyStopped(details, content)) {
            addContinueButton(messageEl, backendMessageId);
        }
    } catch (e) { /* ignore */ }
}
window.addContinueButton = addContinueButton;

function assistantTurnTerminalState(processDetails) {
    if (!Array.isArray(processDetails)) return null;
    for (let i = processDetails.length - 1; i >= 0; i--) {
        const detail = processDetails[i] || {};
        const eventType = String(detail.eventType || '').trim().toLowerCase();
        if (eventType === 'cancelled') {
            return { status: 'cancelled', completedAt: detail.createdAt || null, detail: detail };
        }
        if (eventType === 'timeout') {
            return { status: 'timeout', completedAt: detail.createdAt || null, detail: detail };
        }
        if (eventType === 'error') {
            return { status: 'failed', completedAt: detail.createdAt || null, detail: detail };
        }
    }
    return null;
}

let assistantTurnElapsedTimer = null;

function syncRunningAssistantTurnSummaries() {
    const runningTurns = document.querySelectorAll('#chat-messages .message.assistant[data-turn-status="running"]');
    runningTurns.forEach((messageElement) => syncAssistantTurnSummary(messageElement));
    if (runningTurns.length === 0 && assistantTurnElapsedTimer) {
        clearInterval(assistantTurnElapsedTimer);
        assistantTurnElapsedTimer = null;
    }
}

function syncAssistantTurnElapsedClock() {
    const hasRunningTurn = !!document.querySelector('#chat-messages .message.assistant[data-turn-status="running"]');
    if (hasRunningTurn && !assistantTurnElapsedTimer) {
        assistantTurnElapsedTimer = setInterval(syncRunningAssistantTurnSummaries, 1000);
    } else if (!hasRunningTurn && assistantTurnElapsedTimer) {
        clearInterval(assistantTurnElapsedTimer);
        assistantTurnElapsedTimer = null;
    }
}

function setAssistantTurnTiming(messageElementOrId, timing) {
    const messageElement = typeof messageElementOrId === 'string'
        ? document.getElementById(messageElementOrId)
        : messageElementOrId;
    if (!messageElement || !messageElement.dataset) return;
    const value = timing || {};
    if (value.startedAt) messageElement.dataset.turnStartedAt = String(value.startedAt);
    if (value.completedAt) messageElement.dataset.turnCompletedAt = String(value.completedAt);
    if (value.status) messageElement.dataset.turnStatus = String(value.status);
    const status = String(messageElement.dataset.turnStatus || 'completed');
    if (status === 'running') {
        // The summary API returns durationMs=0 for running tasks. On page refresh, this snapshot must not be
        // saved as a fixed duration, otherwise later renders would keep showing "processed 0 seconds".
        delete messageElement.dataset.turnDurationMs;
        delete messageElement.dataset.turnCompletedAt;
    } else {
        const explicitDuration = Number(value.durationMs);
        if (Number.isFinite(explicitDuration) && explicitDuration >= 0) {
            messageElement.dataset.turnDurationMs = String(Math.round(explicitDuration));
        }
        const startedAt = assistantTurnTimestamp(messageElement.dataset.turnStartedAt);
        const completedAt = assistantTurnTimestamp(messageElement.dataset.turnCompletedAt);
        if ((!Number.isFinite(explicitDuration) || explicitDuration < 0) &&
            Number.isFinite(startedAt) && Number.isFinite(completedAt) && completedAt >= startedAt) {
            messageElement.dataset.turnDurationMs = String(completedAt - startedAt);
        }
    }
    syncAssistantTurnSummary(messageElement);
    syncAssistantTurnElapsedClock();
}

function syncAssistantTurnSummary(messageElementOrId) {
    const messageElement = typeof messageElementOrId === 'string'
        ? document.getElementById(messageElementOrId)
        : messageElementOrId;
    if (!messageElement) return;
    const label = messageElement.querySelector('.mcp-call-label.turn-process-summary');
    if (!label) return;
    const details = messageElement.querySelector('.process-details-container');
    const timeline = details && details.querySelector('.progress-timeline');
    const expanded = !!(timeline && timeline.classList.contains('expanded'));
    const status = String(messageElement.dataset.turnStatus || 'completed');
    let durationMs = Number(messageElement.dataset.turnDurationMs);
    if (!Number.isFinite(durationMs) || durationMs < 0) {
        const startedAt = assistantTurnTimestamp(messageElement.dataset.turnStartedAt);
        const completedAt = status === 'running'
            ? Date.now()
            : assistantTurnTimestamp(messageElement.dataset.turnCompletedAt);
        durationMs = Number.isFinite(startedAt) && Number.isFinite(completedAt)
            ? Math.max(0, completedAt - startedAt)
            : 0;
    }
    const duration = formatAssistantTurnDuration(durationMs);
    const tokenUsage = getAssistantTurnTokenUsage(messageElement);
    const tokenUsageHtml = tokenUsage
        ? '<span class="turn-process-token-chip" title="' + escapeHtml(formatAssistantTurnTokenUsageTitle(tokenUsage)) + '">' +
            escapeHtml(formatAssistantTurnTokenUsageLabel(tokenUsage)) +
          '</span>'
        : '';
    let text;
    if (status === 'running') {
        text = typeof window.t === 'function' ? window.t('chat.turnElapsedRunning', { duration: duration }) : 'Processed ' + duration;
    } else if (status === 'cancelled') {
        text = typeof window.t === 'function' ? window.t('chat.turnElapsedCancelled', { duration: duration }) : 'Interrupted · took ' + duration;
    } else if (status === 'timeout') {
        text = typeof window.t === 'function' ? window.t('chat.turnElapsedTimeout', { duration: duration }) : 'Timed out · took ' + duration;
    } else if (status === 'failed') {
        text = typeof window.t === 'function' ? window.t('chat.turnElapsedFailed', { duration: duration }) : 'Failed · took ' + duration;
    } else {
        text = typeof window.t === 'function' ? window.t('chat.turnElapsedComplete', { duration: duration }) : 'Took ' + duration;
    }
    label.innerHTML = `
        <span class="turn-process-leading">
            <span class="turn-process-status-dot${status === 'running' ? ' is-running' : ''}" aria-hidden="true"></span>
            <span class="turn-process-summary-text">${escapeHtml(text)}</span>
            ${tokenUsageHtml}
        </span>
        <svg class="turn-process-chevron" viewBox="0 0 20 20" fill="none" aria-hidden="true"><path d="M7.5 5.5L12 10l-4.5 4.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
    `;
    label.classList.toggle('is-expanded', expanded);
    label.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    label.setAttribute('aria-label', typeof window.t === 'function'
        ? window.t('chat.turnProcessAria', { state: text })
        : text + ', expand or collapse execution details');
}

window.setAssistantTurnTiming = setAssistantTurnTiming;
window.setAssistantTurnTokenUsage = setAssistantTurnTokenUsage;
window.syncAssistantTurnSummary = syncAssistantTurnSummary;
window.formatAssistantTurnDuration = formatAssistantTurnDuration;
window.extractAssistantTurnTokenUsage = extractAssistantTurnTokenUsage;

/** Pentest area: toolbar (expand details | N tool executions) + standalone tool list + iteration timeline */
function ensureMcpCallSectionChrome(messageElement, messageId) {
    const contentWrapper = messageElement && messageElement.querySelector('.message-content');
    if (!contentWrapper) return null;

    let mcpSection = messageElement.querySelector('.mcp-call-section');
    if (!mcpSection) {
        mcpSection = document.createElement('div');
        mcpSection.className = 'mcp-call-section';
        const mcpLabel = document.createElement('button');
        mcpLabel.type = 'button';
        mcpLabel.className = 'mcp-call-label turn-process-summary';
        mcpLabel.onclick = function (event) {
            event.stopPropagation();
            toggleProcessDetails(null, messageId || messageElement.id);
        };
        mcpSection.appendChild(mcpLabel);
        const resultBubble = contentWrapper.querySelector(':scope > .message-bubble');
        contentWrapper.insertBefore(mcpSection, resultBubble || contentWrapper.firstChild);
    } else if (mcpSection.parentNode === contentWrapper) {
        const resultBubble = contentWrapper.querySelector(':scope > .message-bubble');
        if (resultBubble && mcpSection.nextSibling !== resultBubble) {
            contentWrapper.insertBefore(mcpSection, resultBubble);
        }
    }

    messageElement.classList.add('assistant-turn-with-process');
    const resultBubble = contentWrapper.querySelector(':scope > .message-bubble');
    if (resultBubble) resultBubble.classList.add('assistant-final-result');

    let toolbar = mcpSection.querySelector('.mcp-call-toolbar');
    if (!toolbar) {
        toolbar = document.createElement('div');
        toolbar.className = 'mcp-call-toolbar';
        mcpSection.appendChild(toolbar);
    }

    let toolList = mcpSection.querySelector('.mcp-tool-list');
    if (!toolList) {
        toolList = document.createElement('div');
        toolList.className = 'mcp-tool-list';
        const detailsContainer = mcpSection.querySelector('.process-details-container');
        if (detailsContainer) {
            mcpSection.insertBefore(toolList, detailsContainer);
        } else {
            toolbar.after(toolList);
        }
    }

    const clientId = messageId || messageElement.id;
    if (clientId && !toolbar.querySelector('.process-detail-btn')) {
        const processDetailBtn = document.createElement('button');
        processDetailBtn.className = 'mcp-detail-btn process-detail-btn';
        processDetailBtn.innerHTML = '<span>' + (typeof window.t === 'function' ? window.t('chat.expandDetail') : 'Expand details') + '</span>';
        processDetailBtn.onclick = () => toggleProcessDetails(null, clientId);
        toolbar.appendChild(processDetailBtn);
    }

    syncAssistantTurnSummary(messageElement);
    return { mcpSection, toolbar, toolList };
}

function syncMcpToolsToggleButton(messageElement) {
    if (!messageElement) return;
    const count = getMcpExecutionCount(messageElement);
    let chrome = getExistingMcpCallSectionChrome(messageElement);
    if (!chrome || (count > 0 && (!chrome.toolbar || !chrome.toolList))) {
        if (count <= 0) return;
        chrome = ensureMcpCallSectionChrome(messageElement, messageElement.id);
    }
    if (!chrome) return;
    const { toolbar, toolList } = chrome;
    if (!toolbar || !toolList) return;
    let toolsToggle = toolbar.querySelector('.mcp-tools-toggle-btn');
    if (count <= 0) {
        if (toolsToggle) toolsToggle.remove();
        pruneEmptyMcpCallSection(messageElement);
        return;
    }
    if (!toolsToggle) {
        toolsToggle = document.createElement('button');
        toolsToggle.type = 'button';
        toolsToggle.className = 'mcp-detail-btn mcp-tools-toggle-btn';
        toolsToggle.onclick = function (e) {
            e.stopPropagation();
            toggleMcpToolList(messageElement.id);
        };
        toolbar.appendChild(toolsToggle);
    }
    const expanded = toolList.classList.contains('expanded');
    toolsToggle.innerHTML = '<span>' + formatMcpToolsToggleLabel(count, expanded) + '</span>';
}

function toggleMcpToolList(assistantMessageId) {
    const messageEl = document.getElementById(assistantMessageId);
    if (!messageEl) return;
    const chrome = ensureMcpCallSectionChrome(messageEl, assistantMessageId);
    if (!chrome) return;
    const { toolList } = chrome;
    if (
        !getPendingMcpExecutionCount(messageEl) &&
        !getPendingToolExecutionSummaryCount(messageEl) &&
        !toolList.querySelector('.mcp-detail-btn')
    ) {
        syncMcpToolsToggleButton(messageEl);
        return;
    }
    const willExpand = !toolList.classList.contains('expanded');
    if (willExpand) {
        renderPendingMcpCallButtons(messageEl);
        toolList.classList.add('expanded');
    } else {
        toolList.classList.remove('expanded');
    }
    syncMcpToolsToggleButton(messageEl);
}

window.toggleMcpToolList = toggleMcpToolList;
window.syncMcpToolsToggleButton = syncMcpToolsToggleButton;
window.isProcessDetailsUserExpanded = isProcessDetailsUserExpanded;
window.syncProcessDetailButtonLabels = syncProcessDetailButtonLabels;
window.ensureMcpCallSectionChrome = ensureMcpCallSectionChrome;
window.setMcpExecutionSummaryCount = setMcpExecutionSummaryCount;
window.setPendingMcpExecutionIds = setPendingMcpExecutionIds;
window.setPendingToolExecutionSummaries = setPendingToolExecutionSummaries;

async function openTaskToolExecutionDetail(messageElement, item, index) {
    const detailItem = normalizeToolExecutionSummaryForButton(item);
    if (!detailItem.executionId) return;
    await showMCPDetail(detailItem.executionId);
}

/**
* Declarative rendering of the tool call list.
* Tool details use executionId as the only stable entry point; historical summaries without executionId do not render a tool detail entry.
* Each update replaces the whole list, avoiding duplicate state from incremental appends.
 */
function renderMcpCallButtons(messageElement) {
    if (!messageElement) return;
    const chrome = ensureMcpCallSectionChrome(messageElement, messageElement.id);
    if (!chrome) return;
    const toolList = chrome.toolList;
    const executionIds = getCachedMcpExecutionIds(messageElement);
    const summaries = getCachedToolExecutionSummaries(messageElement);
    const items = selectToolExecutionSummariesForButtons(summaries, executionIds)
        .filter((item) => item && item.executionId);

    const renderVersion = String((parseInt(toolList.dataset.renderVersion, 10) || 0) + 1);
    toolList.dataset.renderVersion = renderVersion;
    const fragment = document.createDocumentFragment();
    items.forEach((item, index) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'mcp-detail-btn';
        btn.dataset.execIndex = String(index + 1);
        if (item.executionId) {
            btn.dataset.execId = item.executionId;
        }
        if (item.toolCallId) {
            btn.dataset.toolCallId = item.toolCallId;
        }
        btn.onclick = () => openTaskToolExecutionDetail(messageElement, item, index);
        if (item.toolName) {
            renderToolExecutionButtonContent(btn, item.toolName, String(index + 1), item.status);
        } else {
            btn.innerHTML = '<span>' + (typeof window.t === 'function'
                ? window.t('chat.callNumber', { n: index + 1 })
                : 'Call #' + (index + 1)) + '</span>';
        }
        fragment.appendChild(btn);
    });
    toolList.replaceChildren(fragment);

    if (summaries.length === 0 && executionIds.length > 0) {
        batchUpdateButtonToolNames(toolList, executionIds, renderVersion);
    }
    syncMcpToolsToggleButton(messageElement);
}

function setMcpCallExecutionIds(messageElement, executionIds) {
    if (!messageElement || !Array.isArray(executionIds)) return;
    cacheMcpExecutionIds(messageElement, executionIds);
    renderMcpCallButtons(messageElement);
}

function setMcpCallSummaries(messageElement, summaries) {
    if (!messageElement || !Array.isArray(summaries)) return;
    cacheToolExecutionSummaries(messageElement, summaries);
    renderMcpCallButtons(messageElement);
}

/** Lazy load: submit the pending data model when the user expands the tool list. */
function renderPendingMcpCallButtons(messageElement) {
    if (!messageElement || !messageElement.dataset) {
        return;
    }
    let renderedSummaryExecutions = false;
    if (messageElement.dataset.pendingToolExecutionSummaries) {
        let summaries;
        try {
            summaries = JSON.parse(messageElement.dataset.pendingToolExecutionSummaries);
        } catch (e) {
            delete messageElement.dataset.pendingToolExecutionSummaries;
            summaries = [];
        }
        if (Array.isArray(summaries) && summaries.length > 0) {
            setMcpCallSummaries(messageElement, summaries);
            renderedSummaryExecutions = true;
        }
        delete messageElement.dataset.pendingToolExecutionSummaries;
    }
    if (renderedSummaryExecutions) {
        return;
    }
    if (messageElement.dataset.pendingMcpExecutionIds) {
        let executionIds;
        try {
            executionIds = JSON.parse(messageElement.dataset.pendingMcpExecutionIds);
        } catch (e) {
            delete messageElement.dataset.pendingMcpExecutionIds;
            executionIds = [];
        }
        if (Array.isArray(executionIds) && executionIds.length > 0) {
            setMcpCallExecutionIds(messageElement, executionIds);
        }
        delete messageElement.dataset.pendingMcpExecutionIds;
    }
}

window.setMcpCallExecutionIds = setMcpCallExecutionIds;

function normalizeToolExecutionSummary(raw) {
    if (typeof raw === 'string') {
        return { toolName: raw, status: '' };
    }
    if (raw && typeof raw === 'object') {
        return {
            toolName: raw.toolName || raw.name || '',
            status: typeof window.getToolExecutionDisplayStatus === 'function' ? window.getToolExecutionDisplayStatus(raw) : (raw.status || '')
        };
    }
    return { toolName: '', status: '' };
}

function getToolExecutionStatusLabel(status) {
    const normalized = String(status || '').toLowerCase();
    if (typeof window.t === 'function') {
        const keyMap = {
            completed: 'mcpMonitor.statusSuccess',
            failed: 'mcpMonitor.statusFailed',
            blocked: 'mcpMonitor.statusBlocked',
            running: 'mcpMonitor.statusRunning',
            cancelled: 'mcpMonitor.statusCancelled',
            pending: 'mcpMonitor.statusPending',
            result_missing: 'timeline.resultMissing'
        };
        const key = keyMap[normalized];
        if (key) {
            const translated = window.t(key);
            if (translated && translated !== key) return translated;
        }
    }
    const fallback = {
        completed: 'Succeeded',
        failed: 'Failed',
        blocked: 'Blocked',
        running: 'Running',
        cancelled: 'Cancelled',
        pending: 'Pending',
        result_missing: 'Result record missing'
    };
    return fallback[normalized] || '';
}

function renderToolExecutionButtonContent(btn, displayToolName, index, status) {
    const safeToolName = escapeHtml(displayToolName || (typeof window.t === 'function' ? window.t('chat.unknownTool') : 'Unknown tool'));
    const safeIndex = escapeHtml(index || '');
    const statusText = getToolExecutionStatusLabel(status);
    const normalizedStatus = String(status || '').toLowerCase();
    const label = safeIndex ? `${safeToolName} #${safeIndex}` : safeToolName;
    btn.innerHTML = '<span class="mcp-tool-name">' + label + '</span>';
    if (!statusText) {
        btn.removeAttribute('data-status');
        btn.removeAttribute('title');
        return;
    }
    btn.dataset.status = normalizedStatus;
    btn.title = statusText;
}

// Batch-fetch tool summaries and update buttons (replaces N separate API requests with one)
async function batchUpdateButtonToolNames(buttonsContainer, executionIds, renderVersion) {
    if (!executionIds || executionIds.length === 0) return;
    try {
        const response = await apiFetch('/api/monitor/executions/names', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: executionIds }),
        });
        if (!response.ok) return;
        const nameMap = await response.json(); // { execId: toolName } or { execId: { toolName, status } }
        // If the summary triggered a new render while the request was pending, the old response must not overwrite the new state.
        if (renderVersion && buttonsContainer.dataset.renderVersion !== renderVersion) return;
        // Update the corresponding button text
        const buttons = buttonsContainer.querySelectorAll('.mcp-detail-btn[data-exec-id]');
        buttons.forEach(btn => {
            const execId = btn.dataset.execId;
            const index = btn.dataset.execIndex;
            const summary = normalizeToolExecutionSummary(nameMap[execId]);
            const toolName = summary.toolName;
            if (toolName) {
                const displayToolName = toolName.includes('::') ? toolName.split('::')[1] : toolName;
                renderToolExecutionButtonContent(btn, displayToolName, index, summary.status);
            }
        });
    } catch (error) {
        console.error('Failed to batch-fetch tool names:', error);
    }
}

function extractMCPResultText(result) {
    if (!result) return '';
    const content = result.content;
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) {
        return content
            .map(item => (item && typeof item === 'object' && typeof item.text === 'string') ? item.text : '')
            .filter(Boolean)
            .join('\n\n');
    }
    if (content && typeof content === 'object' && typeof content.text === 'string') {
        return content.text;
    }
    return '';
}

function formatMCPDetailText(text) {
    if (text == null) return '';
    return String(text);
}

function formatMCPResultJsonForDisplay(result) {
    if (!result) return '{}';
    const payload = {
        content: result.content,
        isError: !!result.isError,
        ...(result.blocked === true ? { blocked: true } : {})
    };
    return JSON.stringify(payload, null, 2);
}

function switchMCPResultDetailTab(tabName) {
    const normalized = tabName === 'raw' ? 'raw' : 'success';
    const tabs = {
        success: document.getElementById('detail-result-tab-success'),
        raw: document.getElementById('detail-result-tab-raw')
    };
    const panels = {
        success: document.getElementById('detail-result-panel-success'),
        raw: document.getElementById('detail-result-panel-raw')
    };
    Object.keys(tabs).forEach(function (key) {
        const isActive = key === normalized;
        if (tabs[key]) {
            tabs[key].classList.toggle('active', isActive);
            tabs[key].setAttribute('aria-selected', isActive ? 'true' : 'false');
        }
        if (panels[key]) {
            panels[key].classList.toggle('active', isActive);
            panels[key].hidden = !isActive;
        }
    });
}

function setMCPResultDetailTabs(defaultTab, hasSuccessContent) {
    const successTab = document.getElementById('detail-result-tab-success');
    if (successTab) {
        successTab.disabled = !hasSuccessContent;
        successTab.classList.toggle('disabled', !hasSuccessContent);
    }
    switchMCPResultDetailTab(hasSuccessContent && defaultTab !== 'raw' ? 'success' : 'raw');
}

function copyActiveMCPResultDetail(triggerBtn = null) {
    const activePanel = document.querySelector('#mcp-detail-modal .detail-result-panel.active');
    const activeBlock = activePanel ? activePanel.querySelector('.code-block') : null;
    copyDetailBlock(activeBlock ? activeBlock.id : 'detail-response', triggerBtn);
}

function renderMCPDetailModal(exec) {
    exec = exec || {};
    document.getElementById('detail-tool-name').textContent = exec.toolName || (typeof window.t === 'function' ? window.t('mcpDetailModal.unknown') : 'Unknown');
    document.getElementById('detail-execution-id').textContent = exec.id || 'N/A';
    const statusEl = document.getElementById('detail-status');
    const normalizedStatus = typeof window.getToolExecutionDisplayStatus === 'function' ? window.getToolExecutionDisplayStatus(exec) : (exec.status || 'unknown').toLowerCase();
    const blocked = normalizedStatus === 'blocked';
    statusEl.textContent = getStatusText(normalizedStatus);
    const statusClass = normalizedStatus === 'background_running' ? 'running' : normalizedStatus;
    statusEl.className = `status-chip status-${statusClass}`;
    try {
        statusEl.dataset.detailStatus = normalizedStatus;
    } catch (e) { /* ignore */ }
    const detailTimeLocale = (typeof window.uiLocale === 'function' ? window.uiLocale() : 'en-US');
    const detailTimeEl = document.getElementById('detail-time');
    if (detailTimeEl) {
        detailTimeEl.textContent = exec.startTime
            ? new Date(exec.startTime).toLocaleString(detailTimeLocale)
            : '—';
        try {
            detailTimeEl.dataset.detailTimeIso = exec.startTime ? new Date(exec.startTime).toISOString() : '';
        } catch (e) { /* ignore */ }
    }

    const requestData = {
        tool: exec.toolName,
        arguments: exec.arguments
    };
    document.getElementById('detail-request').textContent = JSON.stringify(requestData, null, 2);

    const responseElement = document.getElementById('detail-response');
    const successElement = document.getElementById('detail-success');
    const errorSection = document.getElementById('detail-error-section');
    const errorElement = document.getElementById('detail-error');

    responseElement.className = 'code-block';
    responseElement.textContent = '';
    if (successElement) {
        successElement.className = 'code-block';
        successElement.textContent = '';
    }
    if (errorSection && errorElement) {
        errorSection.style.display = 'none';
        errorElement.textContent = '';
    }
    setMCPResultDetailTabs('raw', false);
    const resultTabLabel = document.querySelector('#detail-result-tab-success [data-i18n]');
    if (resultTabLabel) {
        const key = blocked ? 'mcpDetailModal.blockReason' : 'mcpDetailModal.correctInfo';
        resultTabLabel.dataset.i18n = key;
        resultTabLabel.textContent = typeof window.t === 'function' ? window.t(key) : (blocked ? 'Block reason' : 'Result');
    }

    if (exec.result) {
        const agentVisibleText = formatMCPDetailText(extractMCPResultText(exec.result));
        const emptyText = typeof window.t === 'function' ? window.t('mcpDetailModal.execSuccessNoContent') : 'Executed successfully; no displayable text content was returned.';

        if (blocked) {
            responseElement.className = 'code-block blocked';
            responseElement.textContent = formatMCPResultJsonForDisplay(exec.result);
            if (successElement) {
                successElement.className = 'code-block blocked';
                successElement.textContent = agentVisibleText || exec.error || getStatusText('blocked');
            }
            setMCPResultDetailTabs('success', true);
        } else if (exec.result.isError) {
            responseElement.className = 'code-block error';
            responseElement.textContent = formatMCPResultJsonForDisplay(exec.result);
            if (successElement) {
                successElement.textContent = '';
            }
            setMCPResultDetailTabs('raw', false);
            if (exec.error && errorSection && errorElement) {
                errorSection.style.display = 'block';
                errorElement.textContent = exec.error;
            }
        } else {
            responseElement.className = 'code-block';
            responseElement.textContent = formatMCPResultJsonForDisplay(exec.result);
            if (successElement) {
                successElement.textContent = agentVisibleText || emptyText;
            }
            setMCPResultDetailTabs('success', true);
        }
    } else {
        if (normalizedStatus === 'running' || normalizedStatus === 'background_running') {
            responseElement.textContent = typeof window.t === 'function' ? window.t('mcpDetailModal.runningNoResponseYet') : 'No response yet; the tool may still be running. If there is no response for a long time, you can terminate this call below.';
        } else {
            responseElement.textContent = typeof window.t === 'function' ? window.t('chat.noResponseData') : 'No response data';
        }
        setMCPResultDetailTabs('raw', false);
    }

    const abortSection = document.getElementById('detail-abort-section');
    const abortBtn = document.getElementById('detail-abort-btn');
    if (abortSection && abortBtn) {
        if ((normalizedStatus === 'running' || normalizedStatus === 'background_running') && exec.id) {
            abortSection.style.display = 'block';
            abortBtn.dataset.execId = exec.id || '';
            abortBtn.textContent = typeof window.t === 'function' ? window.t('mcpDetailModal.abortBtn') : 'Stop tool';
        } else {
            abortSection.style.display = 'none';
            delete abortBtn.dataset.execId;
        }
    }
}

async function showMCPDetail(executionId) {
    try {
        openAppModal('mcp-detail-modal', { focus: false });
        const response = await apiFetch(`/api/monitor/execution/${executionId}`);
        const exec = await response.json();

        if (!response.ok) {
            closeMCPDetail();
            alert((typeof window.t === 'function' ? window.t('mcpDetailModal.getDetailFailed') : 'Failed to get details') + ': ' + (exec.error || (typeof window.t === 'function' ? window.t('mcpDetailModal.unknown') : 'Unknown error')));
            return;
        }

        deferModalContent(function () {
            renderMCPDetailModal(exec);
        });
    } catch (error) {
        closeMCPDetail();
        alert((typeof window.t === 'function' ? window.t('mcpDetailModal.getDetailFailed') : 'Failed to get details') + ': ' + error.message);
    }
}

// Close MCP details modal
function closeMCPDetail() {
    closeAppModal('mcp-detail-modal');
}

/** Triggered from the details modal: cancel the MCP tool call in progress */
async function abortMCPToolExecutionFromDetail() {
    const btn = document.getElementById('detail-abort-btn');
    const id = btn && btn.dataset.execId;
    if (!id) {
        return;
    }
    await cancelMCPToolExecution(id, { refreshDetail: true });
}

/**
* Open the MCP tool termination dialog (the note is merged with the tool output for the model after the server adds a "user termination note" heading block)
 * @param {string} executionId
 * @param {{ refreshDetail?: boolean }} [options]
 */
function openMcpToolAbortModal(executionId, options = {}) {
    window.__mcpToolAbortContext = { executionId: executionId, options: options || {} };
    const ta = document.getElementById('mcp-tool-abort-note');
    if (ta) {
        ta.value = '';
    }
    openAppModal('mcp-tool-abort-modal');
}

function closeMcpToolAbortModal() {
    window.__mcpToolAbortContext = null;
    closeAppModal('mcp-tool-abort-modal');
}

async function submitMcpToolAbortModal() {
    const ctx = window.__mcpToolAbortContext;
    if (!ctx || !ctx.executionId) {
        closeMcpToolAbortModal();
        return;
    }
    const note = (document.getElementById('mcp-tool-abort-note') && document.getElementById('mcp-tool-abort-note').value || '').trim();
    const executionId = ctx.executionId;
    const options = ctx.options || {};
    closeMcpToolAbortModal();
    await cancelMCPToolExecutionSubmit(executionId, note, options);
}

/**
* Submit termination request (body: { note })
 * @param {string} executionId
 * @param {string} userNote
 * @param {{ refreshDetail?: boolean }} [options]
 */
async function cancelMCPToolExecutionSubmit(executionId, userNote, options = {}) {
    if (!executionId) {
        return;
    }
    let conversationId = '';
    if (typeof monitorState !== 'undefined' && Array.isArray(monitorState.executions)) {
        const exec = monitorState.executions.find(e => e && e.id === executionId);
        if (exec) {
            conversationId = (exec.conversationId || '').trim();
        }
    }
    try {
        if (conversationId && typeof requestCancelWithContinue === 'function') {
            await requestCancelWithContinue(conversationId, userNote || '', { executionId });
        } else {
            const res = await apiFetch(`/api/monitor/execution/${encodeURIComponent(executionId)}/cancel`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ note: userNote || '' }),
            });
            const body = await res.json().catch(() => ({}));
            if (!res.ok) {
                throw new Error(body.error || body.message || res.statusText);
            }
        }
        const okMsg = typeof window.t === 'function' ? window.t('mcpDetailModal.abortSuccess') : 'Termination request sent';
        alert(okMsg);
        if (options.refreshDetail && typeof showMCPDetail === 'function') {
            await showMCPDetail(executionId);
        }
        if (typeof refreshMonitorPanel === 'function') {
            const page = (typeof monitorState !== 'undefined' && monitorState.pagination && monitorState.pagination.page) ? monitorState.pagination.page : 1;
            await refreshMonitorPanel(page);
        }
    } catch (e) {
        const failMsg = typeof window.t === 'function' ? window.t('mcpDetailModal.abortFailed') : 'Termination failed';
        alert(failMsg + ': ' + (e && e.message ? e.message : String(e)));
    }
}

/**
* Cancel a single MCP tool execution ("Stop" on the monitor page). When conversationId exists, reuses the chat page's "interrupt and continue" dialog and API.
 * @param {string} executionId
 * @param {{ refreshDetail?: boolean }} [options]
 */
async function cancelMCPToolExecution(executionId, options = {}) {
    if (!executionId) {
        return;
    }
    let conversationId = '';
    if (typeof monitorState !== 'undefined' && Array.isArray(monitorState.executions)) {
        const exec = monitorState.executions.find(e => e && e.id === executionId);
        if (exec) {
            conversationId = (exec.conversationId || '').trim();
        }
    }
    if (conversationId && typeof openUserInterruptModal === 'function') {
        openUserInterruptModal(null, conversationId);
        window.__monitorInterruptContext = { executionId: executionId, options: options || {} };
        return;
    }
    openMcpToolAbortModal(executionId, options);
}

// Copy content in the details panel
function copyDetailBlock(elementId, triggerBtn = null) {
    const target = document.getElementById(elementId);
    if (!target) {
        return;
    }
    const text = target.textContent || '';
    if (!text.trim()) {
        return;
    }

    const originalLabel = triggerBtn ? (triggerBtn.dataset.originalLabel || triggerBtn.textContent.trim()) : '';
    if (triggerBtn && !triggerBtn.dataset.originalLabel) {
        triggerBtn.dataset.originalLabel = originalLabel;
    }

    const showCopiedState = () => {
        if (!triggerBtn) {
            return;
        }
        triggerBtn.textContent = 'Copied';
        triggerBtn.disabled = true;
        setTimeout(() => {
            triggerBtn.disabled = false;
            triggerBtn.textContent = triggerBtn.dataset.originalLabel || originalLabel || 'Copy';
        }, 1200);
    };

    const fallbackCopy = (value) => {
        return new Promise((resolve, reject) => {
            const textarea = document.createElement('textarea');
            textarea.value = value;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            try {
                const successful = document.execCommand('copy');
                document.body.removeChild(textarea);
                if (successful) {
                    resolve();
                } else {
                    reject(new Error('execCommand failed'));
                }
            } catch (err) {
                document.body.removeChild(textarea);
                reject(err);
            }
        });
    };

    const copyPromise = (navigator.clipboard && typeof navigator.clipboard.writeText === 'function')
        ? navigator.clipboard.writeText(text)
        : fallbackCopy(text);

    copyPromise
        .then(() => {
            showCopiedState();
        })
        .catch(() => {
            if (triggerBtn) {
                triggerBtn.disabled = false;
                triggerBtn.textContent = triggerBtn.dataset.originalLabel || originalLabel || 'Copy';
            }
            alert('Copy failed; please select the text and copy it manually.');
        });
}


// Start new conversation
async function startNewConversation(options = {}) {
    const hasExplicitProjectId = !!options
        && Object.prototype.hasOwnProperty.call(options, 'projectId');
    const inheritedProjectId = typeof resolveChatProjectSelection === 'function'
        ? resolveChatProjectSelection()
        : (window._loadedConversationProjectId || '');
    const requestedProjectId = hasExplicitProjectId
        ? String(options.projectId || '').trim()
        : String(inheritedProjectId || '').trim();
    markChatConversationNavigation('', true);
    if (typeof window.cancelScheduledChatConversationFromHash === 'function') {
        window.cancelScheduledChatConversationFromHash();
    }
    clearChatConversationHash();
    cancelPendingConversationLoad();
    detachLiveChatStreamForNavigation('', true);
    if (typeof window.cancelRunningTaskEventStream === 'function') {
        window.cancelRunningTaskEventStream('');
    }
    if (typeof window.clearChatHitlApprovalDock === 'function') {
        window.clearChatHitlApprovalDock();
    }
    currentConversationId = null;
    window._loadedConversationProjectId = '';
    try {
        window.currentConversationId = '';
    } catch (e) { /* ignore */ }
    window.dispatchEvent(new CustomEvent('conversation-changed', { detail: { conversationId: '' } }));
    updateChatPrimaryActionState();
    // The top "New task" inherits the current folder; the "+" inside a folder can still be set explicitly (including no project).
    if (typeof setActiveProjectId === 'function') setActiveProjectId(requestedProjectId);
    if (typeof refreshChatProjectSelector === 'function') {
        await refreshChatProjectSelector();
    }
    document.getElementById('chat-messages').innerHTML = '';
    updateChatPrimaryActionState();
    renderChatWelcomeEmptyState();
    addAttackChainButton(null);
    updateActiveConversation();
    // Refresh conversation list to show the latest history
    loadConversations();
    // Clear the debounce timer to prevent saving when restoring a draft
    if (draftSaveTimer) {
        clearTimeout(draftSaveTimer);
        draftSaveTimer = null;
    }
    // Clear the draft; a new conversation should not restore the previous draft
    clearChatDraft();
    // Clear input box
    const chatInput = document.getElementById('chat-input');
    if (chatInput) {
        chatInput.value = '';
        adjustTextareaHeight(chatInput);
    }
    refreshHitlConfigByCurrentConversation();
}

function createConversationListItem(conversation) {
    const item = document.createElement('div');
    item.className = 'conversation-item';
    item.dataset.conversationId = conversation.id;
    if (conversation.id === currentConversationId) {
        item.classList.add('active');
    }

    const contentWrapper = document.createElement('div');
    contentWrapper.className = 'conversation-content';

    const title = document.createElement('div');
    title.className = 'conversation-title';
    const titleText = conversation.title || 'Untitled conversation';
    title.textContent = safeTruncateText(titleText, 60);
    title.title = titleText; // Set the full title so it can be viewed on hover
    contentWrapper.appendChild(title);

    if (!getConversationProjectFilter()) {
        const pid = conversation.projectId || conversation.project_id || '';
        const projectName = pid && window.projectNameById ? window.projectNameById[pid] : '';
        if (projectName) {
            const badge = document.createElement('div');
            badge.className = 'conversation-item-project-badge';
            badge.textContent = projectName;
            badge.title = projectName;
            contentWrapper.appendChild(badge);
        }
    }

    const time = document.createElement('div');
    time.className = 'conversation-time';
    time.textContent = conversation._timeText || formatConversationTimestamp(conversation._time || new Date());
    contentWrapper.appendChild(time);

    item.appendChild(contentWrapper);

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'conversation-delete-btn';
    deleteBtn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6h14zM10 11v6M14 11v6"
                  stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    `;
    deleteBtn.title = 'Delete conversation';
    deleteBtn.onclick = (e) => {
        e.stopPropagation();
        deleteConversation(conversation.id);
    };
    item.appendChild(deleteBtn);

    item.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        const targetConversationId = String(item.dataset.conversationId || '').trim();
        if (targetConversationId) loadConversation(targetConversationId);
    };
    return item;
}

// Handle history search
let conversationSearchTimer = null;
function handleConversationSearch(query) {
    commitConversationsPage(1, { bumpNavigateGen: true });
    conversationsSearchQuery = query || '';
    // Debounce to avoid frequent requests
    if (conversationSearchTimer) {
        clearTimeout(conversationSearchTimer);
    }

    const searchInput = document.getElementById('conversation-search-input');
    const clearBtn = document.getElementById('conversation-search-clear');

    if (clearBtn) {
        if (query && query.trim()) {
            clearBtn.style.display = 'block';
        } else {
            clearBtn.style.display = 'none';
        }
    }

    conversationSearchTimer = setTimeout(() => {
        loadConversations(query);
    }, 300); // 300ms debounce delay
}

// Clear search
function clearConversationSearch() {
    const searchInput = document.getElementById('conversation-search-input');
    const clearBtn = document.getElementById('conversation-search-clear');

    if (searchInput) {
        searchInput.value = '';
    }
    if (clearBtn) {
        clearBtn.style.display = 'none';
    }

    commitConversationsPage(1, { bumpNavigateGen: true });
    conversationsSearchQuery = '';
    loadConversations('');
}

function conversationSidebarText(key, fallback) {
    if (typeof window.t === 'function') {
        const translated = window.t(key);
        if (translated && translated !== key) return translated;
    }
    return fallback;
}

/**
* The Go process embeds index.html. During development, even before the process restarts, the new static JS
* upgrades the old sidebar to the project folder structure; this function stays idempotent when the new template already includes the structure.
 */
function ensureProjectSidebarStructure() {
    const sidebar = document.getElementById('conversation-sidebar');
    const sidebarContent = sidebar && sidebar.querySelector('.sidebar-content');
    if (!sidebar || !sidebarContent) return;

    const newTaskLabel = sidebar.querySelector('.new-chat-btn span:last-child');
    if (newTaskLabel) {
        newTaskLabel.setAttribute('data-i18n', 'chat.newTask');
        newTaskLabel.textContent = conversationSidebarText('chat.newTask', 'New task');
    }

    const searchInput = document.getElementById('conversation-search-input');
    if (searchInput) {
        searchInput.setAttribute('data-i18n', 'projects.searchProjectsPlaceholder');
        searchInput.setAttribute('data-i18n-attr', 'placeholder');
        searchInput.setAttribute('oninput', 'handleProjectFolderSearch(this.value)');
        searchInput.setAttribute('onkeypress', "if(event.key === 'Enter') handleProjectFolderSearch(this.value)");
        searchInput.placeholder = conversationSidebarText('projects.searchProjectsPlaceholder', 'Search projects…');
    }
    const searchClear = document.getElementById('conversation-search-clear');
    if (searchClear) searchClear.setAttribute('onclick', 'clearProjectFolderSearch()');

    const projectFilter = sidebarContent.querySelector('.conversation-project-filter');
    if (projectFilter) projectFilter.hidden = true;

    let projectSection = sidebarContent.querySelector('.project-folders-section');
    const legacyTaskSection = sidebarContent.querySelector('.task-folders-section');
    if (!projectSection && legacyTaskSection) {
        projectSection = legacyTaskSection;
        projectSection.className = 'project-folders-section';
        projectSection.setAttribute('aria-labelledby', 'project-folders-title');
        const legacyHeader = projectSection.querySelector('.task-folders-header');
        if (legacyHeader) legacyHeader.className = 'section-header project-folders-header';
        const legacyTitle = projectSection.querySelector('#task-folders-title');
        if (legacyTitle) {
            legacyTitle.id = 'project-folders-title';
            legacyTitle.setAttribute('data-i18n', 'chat.projectFolders');
            legacyTitle.textContent = conversationSidebarText('chat.projectFolders', 'Projects');
        }
        const legacyList = projectSection.querySelector('#task-folders-list');
        if (legacyList) {
            legacyList.id = 'project-folders-list';
            legacyList.className = 'project-folders-list';
            legacyList.removeAttribute('role');
            legacyList.innerHTML = '';
        }
    }
    if (!projectSection) {
        projectSection = document.createElement('section');
        projectSection.className = 'project-folders-section';
        projectSection.setAttribute('aria-labelledby', 'project-folders-title');
        projectSection.innerHTML =
            '<div class="section-header project-folders-header">' +
                '<span id="project-folders-title" class="section-title" data-i18n="chat.projectFolders">Projects</span>' +
                '<button type="button" class="add-group-btn project-folders-add-btn" data-require-permission="project:write" onclick="showNewProjectModalFromChatSidebar()" data-i18n="projects.newProject" data-i18n-attr="title,aria-label" data-i18n-skip-text="true" title="New project" aria-label="New project">' +
                    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
                '</button>' +
            '</div>' +
            '<div id="project-folders-list" class="project-folders-list"></div>';
        const searchBox = sidebarContent.querySelector('.conversation-search-box');
        if (searchBox) searchBox.insertAdjacentElement('afterend', projectSection);
        else sidebarContent.insertBefore(projectSection, sidebarContent.firstChild);
    }

    const projectHeader = projectSection.querySelector('.project-folders-header');
    if (projectHeader && !projectHeader.querySelector('.project-folders-add-btn')) {
        const addProjectButton = document.createElement('button');
        addProjectButton.type = 'button';
        addProjectButton.className = 'add-group-btn project-folders-add-btn';
        addProjectButton.dataset.requirePermission = 'project:write';
        addProjectButton.setAttribute('onclick', 'showNewProjectModalFromChatSidebar()');
        addProjectButton.setAttribute('data-i18n', 'projects.newProject');
        addProjectButton.setAttribute('data-i18n-attr', 'title,aria-label');
        addProjectButton.setAttribute('data-i18n-skip-text', 'true');
        addProjectButton.title = conversationSidebarText('projects.newProject', 'New project');
        addProjectButton.setAttribute('aria-label', addProjectButton.title);
        addProjectButton.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
        projectHeader.appendChild(addProjectButton);
    }

    const recentSection = sidebarContent.querySelector('.recent-conversations-section');
    if (recentSection) {
        recentSection.id = 'recent-conversations-section';
        recentSection.classList.add('is-collapsed');
        let toggle = document.getElementById('recent-conversations-toggle');
        let body = document.getElementById('recent-conversations-body');
        if (!toggle) {
            const oldHeader = recentSection.querySelector(':scope > .section-header');
            const title = oldHeader && oldHeader.querySelector('.section-title');
            const actions = oldHeader && oldHeader.querySelector('.section-header-actions');
            const list = recentSection.querySelector('#conversations-list');

            toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.id = 'recent-conversations-toggle';
            toggle.className = 'section-header recent-conversations-toggle';
            toggle.setAttribute('aria-expanded', 'false');
            toggle.setAttribute('aria-controls', 'recent-conversations-body');
            toggle.setAttribute('data-i18n', 'chat.toggleRecentConversations');
            toggle.setAttribute('data-i18n-attr', 'title,aria-label');
            toggle.setAttribute('data-i18n-skip-text', 'true');
            toggle.title = conversationSidebarText('chat.toggleRecentConversations', 'Expand/collapse recent conversations');
            toggle.setAttribute('aria-label', toggle.title);
            toggle.addEventListener('click', toggleRecentConversations);
            if (title) toggle.appendChild(title);
            else toggle.innerHTML = '<span class="section-title" data-i18n="chat.recentConversations">Recent conversations</span>';

            const meta = document.createElement('span');
            meta.className = 'recent-conversations-toggle-meta';
            meta.innerHTML =
                '<span id="recent-conversations-count" class="recent-conversations-count">0</span>' +
                '<svg class="recent-conversations-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M9 18l6-6-6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
            toggle.appendChild(meta);

            body = document.createElement('div');
            body.id = 'recent-conversations-body';
            body.className = 'recent-conversations-body';
            body.hidden = true;
            if (actions) {
                actions.classList.add('recent-conversations-actions');
                body.appendChild(actions);
            }
            if (list) body.appendChild(list);
            if (oldHeader) oldHeader.remove();
            recentSection.prepend(toggle);
            recentSection.appendChild(body);
        }
    }

    if (typeof window.applyTranslations === 'function') {
        window.applyTranslations(sidebar);
    }
}

function setRecentConversationsExpanded(expanded, options = {}) {
    const section = document.getElementById('recent-conversations-section');
    const toggle = document.getElementById('recent-conversations-toggle');
    const body = document.getElementById('recent-conversations-body');
    const pagination = document.getElementById('conversations-pagination');
    const open = !!expanded;
    if (section) section.classList.toggle('is-collapsed', !open);
    if (toggle) toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (body) body.hidden = !open;
    if (pagination) pagination.hidden = !open;
    if (options.persist !== false) {
        try {
            localStorage.setItem(RECENT_CONVERSATIONS_EXPANDED_KEY, open ? '1' : '0');
        } catch (e) { /* ignore */ }
    }
}

function restoreRecentConversationsState() {
    let expanded = false;
    try {
        expanded = localStorage.getItem(RECENT_CONVERSATIONS_EXPANDED_KEY) === '1';
    } catch (e) { /* ignore */ }
    setRecentConversationsExpanded(expanded, { persist: false });
}

function toggleRecentConversations() {
    const toggle = document.getElementById('recent-conversations-toggle');
    const expanded = toggle && toggle.getAttribute('aria-expanded') === 'true';
    setRecentConversationsExpanded(!expanded);
}

function updateRecentConversationsCount(total) {
    const count = document.getElementById('recent-conversations-count');
    if (count) count.textContent = String(Math.max(0, Number(total) || 0));
}

if (typeof window !== 'undefined') {
    window.toggleRecentConversations = toggleRecentConversations;
    window.setRecentConversationsExpanded = setRecentConversationsExpanded;
}

function formatConversationTimestamp(dateObj, todayStart, yesterdayStart) {
    if (!(dateObj instanceof Date) || isNaN(dateObj.getTime())) {
        return '';
    }
    // If todayStart is not passed, use the current date as the reference
    const now = new Date();
    const referenceToday = todayStart || new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const referenceYesterday = yesterdayStart || new Date(referenceToday.getTime() - 24 * 60 * 60 * 1000);
    const messageDate = new Date(dateObj.getFullYear(), dateObj.getMonth(), dateObj.getDate());
    const fmtLocale = (typeof window.uiLocale === 'function' ? window.uiLocale() : 'en-US');
    const yesterdayLabel = typeof window.t === 'function' ? window.t('chat.yesterday') : 'Yesterday';

    const timeOnlyOpts = { hour: '2-digit', minute: '2-digit' };
    const dateTimeOpts = { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    const fullDateOpts = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    if (fmtLocale === 'zh-CN' || fmtLocale === 'ru-RU') {
        timeOnlyOpts.hour12 = false;
        dateTimeOpts.hour12 = false;
        fullDateOpts.hour12 = false;
    }
    if (messageDate.getTime() === referenceToday.getTime()) {
        return dateObj.toLocaleTimeString(fmtLocale, timeOnlyOpts);
    }
    if (messageDate.getTime() === referenceYesterday.getTime()) {
        return yesterdayLabel + ' ' + dateObj.toLocaleTimeString(fmtLocale, timeOnlyOpts);
    }
    if (dateObj.getFullYear() === referenceToday.getFullYear()) {
        return dateObj.toLocaleString(fmtLocale, dateTimeOpts);
    }
    return dateObj.toLocaleString(fmtLocale, fullDateOpts);
}

function getConversationGroup(dateObj, todayStart, sevenDaysCutoff, yesterdayStart) {
    if (!(dateObj instanceof Date) || isNaN(dateObj.getTime())) {
        return 'earlier';
    }
    const today = new Date(todayStart.getFullYear(), todayStart.getMonth(), todayStart.getDate());
    const yesterday = new Date(yesterdayStart.getFullYear(), yesterdayStart.getMonth(), yesterdayStart.getDate());
    const messageDay = new Date(dateObj.getFullYear(), dateObj.getMonth(), dateObj.getDate());

    if (messageDay.getTime() === today.getTime() || messageDay > today) {
        return 'today';
    }
    if (messageDay.getTime() === yesterday.getTime()) {
        return 'yesterday';
    }
    const cutoff = new Date(sevenDaysCutoff.getFullYear(), sevenDaysCutoff.getMonth(), sevenDaysCutoff.getDate());
    if (messageDay >= cutoff && messageDay < yesterday) {
        return 'last7Days';
    }
    return 'earlier';
}

// Load conversation
/** After a lightweight load, fetch process details only for "Processing…" placeholder replies (non-SSE scenarios such as bots); completed conversations are not prefetched in full */
async function prefetchLastAssistantProcessDetails() {
    const nodes = document.querySelectorAll('#chat-messages .message.assistant');
    if (!nodes.length) return;
    const last = nodes[nodes.length - 1];
    if (!last || !last.id) return;
    const bubble = last.querySelector('.message-bubble');
    const visibleText = bubble ? String(bubble.textContent || '').trim() : '';
    const isPlaceholder = visibleText === 'Processing...' || visibleText === 'Processing...';
    if (!isPlaceholder) return;
    const container = document.getElementById('process-details-' + last.id);
    if (!container || container.dataset.lazyNotLoaded !== '1') return;
    const backendId = last.dataset && last.dataset.backendMessageId;
    if (!backendId || typeof apiFetch !== 'function') return;
    if (typeof window.loadProcessDetailsPaginated === 'function') {
        await window.loadProcessDetailsPaginated(last.id, backendId);
        return;
    }
    const res = await apiFetch('/api/messages/' + encodeURIComponent(String(backendId)) + '/process-details?full=1');
    const j = await res.json().catch(() => ({}));
    if (!res.ok || !Array.isArray(j.processDetails) || j.processDetails.length === 0) return;
    if (typeof renderProcessDetails === 'function') {
        renderProcessDetails(last.id, j.processDetails);
    }
}

async function hydrateConversationTokenUsage(conversationId, expectedSeq, signal) {
    const id = String(conversationId || '').trim();
    if (!id || typeof apiFetch !== 'function' || typeof window.setAssistantTurnTokenUsage !== 'function') return;
    if (signal && signal.aborted) return;
    const params = new URLSearchParams();
    params.set('since', '1970-01-01');
    params.set('limit', '500');
    const res = await apiFetch(
        '/api/conversations/' + encodeURIComponent(id) + '/token-usage?' + params.toString(),
        signal ? { signal: signal } : undefined
    );
    const payload = await res.json().catch(() => ({}));
    if (!res.ok || (signal && signal.aborted)) return;
    if (expectedSeq != null && expectedSeq !== loadConversationRequestSeq) return;
    if (currentConversationId !== id) return;
    const rows = Array.isArray(payload && payload.recent) ? payload.recent : [];
    if (rows.length === 0) return;
    const byMessage = new Map();
    rows.forEach((row) => {
        const messageId = row && row.messageId != null ? String(row.messageId).trim() : '';
        if (!messageId) return;
        const usage = normalizeAssistantTurnTokenUsage(row);
        if (!usage) return;
        byMessage.set(messageId, mergeAssistantTurnTokenUsage(byMessage.get(messageId) || null, usage));
    });
    if (byMessage.size === 0) return;
    document.querySelectorAll('#chat-messages .message.assistant[data-backend-message-id]').forEach((messageElement) => {
        const backendMessageId = messageElement && messageElement.dataset
            ? String(messageElement.dataset.backendMessageId || '').trim()
            : '';
        const usage = backendMessageId ? byMessage.get(backendMessageId) : null;
        if (usage) {
            window.setAssistantTurnTokenUsage(messageElement, usage);
        }
    });
}

async function loadConversation(conversationId) {
    conversationId = String(conversationId || '').trim();
    if (!conversationId) return;
    // Keep the visible conversation addressable across a full page refresh.
    // Sidebar/project entries call loadConversation directly (rather than the
    // router helper), so without this synchronization #chat loses the active
    // conversation and reload falls back to the welcome screen instead of
    // reconnecting the running task event stream.
    markChatConversationNavigation(conversationId);
    if (typeof window.cancelScheduledChatConversationFromHash === 'function') {
        window.cancelScheduledChatConversationFromHash();
    }
    syncChatConversationHash(conversationId);
    const seq = ++loadConversationRequestSeq;
    const previousConversationId = currentConversationId;
    cancelPendingConversationLoad();
    detachLiveChatStreamForNavigation(conversationId);
    // A user click means a new visible conversation. This selection must be committed before any network wait,
    // otherwise the active-task refresh every 2 seconds would still treat the old conversation as visible and queue a reload of the old catch-up stream,
    // which would in turn cancel this switch.
    currentConversationId = conversationId;
    try {
        window.currentConversationId = conversationId;
    } catch (e) { /* ignore */ }
    loadConversationPendingId = conversationId;
    const conversationLoadController = new AbortController();
    loadConversationAbortController = conversationLoadController;
    if (typeof window.selectChatProjectConversationItem === 'function') {
        window.selectChatProjectConversationItem(conversationId);
    }
    if (typeof window.cancelRunningTaskEventStream === 'function') {
        window.cancelRunningTaskEventStream(conversationId);
    }
    if (typeof window.clearChatHitlApprovalDock === 'function') {
        window.clearChatHitlApprovalDock();
    }
    try {
        const cachedConversation = getConversationLiteFromCache(conversationId);
        let conversation = null;
        let response = null;
        try {
            response = await apiFetch(`/api/conversations/${conversationId}?include_process_details=0`, {
                signal: conversationLoadController.signal
            });
            conversation = await response.json();
        } catch (fetchError) {
            if (fetchError && fetchError.name === 'AbortError') return;
            if (!cachedConversation) throw fetchError;
            console.warn('Failed to load latest conversation; using local cache:', fetchError);
            conversation = cachedConversation;
        }
        if (seq !== loadConversationRequestSeq) {
            return;
        }
        if (response && !response.ok) {
            if (seq === loadConversationRequestSeq) {
                currentConversationId = previousConversationId;
                try {
                    window.currentConversationId = previousConversationId || '';
                } catch (e) { /* ignore */ }
                if (previousConversationId) syncChatConversationHash(previousConversationId);
                else clearChatConversationHash();
            }
            showChatToast('Failed to load conversation: ' + (conversation.error || 'Unknown error'), 'error');
            return;
        }
        if (response && response.ok) {
            putConversationLiteCache(conversationId, conversation);
        }
        if (seq !== loadConversationRequestSeq) {
            return;
        }

        // Update current conversation ID
        currentConversationId = conversationId;
        window._loadedConversationProjectId = conversation.projectId || conversation.project_id || '';
        const conversationRoleName = conversation.roleName || conversation.role_name || '';
        if (typeof window.setCurrentRole === 'function') {
            window.setCurrentRole(conversationRoleName || 'default');
        }
        applyConversationAgentMode(conversationId, conversation);
        try {
            window.currentConversationId = conversationId;
        } catch (e) { /* ignore */ }
        window.dispatchEvent(new CustomEvent('conversation-changed', { detail: { conversationId: conversationId } }));
        updateChatPrimaryActionState();
        if (typeof refreshChatProjectSelector === 'function') {
            refreshChatProjectSelector({ reloadFolders: false, renderFolders: false });
        }
        refreshHitlConfigByCurrentConversation();
        const hitlSyncPromise = (typeof window.syncHitlConfigFromServer === 'function')
            ? window.syncHitlConfigFromServer(conversationId).then(() => {
                if (seq === loadConversationRequestSeq && currentConversationId === conversationId) {
                    refreshHitlConfigByCurrentConversation();
                }
            }).catch(() => {})
            : Promise.resolve();
        hitlConfigSyncConversationId = conversationId;
        hitlConfigSyncPromise = Promise.resolve(hitlSyncPromise);
        await hitlConfigSyncPromise;
        if (seq !== loadConversationRequestSeq || currentConversationId !== conversationId) {
            return;
        }
        updateActiveConversation();

        // If the attack chain modal is open and shows a different conversation, close it
        const attackChainModal = document.getElementById('attack-chain-modal');
        if (attackChainModal && isAppModalOpen('attack-chain-modal')) {
            if (currentAttackChainConversationId !== conversationId) {
                closeAttackChainModal();
            }
        }

        // Clear message area
        const messagesDiv = document.getElementById('chat-messages');
        if (seq !== loadConversationRequestSeq) {
            return;
        }
        messagesDiv.innerHTML = '';

        // Check whether there are recent messages in the conversation; if so, clear the draft (to avoid restoring already-sent messages)
        let hasRecentUserMessage = false;
        if (conversation.messages && conversation.messages.length > 0) {
            const lastMessage = conversation.messages[conversation.messages.length - 1];
            if (lastMessage && lastMessage.role === 'user') {
                // Check message time; if within the last 30 seconds, clear the draft
                const messageTime = new Date(lastMessage.createdAt);
                const now = new Date();
                const timeDiff = now.getTime() - messageTime.getTime();
                if (timeDiff < 30000) { // within 30 seconds
                    hasRecentUserMessage = true;
                }
            }
        }
        if (hasRecentUserMessage) {
            // If there is a recently sent user message, clear the draft
            clearChatDraft();
            const chatInput = document.getElementById('chat-input');
            if (chatInput) {
                chatInput.value = '';
                adjustTextareaHeight(chatInput);
            }
        }

        // Load messages — render in batches to avoid blocking the main thread for long
        if (conversation.messages && conversation.messages.length > 0) {
            const FIRST_BATCH = 20;  // First batch rendered synchronously (user-visible area)
            const BATCH_SIZE = 10;   // Items per subsequent batch

            // Helper to render a single message
            let lastAssistantBackendId = '';
            for (let mi = conversation.messages.length - 1; mi >= 0; mi--) {
                if (conversation.messages[mi] && conversation.messages[mi].role === 'assistant') {
                    lastAssistantBackendId = conversation.messages[mi].id || '';
                    break;
                }
            }
            const renderOneMessage = (msg) => {
                if (msg.role === 'user' && isInterruptContinueInjectChatMessage(msg.content)) {
                    return;
                }
                const assistantContent = String(msg && msg.content != null ? msg.content : '').trim();
                const terminalState = msg && msg.role === 'assistant'
                    ? assistantTurnTerminalState(msg.processDetails)
                    : null;
                let displayContent = msg.content;
                if (msg.role === 'assistant' &&
                    (assistantContent === 'Processing...' || assistantContent === 'Processing...') && terminalState) {
                    displayContent = terminalState.detail.message || msg.content;
                }

                // Message time basis:
                // - user: createdAt is enough (it is not updated after sending)
                // - assistant: if the backend provides updatedAt (written back when the task completes), prefer it, to avoid placeholder messages misleading with the "task start time"
                const msgTime = (msg && msg.role === 'assistant' && msg.updatedAt) ? msg.updatedAt : (msg ? msg.createdAt : null);
                const mcpIds = (msg.mcpExecutionIds && Array.isArray(msg.mcpExecutionIds)) ? msg.mcpExecutionIds : [];
                const isAssistantPlaceholder = msg.role === 'assistant' && (
                    assistantContent === 'Processing...' || assistantContent === 'Processing...'
                );
                const addOpts = (msg.role === 'assistant' && (mcpIds.length > 0 || isAssistantPlaceholder))
                    ? {
                        deferMcpButtons: mcpIds.length > 0,
                        hideAssistantPlaceholder: isAssistantPlaceholder
                    }
                    : null;
                const messageId = addMessage(msg.role, displayContent, mcpIds, null, msgTime, addOpts);
                const messageEl = document.getElementById(messageId);
                if (messageEl && msg && msg.id) {
                    messageEl.dataset.backendMessageId = String(msg.id);
                    attachDeleteTurnButton(messageEl);
                }
                if (msg.role === 'assistant') {
                    if (messageEl && typeof window.setAssistantTurnTiming === 'function') {
                        const startedAt = msg && msg.createdAt ? msg.createdAt : null;
                        const completedAt = terminalState && terminalState.completedAt
                            ? terminalState.completedAt
                            : (msg && msg.updatedAt ? msg.updatedAt : startedAt);
                        const startedMs = assistantTurnTimestamp(startedAt);
                        const completedMs = assistantTurnTimestamp(completedAt);
                        const isRunning = isAssistantPlaceholder && !terminalState;
                        const status = terminalState ? terminalState.status : (isRunning ? 'running' : 'completed');
                        window.setAssistantTurnTiming(messageEl, {
                            startedAt: startedAt,
                            completedAt: isRunning ? null : completedAt,
                            durationMs: (!isRunning && Number.isFinite(startedMs) && Number.isFinite(completedMs))
                                ? Math.max(0, completedMs - startedMs)
                                : undefined,
                            status: status
                        });
                    }
                    if (messageEl && msg.reasoningContent) {
                        setMessageReasoningContent(messageEl, msg.reasoningContent);
                    }
                    const hasField = msg && Object.prototype.hasOwnProperty.call(msg, 'processDetails');
                    renderProcessDetails(messageId, hasField ? (msg.processDetails || []) : null);
                    if (messageEl && msg && msg.id && msg.id === lastAssistantBackendId) {
                        maybeShowContinueButton(messageEl, msg.id, hasField ? (msg.processDetails || []) : null, assistantContent);
                    }
                    if (msg.processDetails && msg.processDetails.length > 0) {
                        const hasErrorOrCancelled = msg.processDetails.some(d =>
                            d.eventType === 'error' || d.eventType === 'cancelled'
                        );
                        if (hasErrorOrCancelled) {
                            collapseAllProgressDetails(messageId, null);
                        }
                    }
                }
            };

            const msgs = conversation.messages;
            const firstBatch = msgs.slice(0, FIRST_BATCH);
            const rest = msgs.slice(FIRST_BATCH);

            let pendingMessageBatches = Promise.resolve();

            // First batch rendered synchronously
            firstBatch.forEach(renderOneMessage);

            // Remaining messages are rendered in batches via requestAnimationFrame to avoid blocking the UI
            if (rest.length > 0) {
                const savedConvId = conversationId;
                const savedSeq = seq;
                pendingMessageBatches = new Promise((resolve) => {
                    let offset = 0;
                    const renderNextBatch = () => {
                        if (savedSeq !== loadConversationRequestSeq || currentConversationId !== savedConvId) {
                            resolve();
                            return;
                        }
                        const batch = rest.slice(offset, offset + BATCH_SIZE);
                        batch.forEach(renderOneMessage);
                        offset += BATCH_SIZE;
                        if (offset < rest.length) {
                            requestAnimationFrame(renderNextBatch);
                        } else {
                            if (window.VeritySecChatScroll) {
                                window.VeritySecChatScroll.forceScrollToBottom(false);
                            } else {
                                messagesDiv.scrollTop = messagesDiv.scrollHeight;
                            }
                            resolve();
                        }
                    };
                    requestAnimationFrame(renderNextBatch);
                });
            }

            if (window.VeritySecChatScroll) {
                window.VeritySecChatScroll.forceScrollToBottom(false);
            } else {
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
            addAttackChainButton(conversationId);
            await pendingMessageBatches;
            if (seq !== loadConversationRequestSeq) {
                return;
            }
            hydrateConversationTokenUsage(conversationId, seq, conversationLoadController.signal).catch((e) => {
                if (!e || e.name !== 'AbortError') {
                    console.warn('hydrateConversationTokenUsage failed', e);
                }
            });
            if (currentConversationId === conversationId && typeof window.restoreHitlInlineForConversation === 'function') {
                await window.restoreHitlInlineForConversation(conversationId);
            }
            if (
                window.VeritySecChatScroll &&
                typeof window.VeritySecChatScroll.settleConversationRestoreToBottom === 'function'
            ) {
                window.VeritySecChatScroll.settleConversationRestoreToBottom(30);
            }
        } else {
            renderChatWelcomeEmptyState();
            if (window.VeritySecChatScroll) {
                window.VeritySecChatScroll.forceScrollToBottom(false);
            } else {
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
            addAttackChainButton(conversationId);
            if (seq !== loadConversationRequestSeq) {
                return;
            }
            if (currentConversationId === conversationId && typeof window.restoreHitlInlineForConversation === 'function') {
                await window.restoreHitlInlineForConversation(conversationId);
            }
        }

        // A branch may have been created while the network or navigation
        // interrupted its automatic send. Restore its own persisted prompt.
        const pendingRetestPrompt = conversation.retest && conversation.retest.pending_prompt;
        const retestInput = document.getElementById('chat-input');
        if (seq === loadConversationRequestSeq && currentConversationId === conversationId && pendingRetestPrompt && retestInput &&
            (previousConversationId !== conversationId || !retestInput.value.trim())) {
            retestInput.value = pendingRetestPrompt;
            adjustTextareaHeight(retestInput);
        }

        // After a page refresh the main streaming connection is interrupted; if the conversation is still running on the backend, automatically attach the task-events catch-up stream to keep updating the frontend iteration progress.
        const skipReplay = typeof window.shouldSkipTaskEventReplayAttach === 'function'
            && window.shouldSkipTaskEventReplayAttach(conversationId);
        if (
            seq === loadConversationRequestSeq &&
            currentConversationId === conversationId &&
            typeof window.attachRunningTaskEventStream === 'function' &&
            !skipReplay
        ) {
            Promise.resolve()
                .then(() => window.attachRunningTaskEventStream(conversationId))
                .catch((e) => {
                    console.warn('attachRunningTaskEventStream on loadConversation failed', e);
                });
        } else if (seq === loadConversationRequestSeq && currentConversationId === conversationId) {
            // Non-web streaming sources such as bots: when the conversation has ended or no task is registered, fetch the process details of the last assistant message on demand
            prefetchLastAssistantProcessDetails().catch((e) => {
                console.warn('prefetchLastAssistantProcessDetails failed', e);
            });
        }
    } catch (error) {
        if (error && error.name === 'AbortError') return;
        if (seq === loadConversationRequestSeq) {
            currentConversationId = previousConversationId;
            try {
                window.currentConversationId = previousConversationId || '';
            } catch (e) { /* ignore */ }
            if (previousConversationId) syncChatConversationHash(previousConversationId);
            else clearChatConversationHash();
            if (typeof window.selectChatProjectConversationItem === 'function') {
                window.selectChatProjectConversationItem(previousConversationId);
            }
        }
        console.error('Failed to load conversation:', error);
        showChatToast('Failed to load conversation: ' + (error && error.message ? error.message : String(error)), 'error');
    } finally {
        if (seq === loadConversationRequestSeq && typeof window.finishChatConversationRestore === 'function') {
            window.finishChatConversationRestore(conversationId);
        }
        if (loadConversationAbortController === conversationLoadController) {
            loadConversationAbortController = null;
        }
        if (seq === loadConversationRequestSeq && loadConversationPendingId === conversationId) {
            loadConversationPendingId = '';
        }
    }
}

/** "Delete this turn": on the same line as the timestamp (message-meta-footer), styled differently from the copy button area */
function attachDeleteTurnButton(messageEl) {
    if (!messageEl || !messageEl.dataset.backendMessageId) return;
    if (messageEl.querySelector('.message-delete-turn-btn')) return;
    const content = messageEl.querySelector('.message-content');
    if (!content) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'message-delete-turn-btn';
    const title = typeof window.t === 'function' ? window.t('chat.deleteTurnTitle') : 'Delete this turn';
    btn.title = title;
    btn.setAttribute('aria-label', title);
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6h14zM10 11v6M14 11v6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    btn.onclick = function (e) {
        e.stopPropagation();
        e.preventDefault();
        deleteConversationTurnFromUI(messageEl.dataset.backendMessageId);
    };
    const timeDiv = content.querySelector('.message-time');
    let footer = content.querySelector('.message-meta-footer');
    if (!footer && timeDiv && timeDiv.parentNode === content) {
        footer = document.createElement('div');
        footer.className = 'message-meta-footer';
        timeDiv.parentNode.insertBefore(footer, timeDiv);
        footer.appendChild(timeDiv);
    }
    if (footer) {
        footer.appendChild(btn);
    } else {
        content.appendChild(btn);
    }
}

/** Delete the whole turn containing the anchor (backend: from this turn's user message up to the next user message), and clear the ReAct snapshot */
async function deleteConversationTurnFromUI(anchorBackendMessageId) {
    if (!currentConversationId || !anchorBackendMessageId) return;
    const confirmMsg = typeof window.t === 'function' ? window.t('chat.deleteTurnConfirm') : 'Delete this turn?';
    if (!confirm(confirmMsg)) return;
    try {
        const response = await apiFetch(`/api/conversations/${currentConversationId}/delete-turn`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ messageId: anchorBackendMessageId })
        });
        let data = {};
        try {
            data = await response.json();
        } catch (e) { /* ignore */ }
        if (!response.ok) {
            throw new Error(data.error || data.message || 'delete failed');
        }
        invalidateConversationLiteCache(currentConversationId);
        await loadConversation(currentConversationId);
        if (typeof loadConversations === 'function') {
            loadConversations();
        }
    } catch (error) {
        console.error('delete turn failed:', error);
        const failed = typeof window.t === 'function' ? window.t('chat.deleteTurnFailed') : 'Failed to delete this turn';
        alert(failed + ': ' + (error && error.message ? error.message : error));
    }
}

// Delete conversation
async function deleteConversation(conversationId, skipConfirm = false) {
    // Confirm deletion (unless the caller skipped confirmation)
    if (!skipConfirm) {
        if (!confirm('Delete this conversation? Its messages cannot be recovered, but recorded vulnerabilities will be kept in the vulnerability library.')) {
            return;
        }
    }

    try {
        const response = await apiFetch(`/api/conversations/${conversationId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Delete failed');
        }

        // If the deleted conversation is the current one, clear the conversation view
        if (conversationId === currentConversationId) {
            currentConversationId = null;
            try {
                window.currentConversationId = '';
            } catch (e) { /* ignore */ }
            document.getElementById('chat-messages').innerHTML = '';
            renderChatWelcomeEmptyState();
            addAttackChainButton(null);
        }

        invalidateConversationLiteCache(conversationId);

        // Sync local state of all sidebars first, then perform the network refresh. Project folders use an independent
        // conversation cache; if only "Recent conversations" is refreshed, the deleted item would remain until a full page refresh.
        try {
            document.dispatchEvent(new CustomEvent('conversation-deleted', { detail: { conversationId } }));
        } catch (e) { /* ignore */ }

        // Refresh conversation list
        if (typeof loadConversations === 'function') {
            loadConversations();
        }

        // When the batch management dialog is open, refresh its list as well
        const batchModal = document.getElementById('batch-manage-modal');
        if (batchModal && isAppModalOpen('batch-manage-modal')) {
            allConversationsForBatch = allConversationsForBatch.filter(c => c.id !== conversationId);
            applyBatchConversationFilters();
        }

    } catch (error) {
        console.error('Failed to delete conversation:', error);
        alert('Failed to delete conversation: ' + error.message);
    }
}

// Update active conversation style
function updateActiveConversation() {
    document.querySelectorAll('.conversation-item').forEach(item => {
        item.classList.remove('active');
        if (currentConversationId && item.dataset.conversationId === currentConversationId) {
            item.classList.add('active');
        }
    });
}

// ==================== Attack chain visualization ====================

let attackChainRequestSequence = 0;
const attackChainRequestOwners = new Map();

function beginAttackChainRequest(conversationId) {
    const requestSequence = ++attackChainRequestSequence;
    attackChainRequestOwners.set(conversationId, requestSequence);
    return requestSequence;
}

function isCurrentAttackChainRequest(conversationId, requestSequence) {
    return currentAttackChainConversationId === conversationId && attackChainRequestSequence === requestSequence;
}

function finishAttackChainRequest(conversationId, requestSequence) {
    if (attackChainRequestOwners.get(conversationId) === requestSequence) {
        attackChainRequestOwners.delete(conversationId);
        setAttackChainLoading(conversationId, false);
    }
}

// Generate data URL for node icons (used for Cytoscape background-image)
// Returns a polished gradient square with a white vector icon
function _acBuildNodeIconDataUrl(iconType, color, colorDark) {
    let iconPath = '';
    if (iconType === 'target') {
        iconPath = 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm0-14c-3.31 0-6 2.69-6 6s2.69 6 6 6 6-2.69 6-6-2.69-6-6-6zm0 10c-2.21 0-4-1.79-4-4s1.79-4 4-4 4 1.79 4 4-1.79 4-4 4z';
    } else if (iconType === 'action') {
        iconPath = 'M7 2v11h3v9l7-12h-4l4-8z';
    } else if (iconType === 'vulnerability') {
        iconPath = 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v6h-2V7zm0 8h2v2h-2v-2z';
    } else {
        iconPath = 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z';
    }
    // 64x64 icon square (gradient + rounded corners + white vector icon)
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
<defs>
<linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
<stop offset="0%" stop-color="${color}"/>
<stop offset="100%" stop-color="${colorDark}"/>
</linearGradient>
</defs>
<rect x="0" y="0" width="64" height="64" rx="14" fill="url(#g)"/>
<g transform="translate(14 14) scale(1.5)"><path d="${iconPath}" fill="#FFFFFF"/></g>
</svg>`;
    // Use base64 encoding (btoa is natively supported in browsers)
    try {
        return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));
    } catch (e) {
        // Fallback: URL encoding
        return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
    }
}

let attackChainCytoscape = null;
let currentAttackChainConversationId = null;
// Manage loading state per conversation ID, decoupling different conversations
const attackChainLoadingMap = new Map(); // Map<conversationId, boolean>

// Check whether the specified conversation is loading
function isAttackChainLoading(conversationId) {
    return attackChainLoadingMap.get(conversationId) === true;
}

// Set loading state of the specified conversation
function setAttackChainLoading(conversationId, loading) {
    if (loading) {
        attackChainLoadingMap.set(conversationId, true);
    } else {
        attackChainLoadingMap.delete(conversationId);
    }
}

// Add attack chain button (moved to the menu; this function is kept for compatibility but no longer shows the top button)
function addAttackChainButton(conversationId) {
    // The attack chain button has moved to the three-dot menu; the top button is no longer needed
    // This function is kept for code compatibility but no longer does anything
    const conversationHeader = document.getElementById('conversation-header');
    if (conversationHeader) {
        conversationHeader.style.display = 'none';
    }
}

function updateAttackChainAvailability() {
    addAttackChainButton(currentConversationId);
}

function resetAttackChainContext() {
    if (attackChainCytoscape) {
        attackChainCytoscape.destroy();
        attackChainCytoscape = null;
    }
    window.attackChainOriginalData = null;
    if (window.VeritySecAttackChainContext) window.VeritySecAttackChainContext.clear();
}

function renderAttackChainError(container, message) {
    if (!container) return;
    const errorElement = document.createElement('div');
    errorElement.className = 'error-message';
    errorElement.textContent = message;
    container.replaceChildren(errorElement);
}

// window.t escapes interpolation for innerHTML; these go to textContent, so opt out.
function attackChainFailureText(key, fallbackPrefix, message) {
    if (typeof window.t !== 'function') return fallbackPrefix + message;
    return window.t(key, { message, interpolation: { escapeValue: false } });
}

// Show attack chain modal
async function showAttackChain(conversationId) {
    // If the displayed conversation ID differs, or nothing is loading, allow opening
    // If the same conversation is loading, still allow opening (showing the loading state)
    if (isAttackChainLoading(conversationId) && currentAttackChainConversationId === conversationId) {
        // If the modal is already open and showing the same conversation, do not open it again
        const modal = document.getElementById('attack-chain-modal');
        if (modal && isAppModalOpen('attack-chain-modal')) {
            console.log('Attack chain is loading; the modal is already open');
            return;
        }
    }

    currentAttackChainConversationId = conversationId;
    // Reopening or returning to a conversation starts a fresh view, even if an old request is pending.
    attackChainRequestSequence += 1;
    attackChainRequestOwners.delete(conversationId);
    setAttackChainLoading(conversationId, false);
    resetAttackChainContext();
    const modal = document.getElementById('attack-chain-modal');
    if (!modal) {
        console.error('Attack chain modal not found');
        return;
    }

    openAppModal('attack-chain-modal', { focus: false });
    updateAttackChainStats({ nodes: [], edges: [] });

    // Clear container
    const container = document.getElementById('attack-chain-container');
    if (container) {
        container.innerHTML = '<div class="loading-spinner">' + (typeof window.t === 'function' ? window.t('chat.loading') : 'Loading...') + '</div>';
    }

    // Hide details panel
    const detailsPanel = document.getElementById('attack-chain-details');
    if (detailsPanel) {
        detailsPanel.style.display = 'none';
    }
    const sidebar = document.querySelector('.attack-chain-sidebar');
    if (sidebar) sidebar.classList.remove('details-active');

    // Disable regenerate button
    const regenerateBtn = document.querySelector('button[onclick="regenerateAttackChain()"]');
    if (regenerateBtn) {
        regenerateBtn.disabled = true;
        regenerateBtn.style.opacity = '0.5';
        regenerateBtn.style.cursor = 'not-allowed';
    }

    // Load attack chain data
    await loadAttackChain(conversationId);
}

// Load attack chain data
async function loadAttackChain(conversationId) {
    if (isAttackChainLoading(conversationId)) {
        return; // Prevent duplicate calls
    }

    setAttackChainLoading(conversationId, true);
    const requestSequence = beginAttackChainRequest(conversationId);
    if (currentAttackChainConversationId === conversationId) {
        resetAttackChainContext();
        const container = document.getElementById('attack-chain-container');
        if (container) {
            container.innerHTML = '<div class="loading-spinner">' + (typeof window.t === 'function' ? window.t('chat.loading') : 'Loading...') + '</div>';
        }
    }

    try {
        const response = await apiFetch(`/api/attack-chain/${conversationId}`);

        if (!isCurrentAttackChainRequest(conversationId, requestSequence)) {
            finishAttackChainRequest(conversationId, requestSequence);
            return;
        }

        if (!response.ok) {
            // Handle 409 Conflict (generation in progress)
            if (response.status === 409) {
                const container = document.getElementById('attack-chain-container');
                if (container) {
                    container.innerHTML = `
                        <div style="text-align: center; padding: 28px 24px; color: var(--text-secondary);">
                            <div style="display: inline-flex; align-items: center; gap: 8px; font-size: 0.95rem; color: var(--text-primary);">
                                <span role="presentation" aria-hidden="true">⏳</span>
                                <span>Attack chain is being generated; please wait</span>
                            </div>
                            <button class="btn-secondary" onclick="refreshAttackChain()" style="margin-top: 12px; font-size: 0.78rem; padding: 4px 12px;">
                                Refresh
                            </button>
                        </div>
                    `;
                }
                // Auto-refresh after 5 seconds (refresh allowed, but keep the loading state to prevent repeated clicks)
                // Use a closure to save conversationId to prevent cross-talk
                setTimeout(() => {
                    // Check whether the displayed conversation ID matches
                    if (isCurrentAttackChainRequest(conversationId, requestSequence)) {
                        refreshAttackChain();
                    }
                }, 5000);
                // In the 409 case, keep the loading state to prevent repeated clicks
                // but allow refreshAttackChain to call loadAttackChain to check the status
                // Note: do not reset the loading state; keep it
                // Restore button state (loading state is kept, but the user may refresh manually)
                const regenerateBtn = document.querySelector('button[onclick="regenerateAttackChain()"]');
                if (regenerateBtn) {
                    regenerateBtn.disabled = false;
                    regenerateBtn.style.opacity = '1';
                    regenerateBtn.style.cursor = 'pointer';
                }
                return; // Return early; do not run setAttackChainLoading(conversationId, false) in the finally block
            }

            const error = await response.json();
            throw new Error(error.error || 'Failed to load attack chain');
        }

        const chainData = await response.json();

        // Check whether the displayed conversation ID matches, to prevent cross-talk
        if (!isCurrentAttackChainRequest(conversationId, requestSequence)) {
            console.log('Attack chain data returned, but the displayed conversation has changed; ignoring this render', {
                returned: conversationId,
                current: currentAttackChainConversationId
            });
            finishAttackChainRequest(conversationId, requestSequence);
            return;
        }

        // Render attack chain
        renderAttackChain(chainData);

        // Update statistics
        updateAttackChainStats(chainData);

        // After a successful load, reset the loading state
        finishAttackChainRequest(conversationId, requestSequence);

    } catch (error) {
        console.error('Failed to load attack chain:', error);
        // Also reset the loading state on error
        finishAttackChainRequest(conversationId, requestSequence);
        if (!isCurrentAttackChainRequest(conversationId, requestSequence)) return;
        resetAttackChainContext();
        renderAttackChainError(document.getElementById('attack-chain-container'),
            attackChainFailureText('chat.loadFailed', 'Load failed: ', error.message));
    } finally {
        // Restore regenerate button
        const regenerateBtn = document.querySelector('button[onclick="regenerateAttackChain()"]');
        if (regenerateBtn && isCurrentAttackChainRequest(conversationId, requestSequence)) {
            regenerateBtn.disabled = false;
            regenerateBtn.style.opacity = '1';
            regenerateBtn.style.cursor = 'pointer';
        }
    }
}

// Render attack chain
function renderAttackChain(chainData) {
    if (attackChainCytoscape) {
        attackChainCytoscape.destroy();
        attackChainCytoscape = null;
    }
    window.attackChainOriginalData = chainData;
    if (window.VeritySecAttackChainContext) window.VeritySecAttackChainContext.render(chainData);
    const container = document.getElementById('attack-chain-container');
    if (!container) {
        return;
    }

    // Clear container
    container.innerHTML = '';

    if (!chainData.nodes || chainData.nodes.length === 0) {
        container.innerHTML = '<div class="empty-message">' + (typeof window.t === 'function' ? window.t('chat.noAttackChainData') : 'No attack chain data') + '</div>';
        return;
    }

    // Compute graph complexity (used to adjust layout and style dynamically)
    const nodeCount = chainData.nodes.length;
    const edgeCount = chainData.edges.length;
    const isComplexGraph = nodeCount > 15 || edgeCount > 25;
    const isDarkTheme = document.documentElement.getAttribute('data-theme') === 'dark';

    // Optimize node labels: smart truncation and line wrapping
    chainData.nodes.forEach(node => {
        if (node.label) {
            // Smart truncation: prefer breaking at punctuation or spaces
            const maxLength = isComplexGraph ? 18 : 22;
            if (node.label.length > maxLength) {
                let truncated = node.label.substring(0, maxLength);
                // Try truncating at the last punctuation mark or space
                const lastPunct = Math.max(
                    truncated.lastIndexOf('，'),
                    truncated.lastIndexOf('。'),
                    truncated.lastIndexOf('、'),
                    truncated.lastIndexOf(' '),
                    truncated.lastIndexOf('/')
                );
                if (lastPunct > maxLength * 0.6) { // If the punctuation position is reasonable
                    truncated = truncated.substring(0, lastPunct + 1);
                }
                node.label = truncated + '...';
            }
        }
    });

    // Prepare Cytoscape data
    const elements = [];

    // Add nodes and precompute style info (theme colors consistent with the export)
    chainData.nodes.forEach(node => {
        const riskScore = node.risk_score || 0;
        const nodeType = node.type || '';
        const metadata = node.metadata || {};

        // Unified theme system (consistent with the export)
        let typeLabel = 'Node';
        let typeEn = 'NODE';
        let typeColor = '#334155';      // Primary text color
        let accentColor = '#94a3b8';    // Accent color (icon/border)
        let accentDark = '#475569';     // Dark variant
        let bgGradientStart = '#FFFFFF';
        let bgGradientEnd = '#F8FAFC';
        let iconType = 'default';       // Icon type

        if (nodeType === 'target') {
            typeLabel = 'Target';
            typeEn = 'TARGET';
            typeColor = '#312E81';
            accentColor = '#4F46E5';
            accentDark = '#3730A3';
            bgGradientStart = '#FFFFFF';
            bgGradientEnd = '#F5F3FF';
            iconType = 'target';
        } else if (nodeType === 'action') {
            typeLabel = 'Action';
            typeEn = 'ACTION';
            const findings = metadata.findings || [];
            const hasFindings = Array.isArray(findings) && findings.length > 0;
            const isFailedInsight = (metadata.status || '') === 'failed_insight';
            if (hasFindings && !isFailedInsight) {
                typeColor = '#064E3B';
                accentColor = '#10B981';
                accentDark = '#047857';
                bgGradientStart = '#FFFFFF';
                bgGradientEnd = '#ECFDF5';
            } else {
                typeColor = '#334155';
                accentColor = '#64748B';
                accentDark = '#475569';
                bgGradientStart = '#FFFFFF';
                bgGradientEnd = '#F8FAFC';
            }
            iconType = 'action';
        } else if (nodeType === 'vulnerability') {
            typeLabel = 'Vulnerability';
            typeEn = 'VULNERABILITY';
            if (riskScore >= 80) {
                typeColor = '#881337';
                accentColor = '#E11D48';
                accentDark = '#BE123C';
                bgGradientStart = '#FFFFFF';
                bgGradientEnd = '#FFF1F2';
            } else if (riskScore >= 60) {
                typeColor = '#7C2D12';
                accentColor = '#EA580C';
                accentDark = '#C2410C';
                bgGradientStart = '#FFFFFF';
                bgGradientEnd = '#FFF7ED';
            } else if (riskScore >= 40) {
                typeColor = '#713F12';
                accentColor = '#CA8A04';
                accentDark = '#A16207';
                bgGradientStart = '#FFFFFF';
                bgGradientEnd = '#FEFCE8';
            } else {
                typeColor = '#134E4A';
                accentColor = '#0D9488';
                accentDark = '#0F766E';
                bgGradientStart = '#FFFFFF';
                bgGradientEnd = '#F0FDFA';
            }
            iconType = 'vulnerability';
        }

        const labelTextColor = isDarkTheme ? '#E5E7EB' : '#0F172A';
        if (isDarkTheme) {
            typeColor = '#E5E7EB';
            bgGradientStart = '#111827';
            if (nodeType === 'target') {
                bgGradientEnd = '#1E1B4B';
            } else if (nodeType === 'action') {
                bgGradientEnd = accentColor === '#10B981' ? '#052E2B' : '#172033';
            } else if (nodeType === 'vulnerability') {
                if (riskScore >= 80) {
                    bgGradientEnd = '#3F101C';
                } else if (riskScore >= 60) {
                    bgGradientEnd = '#3B1D0D';
                } else if (riskScore >= 40) {
                    bgGradientEnd = '#3A2A0A';
                } else {
                    bgGradientEnd = '#063A36';
                }
            } else {
                bgGradientEnd = '#172033';
            }
        }

        // Generate icon background-image (data URL) for each node
        const iconSvg = _acBuildNodeIconDataUrl(iconType, accentColor, accentDark);

        // Compute badge text (top right)
        let badgeText = '';
        if (nodeType === 'vulnerability' && riskScore > 0) {
            const rl = riskScore >= 80 ? 'Critical' : riskScore >= 60 ? 'High' : riskScore >= 40 ? 'Medium' : 'Low';
            badgeText = rl + ' · ' + riskScore;
        } else if (nodeType === 'action') {
            const findings = metadata.findings || [];
            if (Array.isArray(findings) && findings.length > 0 && metadata.status !== 'failed_insight') {
                badgeText = 'Findings ' + findings.length;
            } else if (metadata.status === 'failed_insight') {
                badgeText = 'Leads';
            }
        } else if (nodeType === 'target') {
            badgeText = 'Main target';
        }

        elements.push({
            data: {
                id: node.id,
                label: node.label,
                originalLabel: node.label,
                type: nodeType,
                typeLabel: typeLabel,
                typeEn: typeEn,
                typeColor: typeColor,
                accentColor: accentColor,
                accentDark: accentDark,
                bgGradientStart: bgGradientStart,
                bgGradientEnd: bgGradientEnd,
                labelTextColor: labelTextColor,
                iconDataUrl: iconSvg,
                badgeText: badgeText,
                riskScore: riskScore,
                toolExecutionId: node.tool_execution_id || '',
                metadata: metadata
            }
        });
    });

    // Add edges (only those whose source and target nodes both exist)
    const nodeIds = new Set(chainData.nodes.map(node => node.id));

    // Save valid edges for ELK layout
    const validEdges = [];
    chainData.edges.forEach(edge => {
        // Verify that the source and target nodes exist
        if (nodeIds.has(edge.source) && nodeIds.has(edge.target)) {
            validEdges.push(edge);
            elements.push({
                data: {
                    id: edge.id,
                    source: edge.source,
                    target: edge.target,
                    type: edge.type || 'leads_to',
                    weight: edge.weight || 1
                }
            });
        } else {
            console.warn('Skipping invalid edge: source or target node does not exist', {
                edgeId: edge.id,
                source: edge.source,
                target: edge.target,
                sourceExists: nodeIds.has(edge.source),
                targetExists: nodeIds.has(edge.target)
            });
        }
    });

    // Initialize Cytoscape - modern card-style node design (icon + text + badge)
    attackChainCytoscape = cytoscape({
        container: container,
        elements: elements,
        style: [
            {
                selector: 'node',
                style: {
                    // Node label: two lines of text (English type | main title)
                    'label': function(ele) {
                        const typeEn = ele.data('typeEn') || '';
                        const typeLabel = ele.data('typeLabel') || '';
                        const label = ele.data('label') || '';
                        const badgeText = ele.data('badgeText') || '';
                        // Line 1: TYPE_EN · type (small text)
                        // Line 2: main title (large text)
                        // Line 3: badge text (colored hint)
                        let line1 = typeEn + '  ·  ' + typeLabel;
                        if (badgeText) line1 += '  [' + badgeText + ']';
                        return line1 + '\n' + label;
                    },
                    'width': function(ele) {
                        const type = ele.data('type');
                        if (type === 'target') return isComplexGraph ? 300 : 360;
                        if (type === 'vulnerability') return isComplexGraph ? 280 : 340;
                        return isComplexGraph ? 260 : 320;
                    },
                    'height': function(ele) {
                        return isComplexGraph ? 84 : 100;
                    },
                    'shape': 'round-rectangle',
                    // Light gradient background (white to a very pale theme color)
                    'background-fill': 'linear-gradient',
                    'background-gradient-direction': 'to-bottom-right',
                    'background-gradient-stop-colors': function(ele) {
                        return (ele.data('bgGradientStart') || '#FFFFFF') + ' ' +
                               (ele.data('bgGradientEnd') || '#F8FAFC');
                    },
                    'background-gradient-stop-positions': '0 100',
                    'background-opacity': 1,
                    // Left-side type icon (SVG dataURL as background image)
                    'background-image': function(ele) {
                        return ele.data('iconDataUrl') || 'none';
                    },
                    'background-image-containment': 'inside',
                    'background-fit': 'none',
                    'background-image-opacity': 1,
                    'background-width': '36px',
                    'background-height': '36px',
                    'background-position-x': '18px',
                    'background-position-y': '50%',
                    'background-offset-y': '0',
                    'background-clip': 'node',
                    'bounds-expansion': 0,
                    // Border: soft theme color
                    'border-width': 1.5,
                    'border-color': function(ele) {
                        return ele.data('accentColor') || '#94a3b8';
                    },
                    'border-opacity': 0.5,
                    // Text style
                    'color': function(ele) {
                        return ele.data('labelTextColor') || '#0f172a';
                    },
                    'font-size': function(ele) {
                        return isComplexGraph ? '13px' : '14px';
                    },
                    'font-weight': 700,
                    'font-family': '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", "PingFang SC", "Microsoft YaHei", sans-serif',
                    // Text left-aligned, leaving space for the left icon
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'text-justification': 'left',
                    'text-wrap': 'wrap',
                    'text-max-width': function(ele) {
                        const type = ele.data('type');
                        const w = (type === 'target') ? (isComplexGraph ? 300 : 360)
                                : (type === 'vulnerability') ? (isComplexGraph ? 280 : 340)
                                : (isComplexGraph ? 260 : 320);
                        return (w - 80) + 'px';
                    },
                    'text-overflow-wrap': 'anywhere',
                    'text-margin-x': 28,
                    'text-margin-y': 0,
                    'padding': '12px',
                    'line-height': 1.4,
                    'text-outline-width': 0,
                    // Soft shadow (simulated with overlay)
                    'overlay-color': '#0f172a',
                    'overlay-opacity': 0,
                    'overlay-padding': 0,
                    'transition-property': 'overlay-opacity, border-width, border-color',
                    'transition-duration': '160ms'
                }
            },
            {
                // Target node: slightly thicker border
                selector: 'node[type = "target"]',
                style: {
                    'border-width': 2
                }
            },
            {
                // Vulnerability node: slightly thicker border
                selector: 'node[type = "vulnerability"]',
                style: {
                    'border-width': 2
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': function(ele) {
                        const type = ele.data('type');
                        if (type === 'discovers') return 2.6;
                        if (type === 'enables') return 2.8;
                        return 2;
                    },
                    'line-color': function(ele) {
                        const type = ele.data('type');
                        if (type === 'discovers' || type === 'targets') return '#4F46E5';
                        if (type === 'enables') return '#E11D48';
                        if (type === 'leads_to') return '#64748B';
                        return '#cbd5e1';
                    },
                    'target-arrow-color': function(ele) {
                        const type = ele.data('type');
                        if (type === 'discovers' || type === 'targets') return '#4F46E5';
                        if (type === 'enables') return '#E11D48';
                        if (type === 'leads_to') return '#64748B';
                        return '#cbd5e1';
                    },
                    'target-arrow-shape': 'triangle-backcurve',
                    'arrow-scale': 1.35,
                    'curve-style': 'bezier',
                    'control-point-step-size': 60,
                    'opacity': 0.88,
                    'line-style': function(ele) {
                        const type = ele.data('type');
                        if (type === 'targets') return 'dashed';
                        return 'solid';
                    },
                    'line-dash-pattern': function(ele) {
                        const type = ele.data('type');
                        if (type === 'targets') return [10, 5];
                        return [];
                    },
                    'transition-property': 'opacity, width, line-color',
                    'transition-duration': '160ms'
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 3.5,
                    'border-color': '#4F46E5',
                    'z-index': 999,
                    'opacity': 1,
                    'overlay-opacity': 0.06,
                    'overlay-color': '#4F46E5',
                    'overlay-padding': 8
                }
            }
        ],
        userPanningEnabled: true,
        userZoomingEnabled: true,
        boxSelectionEnabled: true,
        minZoom: 0.2,
        maxZoom: 3
    });

    // Use ELK layout (high-quality DAG layout, reduces edge crossings)
    let layoutOptions = {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: isComplexGraph ? 3.0 : 2.5,
        padding: 40
    };

    // Use ELK.js for layout computation
    // elk.bundled.js exposes the ELK object; new ELK() can be used directly
    let elkInstance = null;
    if (typeof ELK !== 'undefined') {
        try {
            elkInstance = new ELK();
        } catch (e) {
            console.warn('ELK initialization failed:', e);
        }
    }

    if (elkInstance) {
        try {

            // === Layout parameters (always uses DOWN vertical layout) ===
            const isSmallGraph = chainData.nodes.length <= 8 && validEdges.length <= 12;
            // Spacing between nodes on the same layer (spread horizontally)
            const nodeGap = isComplexGraph ? 45 : isSmallGraph ? 80 : 60;
            // Layer spacing (vertical: room for edges, while keeping the graph from getting too tall)
            const layerGap = isComplexGraph ? 70 : isSmallGraph ? 130 : 95;

            // Build the ELK graph structure - node sizes kept consistent with the Cytoscape styles
            const elkGraph = {
                id: 'root',
                layoutOptions: {
                    'elk.algorithm': 'layered',
                    'elk.direction': 'DOWN',
                    'elk.padding': '[top=30,left=50,bottom=30,right=50]',
                    'elk.spacing.nodeNode': String(nodeGap),
                    'elk.spacing.edgeNode': '20',
                    'elk.spacing.edgeEdge': '12',
                    'elk.spacing.componentComponent': '50',
                    'elk.layered.spacing.nodeNodeBetweenLayers': String(layerGap),
                    'elk.layered.spacing.edgeNodeBetweenLayers': '20',
                    'elk.layered.spacing.edgeEdgeBetweenLayers': '12',
                    'elk.layered.nodePlacement.strategy': 'BRANDES_KOEPF',
                    'elk.layered.nodePlacement.bk.fixedAlignment': 'BALANCED',
                    'elk.layered.nodePlacement.bk.edgeStraightening': 'IMPROVE_STRAIGHTNESS',
                    'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
                    'elk.layered.crossingMinimization.semiInteractive': 'false',
                    'elk.layered.thoroughness': String(isComplexGraph ? 10 : 15),
                    'elk.layered.cycleBreaking.strategy': 'GREEDY',
                    'elk.layered.compaction.connectedComponents': 'true',
                    'elk.layered.compaction.postCompaction.strategy': 'LEFT_RIGHT_CONSTRAINT_LOCKING',
                    'elk.layered.unnecessaryBendpoints': 'true',
                    'elk.layered.mergeEdges': 'false'
                },
                children: chainData.nodes.map(node => {
                    const type = node.type || '';
                    return {
                        id: node.id,
                        width: type === 'target' ? (isComplexGraph ? 300 : 360) :
                               type === 'vulnerability' ? (isComplexGraph ? 280 : 340) :
                               (isComplexGraph ? 260 : 320),
                        height: isComplexGraph ? 84 : 100
                    };
                }),
                edges: validEdges.map(edge => ({
                    id: edge.id,
                    sources: [edge.source],
                    targets: [edge.target]
                }))
            };

            // Compute layout with ELK
            elkInstance.layout(elkGraph).then(laidOutGraph => {
                // Apply the ELK-computed layout to Cytoscape nodes
                if (laidOutGraph && laidOutGraph.children) {
                    laidOutGraph.children.forEach(elkNode => {
                        const cyNode = attackChainCytoscape.getElementById(elkNode.id);
                        if (cyNode && elkNode.x !== undefined && elkNode.y !== undefined) {
                            cyNode.position({
                                x: elkNode.x + (elkNode.width || 0) / 2,
                                y: elkNode.y + (elkNode.height || 0) / 2
                            });
                        }
                    });

                    // After layout completes, center the graph
                    setTimeout(() => {
                        centerAttackChain();
                    }, 150);
                } else {
                    throw new Error('ELK layout returned an invalid result');
                }
            }).catch(err => {
                console.warn('ELK layout computation failed; using default layout:', err);
                // Fall back to default layout
                const layout = attackChainCytoscape.layout(layoutOptions);
                layout.one('layoutstop', () => {
                    setTimeout(() => {
                        centerAttackChain();
                    }, 100);
                });
                layout.run();
            });
        } catch (e) {
            console.warn('ELK layout initialization failed; using default layout:', e);
            // Fall back to default layout
            const layout = attackChainCytoscape.layout(layoutOptions);
            layout.one('layoutstop', () => {
                setTimeout(() => {
                    centerAttackChain();
                }, 100);
            });
            layout.run();
        }
    } else {
        console.warn('ELK.js not loaded; using default layout. Check that the elkjs library is loaded correctly.');
        // Use default layout
        const layout = attackChainCytoscape.layout(layoutOptions);
        layout.one('layoutstop', () => {
            setTimeout(() => {
                centerAttackChain();
            }, 100);
        });
        layout.run();
    }

    // Function to center the attack chain: always keep all nodes fully visible
    function centerAttackChain() {
        try {
            if (!attackChainCytoscape) {
                return;
            }
            const container = attackChainCytoscape.container();
            if (!container) return;
            const containerWidth = container.offsetWidth;
            const containerHeight = container.offsetHeight;
            if (containerWidth === 0 || containerHeight === 0) {
                setTimeout(centerAttackChain, 100);
                return;
            }

            // Use larger padding so nodes do not touch the edges; visually more comfortable
            // Core principle: rely fully on the fit result to ensure global visibility; do not force a minimum zoom
            const padding = 60;
            attackChainCytoscape.fit(undefined, padding);

            // Fine-tune only in extreme cases: for small graphs (2-3 nodes), lower the zoom after fit if it is too large
            setTimeout(() => {
                if (!attackChainCytoscape) return;
                const currentZoom = attackChainCytoscape.zoom();
                // Upper limit: avoid nodes filling the screen and looking too large
                const MAX_INITIAL_ZOOM = 1.25;
                // Lower limit: avoid tiny graphs being unreadable (tiny graphs usually have few nodes)
                const MIN_READABLE_ZOOM = 0.25;

                let targetZoom = currentZoom;
                if (currentZoom > MAX_INITIAL_ZOOM) {
                    targetZoom = MAX_INITIAL_ZOOM;
                } else if (currentZoom < MIN_READABLE_ZOOM) {
                    // If the zoom after fit is below 0.25, the graph is very large; keep the current result and let the user drag to inspect
                    targetZoom = MIN_READABLE_ZOOM;
                }

                if (Math.abs(targetZoom - currentZoom) > 0.01) {
                    const extent = attackChainCytoscape.extent();
                    const cx = (extent.x1 + extent.x2) / 2;
                    const cy = (extent.y1 + extent.y2) / 2;
                    attackChainCytoscape.zoom({
                        level: targetZoom,
                        position: { x: cx, y: cy }
                    });
                }
                attackChainCytoscape.center();
            }, 60);
        } catch (error) {
            console.warn('Error centering chart:', error);
        }
    }

    // Add click events
    attackChainCytoscape.on('tap', 'node', function(evt) {
        const node = evt.target;
        showNodeDetails(node.data());
    });

    // Click empty space to close details
    attackChainCytoscape.on('tap', function(evt) {
        if (evt.target === attackChainCytoscape) {
            attackChainCytoscape.elements().unselect();
        }
    });

    // Add hover effect: enhanced border + soft glow overlay + fade unrelated edges
    attackChainCytoscape.on('mouseover', 'node', function(evt) {
        const node = evt.target;
        const accent = node.data('accentColor') || '#4F46E5';
        node.style({
            'border-width': 3,
            'border-color': accent,
            'border-opacity': 1,
            'overlay-color': accent,
            'overlay-opacity': 0.08,
            'overlay-padding': 10,
            'z-index': 998
        });
        const connected = node.connectedEdges();
        attackChainCytoscape.edges().not(connected).style('opacity', 0.2);
        connected.style({ 'opacity': 1, 'width': 3.5 });
    });

    attackChainCytoscape.on('mouseout', 'node', function(evt) {
        const node = evt.target;
        const type = node.data('type');
        const defaultBorderWidth = (type === 'target' || type === 'vulnerability') ? 2 : 1.5;
        node.style({
            'border-width': defaultBorderWidth,
            'border-color': node.data('accentColor') || '#94a3b8',
            'border-opacity': 0.5,
            'overlay-opacity': 0,
            'overlay-padding': 0,
            'z-index': 0
        });
        attackChainCytoscape.edges().style({ 'opacity': 0.88, 'width': '' });
    });

}

// Safely get the source and target nodes of an edge
function getEdgeNodes(edge) {
    try {
        const source = edge.source();
        const target = edge.target();

        // Check whether source and target nodes exist
        if (!source || !target || source.length === 0 || target.length === 0) {
            return { source: null, target: null, valid: false };
        }

        return { source: source, target: target, valid: true };
    } catch (error) {
        console.warn('Error getting edge nodes:', error, edge.id());
        return { source: null, target: null, valid: false };
    }
}

// Filter attack chain nodes (by search keyword)
function filterAttackChainNodes(searchText) {
    if (!attackChainCytoscape || !window.attackChainOriginalData) {
        return;
    }

    const searchLower = searchText.toLowerCase().trim();
    if (searchLower === '') {
        // Reset all node visibility
        attackChainCytoscape.nodes().style('display', 'element');
        attackChainCytoscape.edges().style('display', 'element');
        // Restore default border
        attackChainCytoscape.nodes().style('border-width', 2);
        return;
    }

    // Filter nodes
    attackChainCytoscape.nodes().forEach(node => {
        // Search using the original label, excluding the type label
        const originalLabel = node.data('originalLabel') || node.data('label') || '';
        const label = originalLabel.toLowerCase();
        const type = (node.data('type') || '').toLowerCase();
        const matches = label.includes(searchLower) || type.includes(searchLower);

        if (matches) {
            node.style('display', 'element');
            // Highlight matching nodes
            node.style('border-width', 4);
            node.style('border-color', '#0066ff');
        } else {
            node.style('display', 'none');
        }
    });

    // Hide edges without a visible source or target node
    attackChainCytoscape.edges().forEach(edge => {
        const { source, target, valid } = getEdgeNodes(edge);
        if (!valid) {
            edge.style('display', 'none');
            return;
        }

        const sourceVisible = source.style('display') !== 'none';
        const targetVisible = target.style('display') !== 'none';
        if (sourceVisible && targetVisible) {
            edge.style('display', 'element');
        } else {
            edge.style('display', 'none');
        }
    });

    // Re-fit view
    attackChainCytoscape.fit(undefined, 60);
}

// Filter attack chain nodes by type
function filterAttackChainByType(type) {
    if (!attackChainCytoscape || !window.attackChainOriginalData) {
        return;
    }

    if (type === 'all') {
        attackChainCytoscape.nodes().style('display', 'element');
        attackChainCytoscape.edges().style('display', 'element');
        attackChainCytoscape.nodes().style('border-width', 2);
        attackChainCytoscape.fit(undefined, 60);
        return;
    }

    // Filter nodes
    attackChainCytoscape.nodes().forEach(node => {
        const nodeType = node.data('type') || '';
        if (nodeType === type) {
            node.style('display', 'element');
        } else {
            node.style('display', 'none');
        }
    });

    // Hide edges without a visible source or target node
    attackChainCytoscape.edges().forEach(edge => {
        const { source, target, valid } = getEdgeNodes(edge);
        if (!valid) {
            edge.style('display', 'none');
            return;
        }

        const sourceVisible = source.style('display') !== 'none';
        const targetVisible = target.style('display') !== 'none';
        if (sourceVisible && targetVisible) {
            edge.style('display', 'element');
        } else {
            edge.style('display', 'none');
        }
    });

    // Re-fit view
    attackChainCytoscape.fit(undefined, 60);
}

// Filter attack chain nodes by risk level
function filterAttackChainByRisk(riskLevel) {
    if (!attackChainCytoscape || !window.attackChainOriginalData) {
        return;
    }

    if (riskLevel === 'all') {
        attackChainCytoscape.nodes().style('display', 'element');
        attackChainCytoscape.edges().style('display', 'element');
        attackChainCytoscape.nodes().style('border-width', 2);
        attackChainCytoscape.fit(undefined, 60);
        return;
    }

    // Define risk ranges
    const riskRanges = {
        'high': [80, 100],
        'medium-high': [60, 79],
        'medium': [40, 59],
        'low': [0, 39]
    };

    const [minRisk, maxRisk] = riskRanges[riskLevel] || [0, 100];

    // Filter nodes
    attackChainCytoscape.nodes().forEach(node => {
        const riskScore = node.data('riskScore') || 0;
        if (riskScore >= minRisk && riskScore <= maxRisk) {
            node.style('display', 'element');
        } else {
            node.style('display', 'none');
        }
    });

    // Hide edges without a visible source or target node
    attackChainCytoscape.edges().forEach(edge => {
        const { source, target, valid } = getEdgeNodes(edge);
        if (!valid) {
            edge.style('display', 'none');
            return;
        }

        const sourceVisible = source.style('display') !== 'none';
        const targetVisible = target.style('display') !== 'none';
        if (sourceVisible && targetVisible) {
            edge.style('display', 'element');
        } else {
            edge.style('display', 'none');
        }
    });

    // Re-fit view
    attackChainCytoscape.fit(undefined, 60);
}

// Reset attack chain filters
function resetAttackChainFilters() {
    // Reset search box
    const searchInput = document.getElementById('attack-chain-search');
    if (searchInput) {
        searchInput.value = '';
    }

    // Reset type filter
    const typeFilter = document.getElementById('attack-chain-type-filter');
    if (typeFilter) {
        typeFilter.value = 'all';
    }

    // Reset risk filter
    const riskFilter = document.getElementById('attack-chain-risk-filter');
    if (riskFilter) {
        riskFilter.value = 'all';
    }

    // Reset all node visibility
    if (attackChainCytoscape) {
        attackChainCytoscape.nodes().forEach(node => {
            node.style('display', 'element');
            node.style('border-width', 2); // Restore default border
        });
        attackChainCytoscape.edges().style('display', 'element');
        attackChainCytoscape.fit(undefined, 60);
    }
}

// Show node details
function showNodeDetails(nodeData) {
    const detailsPanel = document.getElementById('attack-chain-details');
    const detailsContent = document.getElementById('attack-chain-details-content');

    if (!detailsPanel || !detailsContent) {
        return;
    }

    // Mark the sidebar as having details active; CSS hides the legend so the details take the full space
    const sidebar = document.querySelector('.attack-chain-sidebar');
    if (sidebar) sidebar.classList.add('details-active');

    // Use requestAnimationFrame to optimize the display animation
    requestAnimationFrame(() => {
        detailsPanel.style.display = 'flex';
        requestAnimationFrame(() => {
            detailsPanel.style.opacity = '1';
        });
    });

    let html = `
        <div class="node-detail-item">
            <strong>Node ID:</strong> <code>${nodeData.id}</code>
        </div>
        <div class="node-detail-item">
            <strong>Type:</strong> ${getNodeTypeLabel(nodeData.type)}
        </div>
        <div class="node-detail-item">
            <strong>Label:</strong> ${escapeHtml(nodeData.originalLabel || nodeData.label)}
        </div>
        <div class="node-detail-item">
            <strong>Risk score:</strong> ${nodeData.riskScore}/100
        </div>
    `;

    // Show action node info (tool execution + AI analysis)
    if (nodeData.type === 'action' && nodeData.metadata) {
        if (nodeData.metadata.tool_name) {
            html += `
                <div class="node-detail-item">
                    <strong>Tool name:</strong> <code>${escapeHtml(nodeData.metadata.tool_name)}</code>
                </div>
            `;
        }
        if (nodeData.metadata.tool_intent) {
            html += `
                <div class="node-detail-item">
                    <strong>Tool intent:</strong> <span style="color: #0066ff; font-weight: bold;">${escapeHtml(nodeData.metadata.tool_intent)}</span>
                </div>
            `;
        }
        if (nodeData.metadata.status === 'failed_insight') {
            html += `
                <div class="node-detail-item">
                    <strong>Execution status:</strong> <span style="color: #ff9800; font-weight: bold;">Failed but with leads</span>
                </div>
            `;
        }
        if (nodeData.metadata.ai_analysis) {
            html += `
                <div class="node-detail-item">
                    <strong>AI analysis:</strong> <div class="node-detail-ai-analysis">${escapeHtml(nodeData.metadata.ai_analysis)}</div>
                </div>
            `;
        }
        if (nodeData.metadata.findings && Array.isArray(nodeData.metadata.findings) && nodeData.metadata.findings.length > 0) {
            html += `
                <div class="node-detail-item">
                    <strong>Key findings:</strong>
                    <ul style="margin: 5px 0; padding-left: 20px;">
                        ${nodeData.metadata.findings.map(f => `<li>${escapeHtml(f)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }
    }

    // Show target info (if it is a target node)
    if (nodeData.type === 'target' && nodeData.metadata && nodeData.metadata.target) {
        html += `
            <div class="node-detail-item">
                <strong>Test target:</strong> <code>${escapeHtml(nodeData.metadata.target)}</code>
            </div>
        `;
    }

    // Show vulnerability info (if it is a vulnerability node)
    if (nodeData.type === 'vulnerability' && nodeData.metadata) {
        if (nodeData.metadata.vulnerability_type) {
            html += `
                <div class="node-detail-item">
                    <strong>Vulnerability type:</strong> ${escapeHtml(nodeData.metadata.vulnerability_type)}
                </div>
            `;
        }
        if (nodeData.metadata.description) {
            html += `
                <div class="node-detail-item">
                    <strong>Description:</strong> ${escapeHtml(nodeData.metadata.description)}
                </div>
            `;
        }
        if (nodeData.metadata.severity) {
            html += `
                <div class="node-detail-item">
                    <strong>Severity:</strong> <span style="color: ${getSeverityColor(nodeData.metadata.severity)}; font-weight: bold;">${escapeHtml(nodeData.metadata.severity)}</span>
                </div>
            `;
        }
        if (nodeData.metadata.location) {
            html += `
                <div class="node-detail-item">
                    <strong>Location:</strong> <code>${escapeHtml(nodeData.metadata.location)}</code>
                </div>
            `;
        }
    }

    if (nodeData.toolExecutionId) {
        html += `
            <div class="node-detail-item">
                <strong>Tool execution ID:</strong> <code>${nodeData.toolExecutionId}</code>
            </div>
        `;
    }

    // When details fill the sidebar, the content area handles its own scrolling; reset to top
    if (detailsContent) {
        detailsContent.scrollTop = 0;
    }

    requestAnimationFrame(() => {
        detailsContent.innerHTML = html;
        requestAnimationFrame(() => {
            if (detailsContent) {
                detailsContent.scrollTop = 0;
            }
        });
    });
}

// Get severity color
function getSeverityColor(severity) {
    const colors = {
        'critical': '#ff0000',
        'high': '#ff4444',
        'medium': '#ff8800',
        'low': '#ffbb00'
    };
    return colors[severity.toLowerCase()] || '#666';
}

// Get node type label
function getNodeTypeLabel(type) {
    const labels = {
        'action': 'Action',
        'vulnerability': 'Vulnerability',
        'target': 'Target'
    };
    return labels[type] || type;
}

// Update statistics (uses i18n, consistent with attackChainModal.nodesEdges)
function updateAttackChainStats(chainData) {
    const statsElement = document.getElementById('attack-chain-stats');
    if (statsElement) {
        const nodeCount = chainData.nodes ? chainData.nodes.length : 0;
        const edgeCount = chainData.edges ? chainData.edges.length : 0;
        if (typeof window.t === 'function') {
            statsElement.textContent = window.t('attackChainModal.nodesEdges', {
                nodes: nodeCount,
                edges: edgeCount
            });
        } else {
            statsElement.textContent = `Nodes: ${nodeCount} | Edges: ${edgeCount}`;
        }
    }
}

// On language switch, refresh attack chain statistics text (dynamic textContent is not updated by applyTranslations)
document.addEventListener('languagechange', function () {
    if (window.attackChainOriginalData && typeof updateAttackChainStats === 'function') {
        updateAttackChainStats(window.attackChainOriginalData);
    } else {
        const statsEl = document.getElementById('attack-chain-stats');
        if (statsEl && typeof window.t === 'function') {
            statsEl.textContent = window.t('attackChainModal.nodesEdges', { nodes: 0, edges: 0 });
        }
    }
});

// Close node details
function closeNodeDetails() {
    const detailsPanel = document.getElementById('attack-chain-details');
    const sidebar = document.querySelector('.attack-chain-sidebar');

    if (detailsPanel) {
        detailsPanel.style.opacity = '0';
        setTimeout(() => {
            detailsPanel.style.display = 'none';
            detailsPanel.style.opacity = '';
            // Remove details active state; legend is shown again
            if (sidebar) sidebar.classList.remove('details-active');
        }, 220);
    } else if (sidebar) {
        sidebar.classList.remove('details-active');
    }

    if (attackChainCytoscape) {
        attackChainCytoscape.elements().unselect();
    }
}

// Close attack chain modal
function closeAttackChainModal() {
    closeAppModal('attack-chain-modal');
    attackChainRequestSequence += 1;
    attackChainRequestOwners.delete(currentAttackChainConversationId);
    setAttackChainLoading(currentAttackChainConversationId, false);
    resetAttackChainContext();

    // Close node details
    closeNodeDetails();

    currentAttackChainConversationId = null;
}

// Refresh attack chain (reload)
// Note: this function may be called during loading, to check generation status
function refreshAttackChain() {
    if (currentAttackChainConversationId) {
        // Temporarily allow refresh even while loading (to check generation status)
        const wasLoading = isAttackChainLoading(currentAttackChainConversationId);
        setAttackChainLoading(currentAttackChainConversationId, false); // Temporary reset to allow refresh
        loadAttackChain(currentAttackChainConversationId).finally(() => {
            // If it was loading before (409 case), restore the loading state
            // Otherwise keep false (normal completion)
            if (wasLoading) {
                // Check whether the loading state still needs to be kept (if still 409, loadAttackChain handles it)
                // Here we assume the state is reset if loading succeeds
                // If still 409, loadAttackChain keeps the loading state
            }
        });
    }
}

// Regenerate attack chain
async function regenerateAttackChain() {
    if (!currentAttackChainConversationId) {
        return;
    }

    // Prevent repeated clicks (only checks the current conversation's loading state)
    if (isAttackChainLoading(currentAttackChainConversationId)) {
        console.log('Attack chain is being generated; please wait...');
        return;
    }

    // Save the conversation ID at request time to prevent cross-talk
    const savedConversationId = currentAttackChainConversationId;
    setAttackChainLoading(savedConversationId, true);
    const requestSequence = beginAttackChainRequest(savedConversationId);
    resetAttackChainContext();

    const container = document.getElementById('attack-chain-container');
    if (container) {
        container.innerHTML = '<div class="loading-spinner">Regenerating...</div>';
    }

    // Disable regenerate button
    const regenerateBtn = document.querySelector('button[onclick="regenerateAttackChain()"]');
    if (regenerateBtn) {
        regenerateBtn.disabled = true;
        regenerateBtn.style.opacity = '0.5';
        regenerateBtn.style.cursor = 'not-allowed';
    }

    try {
        // Call the regenerate endpoint
        const response = await apiFetch(`/api/attack-chain/${savedConversationId}/regenerate`, {
            method: 'POST'
        });

        if (!isCurrentAttackChainRequest(savedConversationId, requestSequence)) return;

        if (!response.ok) {
            // Handle 409 Conflict (generation in progress)
            if (response.status === 409) {
                if (container) {
                    container.innerHTML = `
                        <div class="loading-spinner" style="text-align: center; padding: 40px;">
                            <div style="margin-bottom: 16px;">⏳ Attack chain is being generated...</div>
                            <div style="color: var(--text-secondary); font-size: 0.875rem;">
                                Please wait; it will be displayed automatically once generation completes
                            </div>
                            <button class="btn-secondary" onclick="refreshAttackChain()" style="margin-top: 16px;">
                                Refresh to view progress
                            </button>
                        </div>
                    `;
                }
                // Auto-refresh after 5 seconds
                // savedConversationId is defined at the start of the function
                setTimeout(() => {
                    // Only this view's latest request may start another refresh.
                    if (isCurrentAttackChainRequest(savedConversationId, requestSequence)) {
                        refreshAttackChain();
                    }
                }, 5000);
                return;
            }

            const error = await response.json();
            throw new Error(error.error || 'Failed to regenerate attack chain');
        }

        const chainData = await response.json();

        // Check whether the displayed conversation ID matches, to prevent cross-talk
        if (!isCurrentAttackChainRequest(savedConversationId, requestSequence)) {
            console.log('Attack chain data returned, but the displayed conversation has changed; ignoring this render', {
                returned: savedConversationId,
                current: currentAttackChainConversationId
            });
            finishAttackChainRequest(savedConversationId, requestSequence);
            return;
        }

        // Render attack chain
        renderAttackChain(chainData);

        // Update statistics
        updateAttackChainStats(chainData);

    } catch (error) {
        console.error('Failed to regenerate attack chain:', error);
        if (!isCurrentAttackChainRequest(savedConversationId, requestSequence)) return;
        resetAttackChainContext();
        renderAttackChainError(container,
            attackChainFailureText('attackChainModal.regenerateFailed', 'Regeneration failed: ', error.message));
    } finally {
        finishAttackChainRequest(savedConversationId, requestSequence);

        // Restore regenerate button
        if (regenerateBtn && isCurrentAttackChainRequest(savedConversationId, requestSequence)) {
            regenerateBtn.disabled = false;
            regenerateBtn.style.opacity = '1';
            regenerateBtn.style.cursor = 'pointer';
        }
    }
}

// ==================== Attack chain export (polished version) ====================

// XML/HTML escaping
function _acEscapeXml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

// Soft line-wrap by character width (supports mixed Chinese/English text), returns an array of strings
function _acWrapLabel(label, maxChars, maxLines) {
    if (!label) return [''];
    const text = String(label).replace(/\s+/g, ' ').trim();
    if (!text) return [''];
    // Estimate by "character width": CJK counts as 2, others as 1
    const width = (ch) => (/[\u4e00-\u9fa5\uff00-\uffef]/.test(ch) ? 2 : 1);
    const maxW = maxChars * 1.8; // measured in unit width

    const lines = [];
    let buf = '';
    let bufW = 0;
    let lastSpaceIdx = -1;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        const w = width(ch);
        if (ch === ' ') lastSpaceIdx = buf.length;
        if (bufW + w > maxW) {
            // Wrap at spaces (more natural for English)
            let cut = buf;
            let rest = '';
            if (lastSpaceIdx > 0 && lastSpaceIdx >= buf.length - 10) {
                cut = buf.substring(0, lastSpaceIdx);
                rest = buf.substring(lastSpaceIdx + 1);
            }
            lines.push(cut);
            if (lines.length >= maxLines) {
                // Add ellipsis at the end
                const last = lines[lines.length - 1];
                lines[lines.length - 1] = _acTruncateToWidth(last, maxW - 2) + '…';
                return lines;
            }
            buf = rest + ch;
            bufW = 0;
            for (let j = 0; j < buf.length; j++) bufW += width(buf[j]);
            lastSpaceIdx = -1;
        } else {
            buf += ch;
            bufW += w;
        }
    }
    if (buf) lines.push(buf);
    if (lines.length > maxLines) {
        const kept = lines.slice(0, maxLines);
        kept[kept.length - 1] = _acTruncateToWidth(kept[kept.length - 1], maxW - 2) + '…';
        return kept;
    }
    return lines;
}

function _acTruncateToWidth(str, maxW) {
    const width = (ch) => (/[\u4e00-\u9fa5\uff00-\uffef]/.test(ch) ? 2 : 1);
    let w = 0;
    let out = '';
    for (let i = 0; i < str.length; i++) {
        w += width(str[i]);
        if (w > maxW) break;
        out += str[i];
    }
    return out;
}

// Compute the dark primary color for the color (accent dark helper)
function _acDarken(hex, amount) {
    try {
        const h = hex.replace('#', '');
        const r = parseInt(h.substring(0, 2), 16);
        const g = parseInt(h.substring(2, 4), 16);
        const b = parseInt(h.substring(4, 6), 16);
        const f = (c) => Math.max(0, Math.min(255, Math.round(c * (1 - amount))));
        return '#' + [f(r), f(g), f(b)].map(x => x.toString(16).padStart(2, '0')).join('');
    } catch (e) {
        return hex;
    }
}

// Collect the node/edge info needed for export from the current Cytoscape instance
function _acCollectExportData() {
    if (!attackChainCytoscape) return null;
    const nodes = [];
    attackChainCytoscape.nodes().forEach(n => {
        // Filter hidden nodes
        if (n.style('display') === 'none') return;
        const pos = n.position();
        // Read the actual rendered node sizes in Cytoscape to keep the export consistent with the dashboard
        let w = n.outerWidth ? n.outerWidth() : n.width();
        let h = n.outerHeight ? n.outerHeight() : n.height();
        // Fallback
        if (!w || !isFinite(w) || w < 40) w = 280;
        if (!h || !isFinite(h) || h < 30) h = 96;
        nodes.push({
            id: n.id(),
            x: pos.x,
            y: pos.y,
            w: w,
            h: h,
            type: n.data('type') || '',
            typeLabel: n.data('typeLabel') || '',
            typeBadge: n.data('typeBadge') || '•',
            typeColor: n.data('typeColor') || '#334155',
            accentColor: n.data('accentColor') || '#94a3b8',
            bgGradientStart: n.data('bgGradientStart') || '#FFFFFF',
            bgGradientEnd: n.data('bgGradientEnd') || '#F8FAFC',
            riskScore: n.data('riskScore') || 0,
            label: n.data('originalLabel') || n.data('label') || n.id(),
            metadata: n.data('metadata') || {}
        });
    });

    const edges = [];
    attackChainCytoscape.edges().forEach(e => {
        if (e.style('display') === 'none') return;
        const info = getEdgeNodes(e);
        if (!info.valid) return;
        const s = info.source.position();
        const t = info.target.position();
        edges.push({
            id: e.id(),
            source: info.source.id(),
            target: info.target.id(),
            sx: s.x, sy: s.y,
            tx: t.x, ty: t.y,
            type: e.data('type') || 'leads_to'
        });
    });

    return { nodes, edges };
}

// Node type icons (SVG path) — true vector icons
function _acGetNodeIconPath(type) {
    // Path in 24×24 view (scaled to iconSize)
    if (type === 'target') {
        // Target (concentric circles + crosshair)
        return 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm0-14c-3.31 0-6 2.69-6 6s2.69 6 6 6 6-2.69 6-6-2.69-6-6-6zm0 10c-2.21 0-4-1.79-4-4s1.79-4 4-4 4 1.79 4 4-1.79 4-4 4z';
    }
    if (type === 'action') {
        // Lightning (action)
        return 'M7 2v11h3v9l7-12h-4l4-8z';
    }
    if (type === 'vulnerability') {
        // Shield warning
        return 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v6h-2V7zm0 8h2v2h-2v-2z';
    }
    // Default dot
    return 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z';
}

// Get node risk level label (for vulnerability nodes)
function _acGetRiskLabel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score > 0) return 'Low';
    return '';
}

// Generate polished SVG string (premium business report style)
function _acBuildSvgString() {
    const data = _acCollectExportData();
    if (!data || data.nodes.length === 0) throw new Error('No data to export');

    const { nodes, edges } = data;

    // --- Key: unify node sizes to the large card design (SVG uses its own spec) ---
    // SVG export uses larger cards so the information hierarchy stays clear
    nodes.forEach(n => {
        // Reassign SVG width/height based on current positions in Cytoscape
        // Use large cards to show full information
        n.w = 380;
        n.h = 140;
    });

    // Compute the graph bounding box
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(n => {
        minX = Math.min(minX, n.x - n.w / 2);
        minY = Math.min(minY, n.y - n.h / 2);
        maxX = Math.max(maxX, n.x + n.w / 2);
        maxY = Math.max(maxY, n.y + n.h / 2);
    });

    // ==================== Layout parameters ====================
    const GRAPH_PAD = 100;                   // Inner padding of the graph area
    const HEADER_H = 128;                    // Top title bar (enlarged)
    const FOOTER_H = 56;                     // Bottom info bar
    const LEGEND_W = 320;                    // Right legend panel
    const OUTER_PAD = 32;                    // Outermost padding

    const rawGraphW = (maxX - minX) + GRAPH_PAD * 2;
    const rawGraphH = (maxY - minY) + GRAPH_PAD * 2;

    const minGraphW = 900;
    const minGraphH = 620;
    const graphW = Math.max(rawGraphW, minGraphW);
    const graphH = Math.max(rawGraphH, minGraphH);

    const contentW = graphW + LEGEND_W + 36;
    const contentH = graphH + HEADER_H + FOOTER_H + 24;

    const totalW = contentW + OUTER_PAD * 2;
    const totalH = contentH + OUTER_PAD * 2;

    // Position of the graph area in card coordinates
    const graphAreaX = OUTER_PAD + 20;
    const graphAreaY = OUTER_PAD + HEADER_H;
    const graphAreaW = graphW - 4;
    const graphAreaH = contentH - HEADER_H - FOOTER_H;

    // Node coordinate mapping
    const graphCenterOffsetX = (graphAreaW - rawGraphW) / 2;
    const graphCenterOffsetY = (graphAreaH - rawGraphH) / 2;
    const graphOriginX = graphAreaX + GRAPH_PAD + graphCenterOffsetX - minX;
    const graphOriginY = graphAreaY + GRAPH_PAD + graphCenterOffsetY - minY;

    // Legend area coordinates
    const legendX = graphAreaX + graphW + 16;

    // Statistics
    const nodeCount = nodes.length;
    const edgeCount = edges.length;
    const vulnNodes = nodes.filter(n => n.type === 'vulnerability');
    const actionNodes = nodes.filter(n => n.type === 'action');
    const targetNodes = nodes.filter(n => n.type === 'target');
    const criticalCount = vulnNodes.filter(n => n.riskScore >= 80).length;
    const highCount = vulnNodes.filter(n => n.riskScore >= 60 && n.riskScore < 80).length;
    const medCount = vulnNodes.filter(n => n.riskScore >= 40 && n.riskScore < 60).length;
    const lowCount = vulnNodes.filter(n => n.riskScore > 0 && n.riskScore < 40).length;

    const timestamp = new Date();
    const ts = timestamp.getFullYear() + '-' +
        String(timestamp.getMonth() + 1).padStart(2, '0') + '-' +
        String(timestamp.getDate()).padStart(2, '0') + ' ' +
        String(timestamp.getHours()).padStart(2, '0') + ':' +
        String(timestamp.getMinutes()).padStart(2, '0');

    // Type theme colors (premium palette)
    const typeTheme = {
        'target': { primary: '#4F46E5', light: '#EEF2FF', dark: '#3730A3', text: '#312E81', label: 'Target' },
        'action-success': { primary: '#10B981', light: '#ECFDF5', dark: '#047857', text: '#064E3B', label: 'Action' },
        'action-neutral': { primary: '#64748B', light: '#F8FAFC', dark: '#475569', text: '#334155', label: 'Action' },
        'vuln-critical': { primary: '#E11D48', light: '#FFF1F2', dark: '#BE123C', text: '#881337', label: 'Vulnerability' },
        'vuln-high': { primary: '#EA580C', light: '#FFF7ED', dark: '#C2410C', text: '#7C2D12', label: 'Vulnerability' },
        'vuln-med': { primary: '#CA8A04', light: '#FEFCE8', dark: '#A16207', text: '#713F12', label: 'Vulnerability' },
        'vuln-low': { primary: '#0D9488', light: '#F0FDFA', dark: '#0F766E', text: '#134E4A', label: 'Vulnerability' }
    };

    function themeFor(n) {
        if (n.type === 'target') return typeTheme['target'];
        if (n.type === 'action') {
            const m = n.metadata || {};
            const findings = m.findings || [];
            const hasFindings = Array.isArray(findings) && findings.length > 0;
            const isFailed = m.status === 'failed_insight';
            return (hasFindings && !isFailed) ? typeTheme['action-success'] : typeTheme['action-neutral'];
        }
        if (n.type === 'vulnerability') {
            const s = n.riskScore || 0;
            if (s >= 80) return typeTheme['vuln-critical'];
            if (s >= 60) return typeTheme['vuln-high'];
            if (s >= 40) return typeTheme['vuln-med'];
            return typeTheme['vuln-low'];
        }
        return typeTheme['action-neutral'];
    }

    // Edge start/end themes
    const nodesMap = new Map(nodes.map(n => [n.id, n]));

    // ==================== Begin assembling SVG ====================
    const parts = [];
    parts.push(`<?xml version="1.0" encoding="UTF-8"?>`);
    parts.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${totalW}" height="${totalH}" viewBox="0 0 ${totalW} ${totalH}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', 'Hiragino Sans GB', Roboto, Helvetica, Arial, sans-serif">`);

    // ==================== defs ====================
    parts.push(`<defs>`);

    // Root background gradient: very pale warm gray
    parts.push(`<linearGradient id="ac-bg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#FAFBFC"/>
        <stop offset="100%" stop-color="#F1F5F9"/>
    </linearGradient>`);

    // Corner glow
    parts.push(`<radialGradient id="ac-glow-1" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="#6366F1" stop-opacity="0.12"/>
        <stop offset="100%" stop-color="#6366F1" stop-opacity="0"/>
    </radialGradient>`);
    parts.push(`<radialGradient id="ac-glow-2" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="#EC4899" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="#EC4899" stop-opacity="0"/>
    </radialGradient>`);
    parts.push(`<radialGradient id="ac-glow-3" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="#06B6D4" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="#06B6D4" stop-opacity="0"/>
    </radialGradient>`);

    // Brand gradient (for the title)
    parts.push(`<linearGradient id="ac-brand" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#4F46E5"/>
        <stop offset="50%" stop-color="#7C3AED"/>
        <stop offset="100%" stop-color="#EC4899"/>
    </linearGradient>`);

    // Grid dot pattern (very faint)
    parts.push(`<pattern id="ac-dot" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
        <circle cx="12" cy="12" r="1" fill="#0F172A" fill-opacity="0.06"/>
    </pattern>`);

    // Node card shadow (multi-layer shadow for more depth)
    parts.push(`<filter id="ac-shadow-card" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="1" stdDeviation="1.5" flood-color="#0F172A" flood-opacity="0.06"/>
        <feDropShadow dx="0" dy="6" stdDeviation="12" flood-color="#0F172A" flood-opacity="0.08"/>
    </filter>`);

    // Icon badge shadow
    parts.push(`<filter id="ac-shadow-icon" x="-30%" y="-30%" width="160%" height="160%">
        <feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#0F172A" flood-opacity="0.15"/>
    </filter>`);

    // Risk badge shadow
    parts.push(`<filter id="ac-shadow-badge" x="-30%" y="-30%" width="160%" height="160%">
        <feDropShadow dx="0" dy="1.5" stdDeviation="2.5" flood-color="#0F172A" flood-opacity="0.18"/>
    </filter>`);

    // Define icon gradients for each node (for large icons)
    Object.keys(typeTheme).forEach(key => {
        const t = typeTheme[key];
        parts.push(`<linearGradient id="ac-icon-grad-${key}" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="${t.primary}"/>
            <stop offset="100%" stop-color="${t.dark}"/>
        </linearGradient>`);
    });

    // Edges use gradients (source -> target)
    edges.forEach((e, idx) => {
        const sNode = nodesMap.get(e.source);
        const tNode = nodesMap.get(e.target);
        if (!sNode || !tNode) return;
        const sTheme = themeFor(sNode);
        const tTheme = themeFor(tNode);
        parts.push(`<linearGradient id="ac-edge-grad-${idx}" gradientUnits="userSpaceOnUse" x1="${e.sx}" y1="${e.sy}" x2="${e.tx}" y2="${e.ty}">
            <stop offset="0%" stop-color="${sTheme.primary}" stop-opacity="0.7"/>
            <stop offset="100%" stop-color="${tTheme.primary}" stop-opacity="0.9"/>
        </linearGradient>`);
    });

    // Define arrow markers for each theme color
    Object.keys(typeTheme).forEach(key => {
        const t = typeTheme[key];
        parts.push(`<marker id="ac-arrow-${key}" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="8" markerHeight="8" orient="auto-start-reverse" markerUnits="strokeWidth">
            <path d="M 0 0 L 12 6 L 0 12 L 3 6 Z" fill="${t.primary}"/>
        </marker>`);
    });

    parts.push(`</defs>`);

    // ==================== Background ====================
    parts.push(`<rect x="0" y="0" width="${totalW}" height="${totalH}" fill="url(#ac-bg)"/>`);
    // Corner glow
    parts.push(`<ellipse cx="${totalW * 0.1}" cy="${totalH * 0.15}" rx="${totalW * 0.4}" ry="${totalH * 0.4}" fill="url(#ac-glow-1)"/>`);
    parts.push(`<ellipse cx="${totalW * 0.9}" cy="${totalH * 0.85}" rx="${totalW * 0.35}" ry="${totalH * 0.35}" fill="url(#ac-glow-2)"/>`);
    parts.push(`<ellipse cx="${totalW * 0.5}" cy="${totalH * 0.1}" rx="${totalW * 0.3}" ry="${totalH * 0.3}" fill="url(#ac-glow-3)"/>`);

    // ==================== Main card ====================
    parts.push(`<rect x="${OUTER_PAD}" y="${OUTER_PAD}" width="${contentW}" height="${contentH}" rx="24" ry="24" fill="#FFFFFF" stroke="rgba(15,23,42,0.06)" stroke-width="1" filter="url(#ac-shadow-card)"/>`);

    // ==================== Top title bar ====================
    const tX = OUTER_PAD + 40;
    const tY = OUTER_PAD + 28;

    // Left logo block (large, gradient, stylish)
    parts.push(`<g filter="url(#ac-shadow-icon)">`);
    parts.push(`<rect x="${tX - 4}" y="${tY}" width="48" height="48" rx="12" fill="url(#ac-brand)"/>`);
    // Logo icon (hexagon + lightning)
    parts.push(`<g transform="translate(${tX - 4 + 12}, ${tY + 12}) scale(0.9)">
        <path d="M12 2L3 7v10l9 5 9-5V7z" fill="none" stroke="#FFFFFF" stroke-width="1.8" stroke-linejoin="round"/>
        <path d="M10 7l-2 5h3l-1 4 4-5h-3l1-4z" fill="#FFFFFF"/>
    </g>`);
    parts.push(`</g>`);

    // Main title (extra large, bold)
    parts.push(`<text x="${tX + 56}" y="${tY + 26}" font-size="26" font-weight="800" fill="#0F172A" letter-spacing="-0.6px">Attack Chain Visualization Report</text>`);

    // Subtitle (small text, secondary color)
    parts.push(`<text x="${tX + 56}" y="${tY + 50}" font-size="13" font-weight="500" fill="#64748B" letter-spacing="0.1px">Attack Chain Analysis · ${_acEscapeXml(ts)}</text>`);

    // Top right: key stat pills (3)
    const kpiY = OUTER_PAD + 28;
    const kpiH = 48;
    const kpiGap = 12;
    const kpiW = 110;
    const kpiItems = [
        { label: 'Nodes', value: nodeCount, color: '#4F46E5' },
        { label: 'Edges', value: edgeCount, color: '#06B6D4' },
        { label: 'Critical vulns', value: criticalCount, color: criticalCount > 0 ? '#E11D48' : '#94A3B8' }
    ];
    let kpiXStart = OUTER_PAD + contentW - 40 - (kpiW * kpiItems.length + kpiGap * (kpiItems.length - 1));
    kpiItems.forEach((kpi, i) => {
        const kx = kpiXStart + i * (kpiW + kpiGap);
        // Card background
        parts.push(`<rect x="${kx}" y="${kpiY}" width="${kpiW}" height="${kpiH}" rx="12" fill="#FFFFFF" stroke="${kpi.color}" stroke-opacity="0.15" stroke-width="1"/>`);
        // Left thin bar
        parts.push(`<rect x="${kx}" y="${kpiY + 10}" width="3" height="${kpiH - 20}" rx="1.5" fill="${kpi.color}"/>`);
        // Value (large)
        parts.push(`<text x="${kx + 16}" y="${kpiY + 26}" font-size="20" font-weight="800" fill="#0F172A" letter-spacing="-0.4px">${kpi.value}</text>`);
        // Label (small)
        parts.push(`<text x="${kx + 16}" y="${kpiY + 40}" font-size="10.5" font-weight="600" fill="#64748B" letter-spacing="0.4px">${_acEscapeXml(kpi.label)}</text>`);
    });

    // Title divider (gradient fade)
    parts.push(`<line x1="${OUTER_PAD + 40}" y1="${OUTER_PAD + HEADER_H - 10}" x2="${OUTER_PAD + contentW - 40}" y2="${OUTER_PAD + HEADER_H - 10}" stroke="rgba(15,23,42,0.08)" stroke-width="1"/>`);

    // ==================== Graph area ====================
    parts.push(`<rect x="${graphAreaX}" y="${graphAreaY}" width="${graphAreaW}" height="${graphAreaH}" rx="18" fill="#FCFCFD" stroke="rgba(15,23,42,0.05)" stroke-width="1"/>`);
    parts.push(`<rect x="${graphAreaX}" y="${graphAreaY}" width="${graphAreaW}" height="${graphAreaH}" rx="18" fill="url(#ac-dot)" opacity="0.7"/>`);

    // ==================== Begin drawing graphics ====================
    parts.push(`<g transform="translate(${graphOriginX}, ${graphOriginY})">`);

    // ---- Edges (gradient, soft curves) ----
    edges.forEach((e, idx) => {
        const sNode = nodesMap.get(e.source);
        const tNode = nodesMap.get(e.target);
        if (!sNode || !tNode) return;
        const tTheme = themeFor(tNode);

        const dx = e.tx - e.sx;
        const dy = e.ty - e.sy;
        const mag = Math.sqrt(dx * dx + dy * dy) || 1;
        const offset = Math.min(80, mag * 0.25);
        const nx = -dy / mag;
        const ny = dx / mag;
        const cx = (e.sx + e.tx) / 2 + nx * offset;
        const cy = (e.sy + e.ty) / 2 + ny * offset;
        const shrink = 22;
        const ex = e.tx - (dx / mag) * shrink;
        const ey = e.ty - (dy / mag) * shrink;

        const strokeWidth = (e.type === 'discovers' || e.type === 'enables') ? 2.4 : 2;
        const strokeDash = e.type === 'targets' ? 'stroke-dasharray="10,5"' : '';
        // Target arrow key (based on the target node's theme)
        const targetThemeKey = Object.keys(typeTheme).find(k => typeTheme[k] === tTheme) || 'action-neutral';

        // First draw a subtle halo (background glow)
        parts.push(`<path d="M ${e.sx.toFixed(1)} ${e.sy.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${ex.toFixed(1)} ${ey.toFixed(1)}" fill="none" stroke="${tTheme.primary}" stroke-width="${strokeWidth + 4}" stroke-linecap="round" stroke-opacity="0.08" ${strokeDash}/>`);
        // Main line
        parts.push(`<path d="M ${e.sx.toFixed(1)} ${e.sy.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${ex.toFixed(1)} ${ey.toFixed(1)}" fill="none" stroke="url(#ac-edge-grad-${idx})" stroke-width="${strokeWidth}" stroke-linecap="round" ${strokeDash} marker-end="url(#ac-arrow-${targetThemeKey})"/>`);
    });

    // ---- Nodes (large card design) ----
    nodes.forEach((n, i) => {
        const theme = themeFor(n);
        const themeKey = Object.keys(typeTheme).find(k => typeTheme[k] === theme) || 'action-neutral';

        const x = n.x - n.w / 2;
        const y = n.y - n.h / 2;
        const r = 18;  // corner radius

        // ========== Card body ==========
        // Soft shadow + pure white background
        parts.push(`<g filter="url(#ac-shadow-card)">`);
        parts.push(`<rect x="${x}" y="${y}" width="${n.w}" height="${n.h}" rx="${r}" fill="#FFFFFF"/>`);
        parts.push(`</g>`);
        // Top theme color strip (very faint gradient)
        parts.push(`<rect x="${x}" y="${y}" width="${n.w}" height="${n.h}" rx="${r}" fill="${theme.primary}" fill-opacity="0.02"/>`);
        // Thin border
        parts.push(`<rect x="${x}" y="${y}" width="${n.w}" height="${n.h}" rx="${r}" fill="none" stroke="${theme.primary}" stroke-opacity="0.18" stroke-width="1"/>`);
        // Top colored decoration bar (dot sequence or gradient bar)
        parts.push(`<rect x="${x + 20}" y="${y}" width="${n.w - 40}" height="3" rx="1.5" fill="${theme.primary}" fill-opacity="0.5"/>`);

        const padX = 24;
        const padY = 22;

        // ========== Top: large icon + type label + right badge ==========
        const iconSize = 44;
        const iconX = x + padX;
        const iconY = y + padY;

        // Icon background (gradient square)
        parts.push(`<g filter="url(#ac-shadow-icon)">`);
        parts.push(`<rect x="${iconX}" y="${iconY}" width="${iconSize}" height="${iconSize}" rx="12" fill="url(#ac-icon-grad-${themeKey})"/>`);
        parts.push(`</g>`);
        // Icon path (white, scaled)
        const iconPath = _acGetNodeIconPath(n.type);
        const iconScale = (iconSize * 0.55) / 24;
        const iconInnerOffset = (iconSize - 24 * iconScale) / 2;
        parts.push(`<g transform="translate(${iconX + iconInnerOffset}, ${iconY + iconInnerOffset}) scale(${iconScale.toFixed(3)})">
            <path d="${iconPath}" fill="#FFFFFF"/>
        </g>`);

        // Type label (right of the icon)
        const typeTextX = iconX + iconSize + 14;
        // English type label (TYPE LABEL, small faint text)
        const typeEn = n.type === 'target' ? 'TARGET' : n.type === 'action' ? 'ACTION' : n.type === 'vulnerability' ? 'VULNERABILITY' : (n.type || '').toUpperCase();
        parts.push(`<text x="${typeTextX}" y="${iconY + 14}" font-size="10" font-weight="700" fill="${theme.dark}" fill-opacity="0.75" letter-spacing="1.2px">${_acEscapeXml(typeEn)}</text>`);
        // Type label (large, primary color)
        parts.push(`<text x="${typeTextX}" y="${iconY + 34}" font-size="16" font-weight="700" fill="${theme.text}" letter-spacing="-0.2px">${_acEscapeXml(theme.label)}</text>`);

        // ========== Top-right badge ==========
        const badgeY = iconY + 2;
        const badgeH = 26;
        if (n.type === 'vulnerability' && n.riskScore > 0) {
            // Risk score badge (large, gradient background)
            const riskLabel = _acGetRiskLabel(n.riskScore);
            const badgeText = `${riskLabel} · ${n.riskScore}`;
            const badgeW = 90;
            const bx = x + n.w - badgeW - padX;
            parts.push(`<g filter="url(#ac-shadow-badge)">`);
            parts.push(`<rect x="${bx}" y="${badgeY}" width="${badgeW}" height="${badgeH}" rx="${badgeH / 2}" fill="url(#ac-icon-grad-${themeKey})"/>`);
            parts.push(`<text x="${bx + badgeW / 2}" y="${badgeY + badgeH / 2 + 4.5}" text-anchor="middle" font-size="12" font-weight="700" fill="#FFFFFF" letter-spacing="0.2px">${_acEscapeXml(badgeText)}</text>`);
            parts.push(`</g>`);
        } else if (n.type === 'action') {
            const m = n.metadata || {};
            const findings = m.findings || [];
            const hasFindings = Array.isArray(findings) && findings.length > 0;
            const isFailed = m.status === 'failed_insight';
            if (hasFindings || isFailed) {
                const text = isFailed ? 'Leads' : `Findings ${findings.length}`;
                const badgeW = 70;
                const bx = x + n.w - badgeW - padX;
                parts.push(`<rect x="${bx}" y="${badgeY}" width="${badgeW}" height="${badgeH}" rx="${badgeH / 2}" fill="${theme.primary}" fill-opacity="0.12" stroke="${theme.primary}" stroke-opacity="0.4" stroke-width="1"/>`);
                // Small dot (status indicator)
                parts.push(`<circle cx="${bx + 12}" cy="${badgeY + badgeH / 2}" r="3" fill="${theme.primary}"/>`);
                parts.push(`<text x="${bx + 20}" y="${badgeY + badgeH / 2 + 4.5}" font-size="11.5" font-weight="700" fill="${theme.dark}">${_acEscapeXml(text)}</text>`);
            }
        } else if (n.type === 'target') {
            // Target nodes show a "Target" badge
            const badgeW = 60;
            const bx = x + n.w - badgeW - padX;
            parts.push(`<rect x="${bx}" y="${badgeY}" width="${badgeW}" height="${badgeH}" rx="${badgeH / 2}" fill="${theme.primary}" fill-opacity="0.12" stroke="${theme.primary}" stroke-opacity="0.4" stroke-width="1"/>`);
            parts.push(`<text x="${bx + badgeW / 2}" y="${badgeY + badgeH / 2 + 4.5}" text-anchor="middle" font-size="11.5" font-weight="700" fill="${theme.dark}" letter-spacing="0.3px">Main target</text>`);
        }

        // ========== Main title ==========
        const contentTopY = iconY + iconSize + 18;
        const titleFontSize = 16;
        const titleLineH = titleFontSize + 6;
        const contentAvailW = n.w - padX * 2;
        const charsPerLine = Math.max(10, Math.floor(contentAvailW / (titleFontSize * 0.58)));
        const titleLines = _acWrapLabel(n.label, charsPerLine, 2);
        titleLines.forEach((ln, idx) => {
            parts.push(`<text x="${x + padX}" y="${contentTopY + idx * titleLineH}" font-size="${titleFontSize}" font-weight="700" fill="#0F172A" letter-spacing="-0.2px">${_acEscapeXml(ln)}</text>`);
        });

        // ========== Bottom meta bar ==========
        const metaY = y + n.h - 22;
        // Divider
        parts.push(`<line x1="${x + padX}" y1="${metaY - 10}" x2="${x + n.w - padX}" y2="${metaY - 10}" stroke="rgba(15,23,42,0.06)" stroke-width="1"/>`);

        // Generate meta text
        const metaItems = [];
        if (n.type === 'target') {
            const tgt = (n.metadata && n.metadata.target) ? n.metadata.target : null;
            if (tgt) metaItems.push({ icon: 'loc', text: _acTruncateToWidth(tgt, 26) });
        } else if (n.type === 'action') {
            const toolName = n.metadata && n.metadata.tool_name;
            if (toolName) metaItems.push({ icon: 'tool', text: _acTruncateToWidth(toolName, 20) });
            const intent = n.metadata && n.metadata.tool_intent;
            if (intent) metaItems.push({ icon: 'aim', text: _acTruncateToWidth(intent, 22) });
        } else if (n.type === 'vulnerability') {
            const vt = n.metadata && n.metadata.vulnerability_type;
            if (vt) metaItems.push({ icon: 'shield', text: _acTruncateToWidth(vt, 22) });
            const sev = n.metadata && n.metadata.severity;
            if (sev) metaItems.push({ icon: 'alert', text: _acTruncateToWidth(sev, 12) });
        }
        if (metaItems.length === 0) {
            // When there is no meta info, show a short version of the node ID
            metaItems.push({ icon: 'hash', text: _acTruncateToWidth(n.id || '', 20) });
        }

        // Meta icon path (24x24)
        const metaIconPaths = {
            'loc': 'M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5a2.5 2.5 0 1 1 0-5 2.5 2.5 0 0 1 0 5z',
            'tool': 'M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4z',
            'aim': 'M12 2L4 5v6c0 5.5 3.8 10.7 8 12 4.2-1.3 8-6.5 8-12V5l-8-3zm4 10H8V9h3V7l3 3-3 3v-1z',
            'shield': 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.4-1.4 2.6 2.6 6.6-6.6L18 9l-8 8z',
            'alert': 'M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z',
            'hash': 'M20 9h-4.5l.9-4h-2l-.9 4H9l.9-4H8l-.9 4H3v2h3.7l-1 4H2v2h3.3l-.9 4h2l.9-4H12l-.9 4h2l.9-4H19v-2h-4.7l1-4H20V9zm-6.3 6H9l1-4h4.7l-1 4z'
        };

        let metaX = x + padX;
        metaItems.forEach((mi, idx) => {
            if (idx > 0) {
                // Separator
                parts.push(`<circle cx="${metaX + 6}" cy="${metaY}" r="1.2" fill="#CBD5E1"/>`);
                metaX += 14;
            }
            // Icon
            const path = metaIconPaths[mi.icon] || metaIconPaths.hash;
            parts.push(`<g transform="translate(${metaX}, ${metaY - 7}) scale(${(13 / 24).toFixed(3)})">
                <path d="${path}" fill="${theme.primary}" fill-opacity="0.8"/>
            </g>`);
            metaX += 18;
            // Text
            parts.push(`<text x="${metaX}" y="${metaY + 3}" font-size="11.5" font-weight="500" fill="#64748B">${_acEscapeXml(mi.text)}</text>`);
            metaX += mi.text.length * 6.5;  // Rough estimate
        });
    });

    parts.push(`</g>`);

    // ==================== Right legend ====================
    const lx = legendX;
    const ly = graphAreaY;
    const lw = LEGEND_W - 16;
    const lh = graphAreaH;

    // Legend main card
    parts.push(`<rect x="${lx}" y="${ly}" width="${lw}" height="${lh}" rx="18" fill="#FFFFFF" stroke="rgba(15,23,42,0.06)" stroke-width="1"/>`);
    // Top colored decoration
    parts.push(`<rect x="${lx + 16}" y="${ly}" width="${lw - 32}" height="3" rx="1.5" fill="url(#ac-brand)"/>`);

    let curY = ly + 26;

    // --- Node types ---
    parts.push(`<text x="${lx + 24}" y="${curY}" font-size="10.5" font-weight="800" fill="#64748B" letter-spacing="1.5px">NODE TYPES</text>`);
    curY += 22;
    const typeSummary = [
        { key: 'target', count: targetNodes.length, text: 'Target' },
        { key: 'action-success', count: actionNodes.filter(a => { const m = a.metadata || {}; return Array.isArray(m.findings) && m.findings.length > 0 && m.status !== 'failed_insight'; }).length, text: 'Action (with findings)' },
        { key: 'action-neutral', count: actionNodes.filter(a => { const m = a.metadata || {}; const f = Array.isArray(m.findings) ? m.findings : []; return f.length === 0 || m.status === 'failed_insight'; }).length, text: 'Action (other)' },
        { key: 'vuln-critical', count: criticalCount, text: 'Critical vulns' },
        { key: 'vuln-high', count: highCount, text: 'High-risk vulns' },
        { key: 'vuln-med', count: medCount, text: 'Medium-risk vulns' },
        { key: 'vuln-low', count: lowCount, text: 'Low-risk vulns' }
    ];
    typeSummary.forEach(item => {
        const t = typeTheme[item.key];
        if (item.count === 0) return;  // Hide zero-count items
        // Icon square
        parts.push(`<rect x="${lx + 24}" y="${curY - 10}" width="14" height="14" rx="4" fill="${t.primary}"/>`);
        // Label text
        parts.push(`<text x="${lx + 46}" y="${curY + 1}" font-size="12.5" font-weight="500" fill="#334155">${_acEscapeXml(item.text)}</text>`);
        // Count
        parts.push(`<text x="${lx + lw - 24}" y="${curY + 1}" font-size="12.5" font-weight="700" fill="#0F172A" text-anchor="end">${item.count}</text>`);
        curY += 22;
    });
    curY += 10;

    // --- Connection meanings ---
    parts.push(`<text x="${lx + 24}" y="${curY}" font-size="10.5" font-weight="800" fill="#64748B" letter-spacing="1.5px">CONNECTIONS</text>`);
    curY += 22;
    const lineItems = [
        { label: 'Action finds vulnerability', color: '#4F46E5', dash: '' },
        { label: 'Enables / leads to', color: '#E11D48', dash: '' },
        { label: 'Logical order', color: '#64748B', dash: '' },
        { label: 'Target location', color: '#4F46E5', dash: '6,3' }
    ];
    lineItems.forEach(l => {
        const dashAttr = l.dash ? `stroke-dasharray="${l.dash}"` : '';
        parts.push(`<line x1="${lx + 24}" y1="${curY - 3}" x2="${lx + 62}" y2="${curY - 3}" stroke="${l.color}" stroke-width="2.4" stroke-linecap="round" ${dashAttr}/>`);
        parts.push(`<polygon points="${lx + 62},${curY - 6} ${lx + 68},${curY - 3} ${lx + 62},${curY}" fill="${l.color}"/>`);
        parts.push(`<text x="${lx + 78}" y="${curY + 1}" font-size="12.5" font-weight="500" fill="#334155">${_acEscapeXml(l.label)}</text>`);
        curY += 24;
    });
    curY += 10;

    // --- Risk level bar ---
    parts.push(`<text x="${lx + 24}" y="${curY}" font-size="10.5" font-weight="800" fill="#64748B" letter-spacing="1.5px">RISK LEVELS</text>`);
    curY += 22;
    const riskBar = [
        { label: 'Critical', range: '80-100', color: '#E11D48' },
        { label: 'High', range: '60-79', color: '#EA580C' },
        { label: 'Medium', range: '40-59', color: '#CA8A04' },
        { label: 'Low', range: '0-39', color: '#0D9488' }
    ];
    riskBar.forEach(r => {
        // Risk level pill
        parts.push(`<rect x="${lx + 24}" y="${curY - 10}" width="46" height="18" rx="9" fill="${r.color}"/>`);
        parts.push(`<text x="${lx + 47}" y="${curY + 2}" text-anchor="middle" font-size="10.5" font-weight="700" fill="#FFFFFF" letter-spacing="0.3px">${_acEscapeXml(r.label)}</text>`);
        // Score range
        parts.push(`<text x="${lx + 80}" y="${curY + 1}" font-size="12" font-weight="500" fill="#64748B">Score ${_acEscapeXml(r.range)}</text>`);
        curY += 26;
    });

    // ==================== Bottom info bar ====================
    const fY = OUTER_PAD + contentH - FOOTER_H;
    // Divider
    parts.push(`<line x1="${OUTER_PAD + 40}" y1="${fY + 16}" x2="${OUTER_PAD + contentW - 40}" y2="${fY + 16}" stroke="rgba(15,23,42,0.06)" stroke-width="1"/>`);
    // Left brand
    parts.push(`<circle cx="${OUTER_PAD + 44}" cy="${fY + 34}" r="5" fill="url(#ac-brand)"/>`);
    parts.push(`<text x="${OUTER_PAD + 56}" y="${fY + 38}" font-size="11.5" font-weight="600" fill="#64748B">VeritySec <tspan fill="#94A3B8" font-weight="500">· Attack Chain Visualization Report</tspan></text>`);
    // Right timestamp
    parts.push(`<text x="${OUTER_PAD + contentW - 40}" y="${fY + 38}" font-size="11.5" font-weight="500" fill="#94A3B8" text-anchor="end">${_acEscapeXml(ts)}</text>`);

    parts.push(`</svg>`);
    return parts.join('\n');
}

// Download text file
function _acDownloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 150);
}

// Generate high-resolution PNG from SVG string
function _acSvgToPng(svgString, scale) {
    return new Promise((resolve, reject) => {
        try {
            // Read SVG dimensions
            const m = svgString.match(/<svg[^>]*width="(\d+(?:\.\d+)?)"[^>]*height="(\d+(?:\.\d+)?)"/i);
            const w = m ? parseFloat(m[1]) : 1600;
            const h = m ? parseFloat(m[2]) : 900;
            const s = scale || Math.min(2.5, Math.max(1.5, 2000 / Math.max(w, h)));

            const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const img = new Image();
            img.onload = function () {
                try {
                    const canvas = document.createElement('canvas');
                    canvas.width = Math.round(w * s);
                    canvas.height = Math.round(h * s);
                    const ctx = canvas.getContext('2d');
                    ctx.imageSmoothingEnabled = true;
                    ctx.imageSmoothingQuality = 'high';
                    ctx.fillStyle = '#ffffff';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);
                    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                    URL.revokeObjectURL(url);
                    canvas.toBlob(pngBlob => {
                        if (!pngBlob) reject(new Error('PNG generation failed'));
                        else resolve(pngBlob);
                    }, 'image/png', 0.95);
                } catch (err) {
                    URL.revokeObjectURL(url);
                    reject(err);
                }
            };
            img.onerror = function (e) {
                URL.revokeObjectURL(url);
                reject(new Error('SVG load failed'));
            };
            img.src = url;
        } catch (e) {
            reject(e);
        }
    });
}

// Export attack chain (polished version)
function exportAttackChain(format) {
    if (!attackChainCytoscape) {
        alert(typeof window.t === 'function' ? window.t('chat.pleaseLoadAttackChainFirst', {}, 'Load the attack chain first') : 'Load the attack chain first');
        return;
    }

    // Delay to ensure rendering completes
    setTimeout(() => {
        try {
            const svgString = _acBuildSvgString();
            const convId = currentAttackChainConversationId || 'export';
            const tsName = Date.now();

            if (format === 'svg') {
                const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
                _acDownloadBlob(blob, `attack-chain-${convId}-${tsName}.svg`);
            } else if (format === 'png') {
                _acSvgToPng(svgString, 2)
                    .then(pngBlob => _acDownloadBlob(pngBlob, `attack-chain-${convId}-${tsName}.png`))
                    .catch(err => {
                        console.error('PNG export failed; falling back to native Cytoscape export:', err);
                        // Fallback: use Cytoscape's built-in export
                        try {
                            const p = attackChainCytoscape.png({ output: 'blob', bg: '#ffffff', full: true, scale: 2 });
                            if (p && typeof p.then === 'function') {
                                p.then(b => _acDownloadBlob(b, `attack-chain-${convId}-${tsName}.png`))
                                    .catch(e => alert('PNG export failed: ' + (e && e.message || e)));
                            } else if (p) {
                                _acDownloadBlob(p, `attack-chain-${convId}-${tsName}.png`);
                            } else {
                                alert('PNG export failed');
                            }
                        } catch (e2) {
                            alert('PNG export failed: ' + (e2 && e2.message || e2));
                        }
                    });
            } else {
                alert('Unsupported export format: ' + format);
            }
        } catch (error) {
            console.error('Export failed:', error);
            alert('Export failed: ' + (error && error.message || 'Unknown error'));
        }
    }, 80);
}

// ============================================
// Conversation batch management
// ============================================

let contextMenuConversationId = null;
let contextMenuConversationTitle = '';
let conversationsListLoadSeq = 0; // Conversation list load sequence, to avoid duplicate renders from concurrent requests
let conversationsListNavigateGen = 0; // Generation counter for user-initiated paging, to prevent background refresh from overwriting paging results
const CONVERSATIONS_PAGE_SIZE_KEY = 'veritysec.conversations_page_size';
const CONVERSATIONS_SORT_KEY = 'veritysec.conversations_sort_by';
const CONVERSATIONS_PROJECT_FILTER_KEY = 'veritysec.conversations_project_filter';
const CONVERSATION_PROJECT_FILTER_NONE = '__none__';
const CONVERSATION_PROJECT_FILTER_SELECT_ID = 'conversation-project-filter';
const CONVERSATION_PROJECT_FILTER_CARET = '<svg class="conversation-project-filter-caret" width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const BATCH_PROJECT_FILTER_SELECT_ID = 'batch-project-filter';
const projectFilterCustomSelectRegistry = {};
let projectFilterCustomSelectDocBound = false;

function projectFilterT(key, fallback) {
    if (typeof window.t === 'function') {
        const value = window.t(key);
        if (value && value !== key) return value;
    }
    return fallback;
}

function closeProjectFilterCustomSelect(selectId) {
    const reg = projectFilterCustomSelectRegistry[selectId];
    if (!reg || !reg.wrapper) return;
    reg.wrapper.classList.remove('open');
    if (reg.trigger) reg.trigger.setAttribute('aria-expanded', 'false');
    if (reg.filterSearchTimer) {
        clearTimeout(reg.filterSearchTimer);
        reg.filterSearchTimer = null;
    }
    reg.filterSearchSeq = (reg.filterSearchSeq || 0) + 1;
    if (reg.searchInput) reg.searchInput.value = '';
}

function closeAllProjectFilterCustomSelects() {
    Object.keys(projectFilterCustomSelectRegistry).forEach(closeProjectFilterCustomSelect);
}

function ensureProjectFilterSearchUi(reg) {
    if (reg.searchInput && reg.optionsList) return;
    const { dropdown } = reg;
    dropdown.innerHTML = '';

    const searchWrap = document.createElement('div');
    searchWrap.className = 'conversation-project-filter-search';
    const searchInput = document.createElement('input');
    searchInput.type = 'search';
    searchInput.className = 'conversation-project-filter-search-input';
    searchInput.setAttribute('autocomplete', 'off');
    searchInput.setAttribute('data-i18n', 'chat.filterProjectSearch');
    searchInput.setAttribute('data-i18n-attr', 'placeholder');
    searchInput.placeholder = projectFilterT('chat.filterProjectSearch', 'Search projects…');
    searchWrap.appendChild(searchInput);
    dropdown.appendChild(searchWrap);
    reg.searchInput = searchInput;

    const optionsList = document.createElement('div');
    optionsList.className = 'conversation-project-filter-options';
    dropdown.appendChild(optionsList);
    reg.optionsList = optionsList;
    reg.filterSearchSeq = 0;
    reg.filterSearchTimer = null;

    searchInput.addEventListener('input', () => loadProjectFilterLocalOptions(reg.select.id));
    searchInput.addEventListener('click', (e) => e.stopPropagation());
    searchInput.addEventListener('keydown', (e) => {
        e.stopPropagation();
        if (e.key === 'Escape') closeProjectFilterCustomSelect(reg.select.id);
    });
}

function createProjectFilterOptionButton(value, label, selectedValue) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'conversation-project-filter-option';
    item.setAttribute('role', 'option');
    item.setAttribute('data-value', value);
    item.title = label;
    if (value === selectedValue) {
        item.classList.add('is-selected');
        item.setAttribute('aria-selected', 'true');
    } else {
        item.setAttribute('aria-selected', 'false');
    }
    const check = document.createElement('span');
    check.className = 'conversation-project-filter-check';
    check.setAttribute('aria-hidden', 'true');
    check.textContent = '✓';
    const labelEl = document.createElement('span');
    labelEl.className = 'conversation-project-filter-option-label';
    labelEl.textContent = label;
    labelEl.title = label;
    item.appendChild(check);
    item.appendChild(labelEl);
    return item;
}

function appendProjectFilterStatusMessage(optionsList, className, text) {
    const el = document.createElement('div');
    el.className = className;
    el.textContent = text;
    optionsList.appendChild(el);
    return el;
}

function renderProjectFilterPinnedOptions(reg) {
    const { select, optionsList } = reg;
    optionsList.innerHTML = '';
    Array.prototype.forEach.call(select.options, (opt) => {
        if (opt.value === '' || opt.value === CONVERSATION_PROJECT_FILTER_NONE) {
            optionsList.appendChild(createProjectFilterOptionButton(opt.value, opt.textContent || '', select.value));
        }
    });
}

function ensureNativeProjectFilterOption(select, projectId, label) {
    if (!projectId || projectId === CONVERSATION_PROJECT_FILTER_NONE) return;
    if (Array.prototype.some.call(select.options, (opt) => opt.value === projectId)) return;
    const opt = document.createElement('option');
    opt.value = projectId;
    opt.textContent = label || projectId;
    select.appendChild(opt);
}

async function loadProjectFilterLocalOptions(selectId) {
    const reg = projectFilterCustomSelectRegistry[selectId];
    if (!reg || !reg.optionsList) return;
    const query = (reg.searchInput?.value || '').trim();
    const seq = ++reg.filterSearchSeq;

    const needsFetch = typeof window.isProjectsCacheReady === 'function' && !window.isProjectsCacheReady();
    let loadingEl = null;
    if (needsFetch) {
        renderProjectFilterPinnedOptions(reg);
        loadingEl = appendProjectFilterStatusMessage(
            reg.optionsList,
            'conversation-project-filter-status',
            projectFilterT('common.loading', 'Loading…')
        );
    }

    try {
        const ensureLoaded = typeof window.ensureProjectsLoaded === 'function'
            ? window.ensureProjectsLoaded
            : null;
        const filterLocal = typeof window.filterActiveProjectsLocal === 'function'
            ? window.filterActiveProjectsLocal
            : null;
        if (!ensureLoaded || !filterLocal) throw new Error('projects cache unavailable');

        const all = await ensureLoaded();
        if (seq !== reg.filterSearchSeq) return;

        renderProjectFilterPinnedOptions(reg);
        const selected = reg.select.value;
        const pinnedValues = new Set(['', CONVERSATION_PROJECT_FILTER_NONE]);
        const projects = filterLocal(all, query);
        projects.forEach((p) => {
            if (pinnedValues.has(p.id)) return;
            reg.optionsList.appendChild(
                createProjectFilterOptionButton(p.id, p.name || p.id, selected)
            );
        });

        if (query && projects.length === 0) {
            appendProjectFilterStatusMessage(
                reg.optionsList,
                'conversation-project-filter-empty',
                projectFilterT('chat.filterProjectSearchEmpty', 'No matching projects')
            );
        }
    } catch (e) {
        if (seq !== reg.filterSearchSeq) return;
        renderProjectFilterPinnedOptions(reg);
        appendProjectFilterStatusMessage(
            reg.optionsList,
            'conversation-project-filter-empty',
            projectFilterT('chat.filterProjectSearchFailed', 'Failed to load projects; please retry')
        );
    } finally {
        if (loadingEl && loadingEl.parentNode) loadingEl.remove();
    }
}

function syncProjectFilterCustomSelect(selectId) {
    const reg = projectFilterCustomSelectRegistry[selectId];
    if (!reg) return;
    ensureProjectFilterSearchUi(reg);
    const { select, trigger } = reg;
    const valueSpan = trigger.querySelector('.conversation-project-filter-value');
    const selectedOpt = select.options[select.selectedIndex];
    const selectedText = selectedOpt ? (selectedOpt.textContent || '') : '';
    if (valueSpan) {
        valueSpan.textContent = selectedText;
        valueSpan.title = selectedText;
    }
}

function ensureSimpleCustomSelectOptionsUi(reg) {
    if (reg.optionsList) return;
    reg.dropdown.innerHTML = '';
    const optionsList = document.createElement('div');
    optionsList.className = 'conversation-project-filter-options';
    reg.dropdown.appendChild(optionsList);
    reg.optionsList = optionsList;
}

function renderSimpleCustomSelectOptions(reg) {
    ensureSimpleCustomSelectOptionsUi(reg);
    const { select, optionsList } = reg;
    optionsList.innerHTML = '';
    Array.prototype.forEach.call(select.options, (opt) => {
        optionsList.appendChild(createProjectFilterOptionButton(opt.value, opt.textContent || '', select.value));
    });
}

function syncSimpleCustomSelect(selectId) {
    const reg = projectFilterCustomSelectRegistry[selectId];
    if (!reg) return;
    const { select, trigger } = reg;
    const valueSpan = trigger.querySelector('.conversation-project-filter-value');
    const selectedOpt = select.options[select.selectedIndex];
    const selectedText = selectedOpt ? (selectedOpt.textContent || '') : '';
    if (valueSpan) {
        valueSpan.textContent = selectedText;
        valueSpan.title = selectedText;
    }
}

function initSimpleCustomSelect(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return;
    if (select.dataset.projectCustomSelect === '1') {
        syncSimpleCustomSelect(selectId);
        return;
    }
    select.dataset.projectCustomSelect = '1';
    select.classList.add('conversation-project-filter-native');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');

    const wrapper = document.createElement('div');
    wrapper.className = 'conversation-project-filter-ui';

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'conversation-project-filter-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    const valueSpan = document.createElement('span');
    valueSpan.className = 'conversation-project-filter-value';
    trigger.appendChild(valueSpan);
    trigger.insertAdjacentHTML('beforeend', CONVERSATION_PROJECT_FILTER_CARET);

    const dropdown = document.createElement('div');
    dropdown.className = 'conversation-project-filter-dropdown';
    dropdown.setAttribute('role', 'listbox');

    const parent = select.parentNode;
    parent.insertBefore(wrapper, select);
    wrapper.appendChild(trigger);
    wrapper.appendChild(dropdown);
    wrapper.appendChild(select);

    projectFilterCustomSelectRegistry[selectId] = { wrapper, trigger, dropdown, select };

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = wrapper.classList.contains('open');
        closeAllProjectFilterCustomSelects();
        if (!open) {
            wrapper.classList.add('open');
            trigger.setAttribute('aria-expanded', 'true');
            renderSimpleCustomSelectOptions(projectFilterCustomSelectRegistry[selectId]);
        }
    });

    dropdown.addEventListener('click', (e) => {
        const opt = e.target.closest('.conversation-project-filter-option');
        if (!opt) return;
        e.stopPropagation();
        const val = opt.getAttribute('data-value');
        if (val === null) return;
        if (select.value !== val) {
            select.value = val;
            select.dispatchEvent(new Event('change', { bubbles: true }));
        }
        closeProjectFilterCustomSelect(selectId);
        syncSimpleCustomSelect(selectId);
    });

    if (!projectFilterCustomSelectDocBound) {
        projectFilterCustomSelectDocBound = true;
        document.addEventListener('click', closeAllProjectFilterCustomSelects);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeAllProjectFilterCustomSelects();
        });
    }
    syncSimpleCustomSelect(selectId);
}

function initProjectFilterCustomSelect(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return;
    if (select.dataset.projectCustomSelect === '1') {
        syncProjectFilterCustomSelect(selectId);
        return;
    }
    select.dataset.projectCustomSelect = '1';
    select.classList.add('conversation-project-filter-native');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');

    const wrapper = document.createElement('div');
    wrapper.className = 'conversation-project-filter-ui';

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'conversation-project-filter-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    const valueSpan = document.createElement('span');
    valueSpan.className = 'conversation-project-filter-value';
    trigger.appendChild(valueSpan);
    trigger.insertAdjacentHTML('beforeend', CONVERSATION_PROJECT_FILTER_CARET);

    const dropdown = document.createElement('div');
    dropdown.className = 'conversation-project-filter-dropdown';
    dropdown.setAttribute('role', 'listbox');

    const parent = select.parentNode;
    parent.insertBefore(wrapper, select);
    wrapper.appendChild(trigger);
    wrapper.appendChild(dropdown);
    wrapper.appendChild(select);

    projectFilterCustomSelectRegistry[selectId] = { wrapper, trigger, dropdown, select };

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const open = wrapper.classList.contains('open');
        closeAllProjectFilterCustomSelects();
        if (!open) {
            wrapper.classList.add('open');
            trigger.setAttribute('aria-expanded', 'true');
            ensureProjectFilterSearchUi(projectFilterCustomSelectRegistry[selectId]);
            const reg = projectFilterCustomSelectRegistry[selectId];
            if (reg?.searchInput) {
                reg.searchInput.value = '';
                loadProjectFilterLocalOptions(selectId);
                requestAnimationFrame(() => reg.searchInput.focus());
            }
        }
    });

    dropdown.addEventListener('click', (e) => {
        const opt = e.target.closest('.conversation-project-filter-option');
        if (!opt) return;
        e.stopPropagation();
        const val = opt.getAttribute('data-value');
        if (val === null) return;
        const label = opt.querySelector('.conversation-project-filter-option-label')?.textContent || val;
        ensureNativeProjectFilterOption(select, val, label);
        if (select.value !== val) {
            select.value = val;
            select.dispatchEvent(new Event('change', { bubbles: true }));
        }
        closeProjectFilterCustomSelect(selectId);
        syncProjectFilterCustomSelect(selectId);
    });

    if (!projectFilterCustomSelectDocBound) {
        projectFilterCustomSelectDocBound = true;
        document.addEventListener('click', closeAllProjectFilterCustomSelects);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeAllProjectFilterCustomSelects();
        });
    }
    syncProjectFilterCustomSelect(selectId);
}

function syncConversationProjectCustomSelect() {
    syncProjectFilterCustomSelect(CONVERSATION_PROJECT_FILTER_SELECT_ID);
}

function initConversationProjectCustomSelect() {
    initProjectFilterCustomSelect(CONVERSATION_PROJECT_FILTER_SELECT_ID);
}

function getConversationProjectFilter() {
    try {
        return localStorage.getItem(CONVERSATIONS_PROJECT_FILTER_KEY) || '';
    } catch (e) {
        return '';
    }
}

function setConversationProjectFilter(projectId) {
    const value = (projectId || '').trim();
    try {
        if (value) localStorage.setItem(CONVERSATIONS_PROJECT_FILTER_KEY, value);
        else localStorage.removeItem(CONVERSATIONS_PROJECT_FILTER_KEY);
    } catch (e) { /* ignore */ }
    const sel = document.getElementById('conversation-project-filter');
    if (sel && sel.value !== value) sel.value = value;
    syncConversationProjectCustomSelect();
    updateConversationSidebarFilterUI();
}

function appendProjectFilterPinnedNativeOptions(sel) {
    const tFn = typeof window.t === 'function' ? window.t.bind(window) : null;
    const allLabel = tFn ? tFn('chat.filterAllProjects') : 'All projects';
    const unboundLabel = tFn ? tFn('chat.filterUnboundProjects') : 'Unbound projects';
    sel.innerHTML = '';
    const allOpt = document.createElement('option');
    allOpt.value = '';
    allOpt.textContent = allLabel;
    allOpt.setAttribute('data-i18n', 'chat.filterAllProjects');
    sel.appendChild(allOpt);
    const unboundOpt = document.createElement('option');
    unboundOpt.value = CONVERSATION_PROJECT_FILTER_NONE;
    unboundOpt.textContent = unboundLabel;
    unboundOpt.setAttribute('data-i18n', 'chat.filterUnboundProjects');
    sel.appendChild(unboundOpt);
}

async function resolveProjectFilterSelection(projectId) {
    const saved = (projectId || '').trim();
    if (!saved || saved === CONVERSATION_PROJECT_FILTER_NONE) return saved;
    const fetchSummary = typeof window.fetchProjectSummary === 'function'
        ? window.fetchProjectSummary
        : null;
    if (!fetchSummary) return saved;
    const project = await fetchSummary(saved);
    if (!project || !project.id || project.status === 'archived') return '';
    return project.id;
}

async function appendSelectedProjectFilterOption(sel, projectId) {
    const id = (projectId || '').trim();
    if (!id || id === CONVERSATION_PROJECT_FILTER_NONE) return;
    if (Array.prototype.some.call(sel.options, (opt) => opt.value === id)) return;
    const fetchSummary = typeof window.fetchProjectSummary === 'function'
        ? window.fetchProjectSummary
        : null;
    const project = fetchSummary ? await fetchSummary(id) : null;
    const label = (project && (project.name || project.id)) || (window.projectNameById && window.projectNameById[id]) || id;
    const opt = document.createElement('option');
    opt.value = id;
    opt.textContent = label;
    sel.appendChild(opt);
}

async function refreshConversationProjectFilter() {
    const sel = document.getElementById('conversation-project-filter');
    if (!sel) return;
    const saved = getConversationProjectFilter();
    appendProjectFilterPinnedNativeOptions(sel);
    const normalized = await resolveProjectFilterSelection(saved);
    if (normalized && normalized !== CONVERSATION_PROJECT_FILTER_NONE) {
        await appendSelectedProjectFilterOption(sel, normalized);
    }
    if (normalized !== saved) setConversationProjectFilter(normalized);
    sel.value = normalized;
    syncConversationProjectCustomSelect();
    updateConversationSidebarFilterUI();
}

function onConversationProjectFilterChange(projectId) {
    setConversationProjectFilter(projectId || '');
    commitConversationsPage(1, { bumpNavigateGen: true });
    loadConversations(conversationsSearchQuery);
}

function updateConversationSidebarFilterUI() {
    const titleEl = document.querySelector('.recent-conversations-section .section-title');
    const filter = getConversationProjectFilter();
    const hasSearch = !!(conversationsSearchQuery && conversationsSearchQuery.trim());
    if (!titleEl) return;
    const tFn = typeof window.t === 'function' ? window.t.bind(window) : null;
    if (filter && filter !== CONVERSATION_PROJECT_FILTER_NONE) {
        const name = (window.projectNameById && window.projectNameById[filter]) || filter;
        const fullTitle = tFn ? tFn('chat.projectConversationsTitle', { name }) : `${name} · conversations`;
        titleEl.textContent = fullTitle;
        titleEl.title = fullTitle;
        titleEl.classList.add('section-title--filtered');
        titleEl.removeAttribute('data-i18n');
    } else if (filter === CONVERSATION_PROJECT_FILTER_NONE) {
        const fullTitle = tFn ? tFn('chat.unboundConversationsTitle') : 'Unbound conversations';
        titleEl.textContent = fullTitle;
        titleEl.title = fullTitle;
        titleEl.classList.add('section-title--filtered');
        titleEl.setAttribute('data-i18n', 'chat.unboundConversationsTitle');
    } else {
        titleEl.classList.remove('section-title--filtered');
        titleEl.removeAttribute('title');
        titleEl.setAttribute('data-i18n', 'chat.recentConversations');
        if (tFn) titleEl.textContent = tFn('chat.recentConversations');
    }
}

window.onConversationProjectBindingChanged = function onConversationProjectBindingChanged() {
    loadConversations(conversationsSearchQuery);
};

function getConversationSortBy() {
    try {
        const saved = localStorage.getItem(CONVERSATIONS_SORT_KEY);
        if (saved === 'created_at' || saved === 'updated_at') return saved;
    } catch (e) { /* ignore */ }
    return 'updated_at';
}

let conversationSortBy = getConversationSortBy();

function getConversationSortTime(conv) {
    const field = conversationSortBy === 'created_at' ? 'createdAt' : 'updatedAt';
    const raw = conv && conv[field];
    if (!raw) return new Date(0);
    const date = new Date(raw);
    return isNaN(date.getTime()) ? new Date(0) : date;
}

function updateConversationSortMenuUI() {
    const menu = document.getElementById('conversation-sort-menu');
    const btn = document.getElementById('conversation-sort-btn');
    if (!menu) return;
    menu.querySelectorAll('.conversation-sort-option').forEach((option) => {
        const selected = option.dataset.sort === conversationSortBy;
        option.classList.toggle('is-selected', selected);
        option.setAttribute('aria-checked', selected ? 'true' : 'false');
    });
    if (btn) {
        btn.setAttribute('aria-expanded', menu.hidden ? 'false' : 'true');
    }
}

function closeConversationSortMenu() {
    const menu = document.getElementById('conversation-sort-menu');
    const btn = document.getElementById('conversation-sort-btn');
    if (menu) menu.hidden = true;
    if (btn) btn.setAttribute('aria-expanded', 'false');
}

function toggleConversationSortMenu(event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const menu = document.getElementById('conversation-sort-menu');
    const btn = document.getElementById('conversation-sort-btn');
    if (!menu || !btn) return;
    const willOpen = menu.hidden;
    closeConversationSortMenu();
    if (willOpen) {
        menu.hidden = false;
        btn.setAttribute('aria-expanded', 'true');
        updateConversationSortMenuUI();
    }
}

function setConversationSortBy(sortBy) {
    const next = sortBy === 'created_at' ? 'created_at' : 'updated_at';
    if (next === conversationSortBy) {
        closeConversationSortMenu();
        return;
    }
    conversationSortBy = next;
    try {
        localStorage.setItem(CONVERSATIONS_SORT_KEY, next);
    } catch (e) { /* ignore */ }
    updateConversationSortMenuUI();
    closeConversationSortMenu();
    commitConversationsPage(1, { bumpNavigateGen: true });
    loadConversations(conversationsSearchQuery);
}

if (!window.__conversationSortMenuBound) {
    window.__conversationSortMenuBound = true;
    document.addEventListener('click', (event) => {
        const dropdown = document.getElementById('conversation-sort-dropdown');
        if (!dropdown || dropdown.contains(event.target)) return;
        closeConversationSortMenu();
    });
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeConversationSortMenu();
    });
}

window.toggleConversationSortMenu = toggleConversationSortMenu;
window.setConversationSortBy = setConversationSortBy;
window.closeConversationSortMenu = closeConversationSortMenu;

function getConversationsPageSize() {
    try {
        const saved = parseInt(localStorage.getItem(CONVERSATIONS_PAGE_SIZE_KEY), 10);
        if ([20, 50, 100].includes(saved)) return saved;
    } catch (e) { /* ignore */ }
    return 50;
}

let conversationsPagination = {
    page: 1,
    pageSize: getConversationsPageSize(),
    total: 0,
    visibleCount: 0,
};
let conversationsSearchQuery = '';
let conversationsPaginationEventsBound = false;

function getConversationsTotalPages() {
    const { total, pageSize } = conversationsPagination;
    return Math.max(1, Math.ceil((total || 0) / pageSize) || 1);
}

/**
* Pagination state convention:
* - conversationsPagination.page is written only here (user action / reconcile clamp / clamp)
* - loadConversations only reads the page number and computes the offset from intentPage or the current page
* - isStaleConversationListLoad discards in-flight requests whose page or navigateGen has changed
 */
function commitConversationsPage(page, { bumpNavigateGen = false } = {}) {
    const next = Math.max(1, parseInt(page, 10) || 1);
    if (bumpNavigateGen) {
        conversationsListNavigateGen += 1;
    }
    conversationsPagination.page = next;
    return next;
}

function isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage) {
    if (loadSeq !== conversationsListLoadSeq) return true;
    // The user paged during the background refresh (including 2→1 and 1→2); discard the stale result
    if (intentPage == null && navigateGenAtStart !== conversationsListNavigateGen) return true;
    // After user paging, discard requests whose target page has changed
    if (intentPage != null && intentPage !== conversationsPagination.page) return true;
    // The page number changed by the time the background refresh finished (e.g. reconcile clamp); discard the stale result
    if (intentPage == null && activePage != null && activePage !== conversationsPagination.page) return true;
    return false;
}

function reconcileConversationsPageAfterTotal(activePage, intentPage, parsed, pageSize, offset, resolvedTotal) {
    let total = resolvedTotal;
    const totalPages = () => Math.max(1, Math.ceil((total || 0) / pageSize) || 1);

    if (activePage <= totalPages()) {
        return { ok: true, total };
    }

    const serverTotal = parseListTotalValue(parsed.total, parsed.items.length);
    const hasPageData = parsed.items.length > 0;
    const knownTotal = conversationsPagination.total || 0;
    // When the user paged and the server does have data for that page, do not trust a stale or low total (avoids 2>1 being clamped back to page 1)
    if (intentPage != null && (hasPageData || serverTotal > offset || total > offset || knownTotal > offset)) {
        total = Math.max(total, serverTotal, knownTotal, offset + parsed.items.length);
        if (activePage <= totalPages()) {
            return { ok: true, total };
        }
    }

    const clampedPage = totalPages();
    commitConversationsPage(clampedPage);
    return { ok: false, total, clampedPage };
}

function clampConversationsPageToTotal() {
    const totalPages = getConversationsTotalPages();
    if (conversationsPagination.page > totalPages) {
        commitConversationsPage(totalPages);
        return true;
    }
    if (conversationsPagination.page < 1) {
        commitConversationsPage(1);
        return true;
    }
    return false;
}

let conversationsPaginationRenderLock = false;

function initConversationsPaginationEvents() {
    if (conversationsPaginationEventsBound) return;
    const el = document.getElementById('conversations-pagination');
    if (!el) return;
    conversationsPaginationEventsBound = true;
    el.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-conv-page]');
        if (!btn || btn.disabled) return;
        e.preventDefault();
        const page = parseInt(btn.getAttribute('data-conv-page'), 10);
        if (Number.isFinite(page)) {
            goConversationsPage(page);
        }
    });
    el.addEventListener('change', (e) => {
        if (conversationsPaginationRenderLock) return;
        if (e.target && e.target.id === 'conversations-page-size-pagination') {
            changeConversationsPageSize();
        }
    });
}

function parseListTotalValue(raw, itemsLength) {
    if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) return raw;
    if (raw != null && raw !== '') {
        const n = parseInt(String(raw), 10);
        if (Number.isFinite(n) && n >= 0) return n;
    }
    return itemsLength;
}

function parseListOffsetValue(raw) {
    if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) return raw;
    if (raw != null && raw !== '') {
        const n = parseInt(String(raw), 10);
        if (Number.isFinite(n) && n >= 0) return n;
    }
    return 0;
}

function parseConversationsListResponse(data) {
    if (Array.isArray(data)) {
        return { items: data, total: data.length, limit: data.length, offset: 0, isLegacyArray: true };
    }
    const items = data.conversations || data.items || [];
    const arr = Array.isArray(items) ? items : [];
    return {
        items: arr,
        total: parseListTotalValue(data.total, arr.length),
        limit: parseListTotalValue(data.limit, arr.length) || arr.length,
        offset: parseListOffsetValue(data.offset),
        isLegacyArray: false,
    };
}

async function resolveConversationsListTotal(params, parsed, pageSize, offset) {
    const serverTotal = parsed.total;
    if (!parsed.isLegacyArray && typeof serverTotal === 'number' && Number.isFinite(serverTotal) && serverTotal >= 0) {
        return serverTotal;
    }
    if (!parsed.isLegacyArray && serverTotal > offset + parsed.items.length) {
        return serverTotal;
    }
    if (parsed.items.length < pageSize) {
        return Math.max(serverTotal, offset + parsed.items.length);
    }
    const probe = new URLSearchParams(params);
    probe.set('offset', String(offset + pageSize));
    probe.set('limit', '1');
    try {
        const res = await apiFetch(`/api/conversations?${probe}`);
        if (!res.ok) return Math.max(serverTotal, offset + parsed.items.length);
        const probeParsed = parseConversationsListResponse(await res.json());
        if (probeParsed.total > serverTotal) return probeParsed.total;
        if (probeParsed.items.length > 0) {
            return Math.max(serverTotal, offset + pageSize + 1);
        }
    } catch (e) { /* ignore */ }
    return Math.max(serverTotal, offset + parsed.items.length);
}

async function fetchAllConversations(searchQuery) {
    let all = [];
    const pageSize = 200;
    let offset = 0;
    let total = Infinity;
    const search = (searchQuery || '').trim();
    while (all.length < total) {
        const params = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
        if (search) params.set('search', search);
        const res = await apiFetch(`/api/conversations?${params}`);
        if (!res.ok) throw new Error('load conversations failed');
        const parsed = parseConversationsListResponse(await res.json());
        all = all.concat(parsed.items);
        total = parsed.total;
        if (!parsed.items.length) break;
        offset += parsed.items.length;
    }
    return all;
}

function getConversationListEmptyHtml() {
    const filter = getConversationProjectFilter();
    if (filter && filter !== CONVERSATION_PROJECT_FILTER_NONE) {
        return '<div class="conversations-list-empty" data-i18n="chat.noProjectConversations"></div>';
    }
    if (filter === CONVERSATION_PROJECT_FILTER_NONE) {
        return '<div class="conversations-list-empty" data-i18n="chat.noUnboundConversations"></div>';
    }
    return '<div class="conversations-list-empty" data-i18n="chat.noHistoryConversations"></div>';
}

function renderConversationsPagination(visibleCount) {
    const el = document.getElementById('conversations-pagination');
    if (!el) return;
    const { page, pageSize, total } = conversationsPagination;
    if (typeof visibleCount === 'number') {
        conversationsPagination.visibleCount = visibleCount;
    }

    if (!total) {
        el.innerHTML = '';
        el.hidden = true;
        if (typeof initPaginationSelects === 'function') initPaginationSelects(el);
        return;
    }

    const totalPages = getConversationsTotalPages();
    const navDisabled = totalPages <= 1;
    const recentToggle = document.getElementById('recent-conversations-toggle');
    el.hidden = !recentToggle || recentToggle.getAttribute('aria-expanded') !== 'true';
    const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
    const end = Math.min(page * pageSize, total);
    const tFn = typeof window.t === 'function' ? window.t.bind(window) : null;
    const infoText = tFn
        ? tFn('chat.paginationRange', { start, end, total })
        : `${start}-${end}/${total}`;
    const pageText = tFn
        ? tFn('chat.paginationPage', { page, total: totalPages })
        : `${page}/${totalPages}`;
    const perPageLabel = tFn ? tFn('chat.paginationPerPage') : 'Per page';
    const prevLabel = tFn ? tFn('chat.paginationPrev') : 'Prev';
    const nextLabel = tFn ? tFn('chat.paginationNext') : 'Next';
    const prevPage = page - 1;
    const nextPage = page + 1;
    conversationsPaginationRenderLock = true;
    try {
        el.innerHTML = `
        <div class="sidebar-list-pagination-inner sidebar-list-pagination-inner--compact">
            <span class="pagination-info">${escapeHtml(infoText)}</span>
            <div class="pagination-controls">
                <button type="button" class="btn-icon-pagination" data-conv-page="${prevPage}" ${page <= 1 || navDisabled ? 'disabled' : ''} title="${escapeHtml(prevLabel)}" aria-label="${escapeHtml(prevLabel)}">‹</button>
                <span class="pagination-page">${escapeHtml(pageText)}</span>
                <button type="button" class="btn-icon-pagination" data-conv-page="${nextPage}" ${page >= totalPages || navDisabled ? 'disabled' : ''} title="${escapeHtml(nextLabel)}" aria-label="${escapeHtml(nextLabel)}">›</button>
            </div>
            <label class="pagination-page-size">
                ${escapeHtml(perPageLabel)}
                <select id="conversations-page-size-pagination">
                    <option value="20" ${pageSize === 20 ? 'selected' : ''}>20</option>
                    <option value="50" ${pageSize === 50 ? 'selected' : ''}>50</option>
                    <option value="100" ${pageSize === 100 ? 'selected' : ''}>100</option>
                </select>
            </label>
        </div>`;
        if (typeof initPaginationSelects === 'function') initPaginationSelects(el);
    } finally {
        conversationsPaginationRenderLock = false;
    }
}

function goConversationsPage(page) {
    const requestedPage = Math.max(1, parseInt(page, 10) || 1);
    const scrollToTop = requestedPage !== conversationsPagination.page;
    commitConversationsPage(requestedPage, { bumpNavigateGen: true });
    loadConversations(conversationsSearchQuery, {
        refreshMeta: false,
        scrollToTop,
        intentPage: requestedPage,
    });
}

function changeConversationsPageSize() {
    const sel = document.getElementById('conversations-page-size-pagination');
    const newSize = sel ? parseInt(sel.value, 10) : 50;
    if (![20, 50, 100].includes(newSize)) return;
    // After rebuilding the DOM the browser may fire change asynchronously; do not reset the page number when the value is unchanged
    if (newSize === conversationsPagination.pageSize) return;
    try {
        localStorage.setItem(CONVERSATIONS_PAGE_SIZE_KEY, String(newSize));
    } catch (e) { /* ignore */ }
    conversationsPagination.pageSize = newSize;
    commitConversationsPage(1, { bumpNavigateGen: true });
    loadConversations(conversationsSearchQuery);
}

window.goConversationsPage = goConversationsPage;
window.changeConversationsPageSize = changeConversationsPageSize;

// Load conversation list (supports pinning)
async function loadConversations(searchQuery = '', options = {}) {
    const refreshMeta = options.refreshMeta !== false;
    const scrollToTop = options.scrollToTop === true;
    const intentPage = Number.isFinite(options.intentPage) ? options.intentPage : null;
    const navigateGenAtStart = conversationsListNavigateGen;
    const loadSeq = ++conversationsListLoadSeq;
    try {
        conversationsSearchQuery = searchQuery || '';
        const pageSize = getConversationsPageSize();
        conversationsPagination.pageSize = pageSize;
        const activePage = intentPage != null ? intentPage : conversationsPagination.page;
        const offset = (activePage - 1) * pageSize;
        const convParams = new URLSearchParams({ limit: String(pageSize), offset: String(offset) });
        if (conversationSortBy === 'created_at') {
            convParams.set('sort_by', 'created_at');
        }
        const projectFilter = getConversationProjectFilter();
        if (projectFilter) {
            convParams.set('project_id', projectFilter);
        }
        if (searchQuery && searchQuery.trim()) {
            convParams.set('search', searchQuery.trim());
        }
        updateConversationSidebarFilterUI();
        const url = `/api/conversations?${convParams}`;
        const response = await apiFetch(url);
        if (isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage)) return;

        const listContainer = document.getElementById('conversations-list');
        if (!listContainer) {
            return;
        }

        // Save scroll position
        const sidebarContent = listContainer.closest('.sidebar-content');
        const savedScrollTop = sidebarContent ? sidebarContent.scrollTop : 0;

        const emptyStateHtml = getConversationListEmptyHtml();
        listContainer.innerHTML = '';

        // If the response is not 200, show the empty state (handled gracefully, without an error)
        if (!response.ok) {
            listContainer.innerHTML = emptyStateHtml;
            if (typeof window.applyTranslations === 'function') window.applyTranslations(listContainer);
            updateRecentConversationsCount(0);
            renderConversationsPagination(0);
            return;
        }

        const data = await response.json();
        if (isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage)) return;
        const parsed = parseConversationsListResponse(data);
        const resolvedTotal = await resolveConversationsListTotal(convParams, parsed, pageSize, offset);
        if (isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage)) return;
        conversationsPagination.total = resolvedTotal;
        updateRecentConversationsCount(resolvedTotal);

        const pageCheck = reconcileConversationsPageAfterTotal(
            activePage, intentPage, parsed, pageSize, offset, resolvedTotal
        );
        conversationsPagination.total = pageCheck.total;
        if (!pageCheck.ok) {
            if (isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage)) return;
            // Keep the intent even when user paging is clamped, and bump navigateGen to invalidate in-flight background refreshes
            if (intentPage != null) {
                commitConversationsPage(pageCheck.clampedPage, { bumpNavigateGen: true });
            }
            loadConversations(searchQuery, {
                ...options,
                intentPage: pageCheck.clampedPage,
                scrollToTop: options.scrollToTop === true || activePage !== pageCheck.clampedPage,
            });
            return;
        }
        if (intentPage == null && clampConversationsPageToTotal()) {
            if (isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage)) return;
            loadConversations(searchQuery, options);
            return;
        }

        // Double safeguard: if duplicate IDs appear due to the backend or concurrency, de-duplicate by ID on the frontend
        const uniqueConversations = [];
        const seenConversationIds = new Set();
        parsed.items.forEach(conv => {
            if (!conv || !conv.id || seenConversationIds.has(conv.id)) {
                return;
            }
            seenConversationIds.add(conv.id);
            uniqueConversations.push(conv);
        });

        if (uniqueConversations.length === 0) {
            listContainer.innerHTML = emptyStateHtml;
            if (typeof window.applyTranslations === 'function') window.applyTranslations(listContainer);
            renderConversationsPagination(0);
            return;
        }

        // Separate pinned and regular conversations
        const pinnedConvs = [];
        const normalConvs = [];

        uniqueConversations.forEach(conv => {
            if (conv.pinned) {
                pinnedConvs.push(conv);
            } else {
                normalConvs.push(conv);
            }
        });

        // Sort by time
        const sortByTime = (a, b) => getConversationSortTime(b) - getConversationSortTime(a);

        pinnedConvs.sort(sortByTime);
        normalConvs.sort(sortByTime);

        const now = new Date();
        const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const yesterdayStart = new Date(todayStart);
        yesterdayStart.setDate(todayStart.getDate() - 1);
        const sevenDaysCutoff = new Date(todayStart);
        sevenDaysCutoff.setDate(todayStart.getDate() - 7);

        const tFn = typeof window.t === 'function' ? window.t.bind(window) : null;
        const groupOrder = [
            { key: 'today', label: tFn ? tFn('chat.historyGroupToday') : 'Today' },
            { key: 'yesterday', label: tFn ? tFn('chat.yesterday') : 'Yesterday' },
            { key: 'last7Days', label: tFn ? tFn('chat.historyGroupLast7Days') : 'Past 7 days' },
            { key: 'earlier', label: tFn ? tFn('chat.historyGroupEarlier') : 'Earlier' },
        ];

        const groups = {
            today: [],
            yesterday: [],
            last7Days: [],
            earlier: [],
        };

        normalConvs.forEach(conv => {
            const dateObj = getConversationSortTime(conv);
            const validDate = dateObj.getTime() === 0 ? new Date() : dateObj;
            const groupKey = getConversationGroup(validDate, todayStart, sevenDaysCutoff, yesterdayStart);
            groups[groupKey].push({
                ...conv,
                _timeText: formatConversationTimestamp(validDate, todayStart, yesterdayStart),
            });
        });

        const fragment = document.createDocumentFragment();

        if (pinnedConvs.length > 0) {
            pinnedConvs.forEach(conv => {
                const dateObj = getConversationSortTime(conv);
                const validDate = dateObj.getTime() === 0 ? new Date() : dateObj;
                fragment.appendChild(createConversationListItemWithMenu({
                    ...conv,
                    _timeText: formatConversationTimestamp(validDate, todayStart, yesterdayStart),
                }, true));
            });
        }

        groupOrder.forEach(({ key, label }) => {
            const items = groups[key];
            if (!items || items.length === 0) {
                return;
            }
            const section = document.createElement('div');
            section.className = 'conversation-group';

            const title = document.createElement('div');
            title.className = 'conversation-group-title';
            title.textContent = label;
            section.appendChild(title);

            items.forEach(itemData => {
                section.appendChild(createConversationListItemWithMenu(itemData, false));
            });

            fragment.appendChild(section);
        });

        const visibleCount = pinnedConvs.length + Object.values(groups).reduce((n, arr) => n + (arr ? arr.length : 0), 0);
        conversationsPagination.visibleCount = visibleCount;

        if (fragment.children.length === 0) {
            listContainer.innerHTML = emptyStateHtml;
            if (typeof window.applyTranslations === 'function') window.applyTranslations(listContainer);
            renderConversationsPagination(0);
            return;
        }

        if (isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage)) return;
        listContainer.appendChild(fragment);
        updateActiveConversation();
        renderConversationsPagination(visibleCount);

        // Return to the top of the list when paging; background refresh keeps the scroll position
        if (sidebarContent) {
            requestAnimationFrame(() => {
                if (!isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage)) {
                    sidebarContent.scrollTop = scrollToTop ? 0 : savedScrollTop;
                }
            });
        }
    } catch (error) {
        if (isStaleConversationListLoad(loadSeq, intentPage, navigateGenAtStart, activePage)) return;
        console.error('Failed to load conversation list:', error);
        // On error, show the empty state instead of an error message (friendlier user experience)
        const listContainer = document.getElementById('conversations-list');
        if (listContainer) {
            listContainer.innerHTML = getConversationListEmptyHtml();
            if (typeof window.applyTranslations === 'function') window.applyTranslations(listContainer);
            updateRecentConversationsCount(0);
            renderConversationsPagination(0);
        }
    }
}

// Create conversation item with menu
function createConversationListItemWithMenu(conversation, isPinned) {
    const item = document.createElement('div');
    item.className = 'conversation-item';
    item.dataset.conversationId = conversation.id;
    if (conversation.id === currentConversationId) {
        item.classList.add('active');
    }

    const contentWrapper = document.createElement('div');
    contentWrapper.className = 'conversation-content';

    const titleWrapper = document.createElement('div');
    titleWrapper.style.display = 'flex';
    titleWrapper.style.alignItems = 'center';
    titleWrapper.style.gap = '4px';

    const title = document.createElement('div');
    title.className = 'conversation-title';
    const titleText = conversation.title || 'Untitled conversation';
    title.textContent = safeTruncateText(titleText, 60);
    title.title = titleText; // Set the full title so it can be viewed on hover
    titleWrapper.appendChild(title);

    if (isPinned) {
        const pinIcon = document.createElement('span');
        pinIcon.className = 'conversation-item-pinned';
        pinIcon.innerHTML = '📌';
        pinIcon.title = 'Pinned';
        titleWrapper.appendChild(pinIcon);
    }

    contentWrapper.appendChild(titleWrapper);

    const time = document.createElement('div');
    time.className = 'conversation-time';
    const dateObj = conversation.updatedAt ? new Date(conversation.updatedAt) : new Date();
    time.textContent = conversation._timeText || formatConversationTimestamp(dateObj);
    contentWrapper.appendChild(time);

    item.appendChild(contentWrapper);

    const menuBtn = document.createElement('button');
    menuBtn.className = 'conversation-item-menu';
    menuBtn.innerHTML = '⋯';
    menuBtn.onclick = (e) => openConversationContextMenuForId(e, conversation.id, conversation.title || '');
    item.appendChild(menuBtn);

    item.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        const targetConversationId = String(item.dataset.conversationId || '').trim();
        if (targetConversationId) loadConversation(targetConversationId);
    };

    return item;
}

function openConversationContextMenuForId(event, conversationId, conversationTitle = '') {
    event.stopPropagation();
    event.preventDefault();
    contextMenuConversationId = conversationId;
    contextMenuConversationTitle = conversationTitle;
    return showConversationContextMenu(event);
}

let downloadMarkdownSubmenuHideTimer = null;

function clearDownloadMarkdownSubmenuHideTimeout() {
    if (!downloadMarkdownSubmenuHideTimer) return;
    clearTimeout(downloadMarkdownSubmenuHideTimer);
    downloadMarkdownSubmenuHideTimer = null;
}

function hideDownloadMarkdownSubmenu() {
    clearDownloadMarkdownSubmenuHideTimeout();
    downloadMarkdownSubmenuHideTimer = setTimeout(() => {
        const submenu = document.getElementById('download-markdown-submenu');
        if (submenu) submenu.style.display = 'none';
        downloadMarkdownSubmenuHideTimer = null;
    }, 120);
}

function handleDownloadMarkdownSubmenuEnter() {
    clearDownloadMarkdownSubmenuHideTimeout();
    const submenu = document.getElementById('download-markdown-submenu');
    if (submenu) submenu.style.display = 'block';
}

function handleDownloadMarkdownSubmenuLeave(event) {
    const submenu = document.getElementById('download-markdown-submenu');
    if (submenu && event?.relatedTarget && submenu.contains(event.relatedTarget)) return;
    hideDownloadMarkdownSubmenu();
}

function updateConversationContextPinText(isPinned) {
    const pinMenuText = document.getElementById('pin-conversation-menu-text');
    if (!pinMenuText) return;
    if (typeof window.t === 'function') {
        pinMenuText.textContent = isPinned ? window.t('contextMenu.unpinConversation') : window.t('contextMenu.pinConversation');
    } else {
        pinMenuText.textContent = isPinned ? 'Unpin' : 'Pin this conversation';
    }
}

async function refreshConversationContextPinText(convId) {
    if (!convId) {
        updateConversationContextPinText(false);
        return;
    }
    try {
        const response = await apiFetch(`/api/conversations/${convId}`);
        if (!response.ok) return;
        const conv = await response.json();
        updateConversationContextPinText(!!conv.pinned);
    } catch (error) {
        console.error('Failed to get conversation pin status:', error);
    }
}

// Show conversation context menu
async function showConversationContextMenu(event) {
    const menu = document.getElementById('conversation-context-menu');
    if (!menu) return;

    const downloadSubmenu = document.getElementById('download-markdown-submenu');
    if (downloadSubmenu) {
        downloadSubmenu.style.display = 'none';
    }
    // Clear all timers
    clearDownloadMarkdownSubmenuHideTimeout();

    const convId = contextMenuConversationId;
    updateConversationContextPinText(false);

    // Update the enabled state of the attack chain menu item
    const attackChainMenuItem = document.getElementById('attack-chain-menu-item');
    if (attackChainMenuItem) {
        if (convId) {
            const isRunning = typeof isConversationTaskRunning === 'function'
                ? isConversationTaskRunning(convId)
                : false;
            if (isRunning) {
                attackChainMenuItem.style.opacity = '0.5';
                attackChainMenuItem.style.cursor = 'not-allowed';
                attackChainMenuItem.onclick = null;
                attackChainMenuItem.title = 'Current conversation is running; please try generating the attack chain later';
            } else {
                attackChainMenuItem.style.opacity = '1';
                attackChainMenuItem.style.cursor = 'pointer';
                attackChainMenuItem.onclick = showAttackChainFromContext;
                attackChainMenuItem.title = (typeof window.t === 'function' ? window.t('chat.viewAttackChainCurrentConv') : 'View attack chain of the current conversation');
            }
        } else {
            attackChainMenuItem.style.opacity = '0.5';
            attackChainMenuItem.style.cursor = 'not-allowed';
            attackChainMenuItem.onclick = null;
            attackChainMenuItem.title = (typeof window.t === 'function' ? window.t('chat.viewAttackChainSelectConv') : 'Select a conversation to view its attack chain');
        }
    }

    // Show the menu first; pin status refreshes asynchronously afterwards, so a slow API does not make clicks look unresponsive.
    menu.style.display = 'block';
    menu.style.visibility = 'visible';
    menu.style.opacity = '1';

    // Force reflow to get correct dimensions
    void menu.offsetHeight;

    // Compute menu position, ensuring it stays on screen
    const menuRect = menu.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    const submenuWidth = 0;

    let left = event.clientX;
    let top = event.clientY;

    // If the menu would exceed the right edge, move it to the left
    if (left + menuRect.width + submenuWidth > viewportWidth) {
        left = event.clientX - menuRect.width;
        // If it still overflows after adjusting, place it to the left of the button
        if (left < 0) {
            left = Math.max(8, event.clientX - menuRect.width - submenuWidth);
        }
    }

    // If the menu would exceed the bottom edge, move it above
    if (top + menuRect.height > viewportHeight) {
        top = Math.max(8, event.clientY - menuRect.height);
    }

    // Ensure it does not exceed the left edge
    if (left < 0) {
        left = 8;
    }

    // Ensure it does not exceed the top edge
    if (top < 0) {
        top = 8;
    }

    menu.style.left = left + 'px';
    menu.style.top = top + 'px';

    // If the menu is on the right, the submenu should show on the left
    if (left < event.clientX) {
        if (downloadSubmenu) {
            downloadSubmenu.style.left = 'auto';
            downloadSubmenu.style.right = '100%';
            downloadSubmenu.style.marginLeft = '0';
            downloadSubmenu.style.marginRight = '4px';
        }
    } else {
        if (downloadSubmenu) {
            downloadSubmenu.style.left = '100%';
            downloadSubmenu.style.right = 'auto';
            downloadSubmenu.style.marginLeft = '4px';
            downloadSubmenu.style.marginRight = '0';
        }
    }

    // Click outside to close the menu
    const closeMenu = (e) => {
        // Check whether the click is inside the main menu or submenu
        const downloadMarkdownSubmenuEl = document.getElementById('download-markdown-submenu');
        const clickedInMenu = menu.contains(e.target);
        const clickedInDownloadSubmenu = downloadMarkdownSubmenuEl && downloadMarkdownSubmenuEl.contains(e.target);

        if (!clickedInMenu && !clickedInDownloadSubmenu) {
            closeContextMenu();
            document.removeEventListener('click', closeMenu);
        }
    };
    setTimeout(() => {
        document.addEventListener('click', closeMenu);
    }, 0);

    refreshConversationContextPinText(convId);
}

let renameConversationTargetId = null;

function ensureConversationRenameModal() {
    let modal = document.getElementById('conversation-rename-modal');
    if (modal) return modal;

    modal = document.createElement('div');
    modal.id = 'conversation-rename-modal';
    modal.className = 'modal-overlay projects-modal-overlay';
    modal.style.display = 'none';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'conversation-rename-title');
    modal.innerHTML = `
        <div class="projects-modal-dialog">
            <div class="projects-modal-header">
                <div class="projects-modal-header-text">
                    <div>
                        <h3 id="conversation-rename-title" data-i18n="chat.renameConversationTitle">Rename conversation</h3>
                        <p class="projects-modal-subtitle" data-i18n="chat.renameConversationSubtitle">Changes also update the name in project folders and recent conversations</p>
                    </div>
                </div>
                <button type="button" class="projects-modal-close" data-conversation-rename-close aria-label="Close" data-i18n="common.close" data-i18n-attr="aria-label" data-i18n-skip-text="true">&times;</button>
            </div>
            <div class="projects-modal-body">
                <div class="projects-form-field">
                    <label for="conversation-rename-input" data-i18n="chat.conversationTitleLabel">Conversation name</label>
                    <input type="text" id="conversation-rename-input" class="form-input" maxlength="200" autocomplete="off" data-i18n="chat.conversationTitlePlaceholder" data-i18n-attr="placeholder" placeholder="Enter conversation name">
                </div>
            </div>
            <div class="projects-modal-footer">
                <button class="btn-secondary" type="button" data-conversation-rename-close data-i18n="common.cancel">Cancel</button>
                <button class="btn-primary" type="button" id="conversation-rename-submit" data-i18n="contextMenu.rename">Rename</button>
            </div>
        </div>`;
    modal.addEventListener('click', (event) => {
        if (event.target === modal) closeConversationRenameModal();
    });
    modal.querySelectorAll('[data-conversation-rename-close]').forEach((button) => {
        button.addEventListener('click', closeConversationRenameModal);
    });
    modal.querySelector('#conversation-rename-submit')?.addEventListener('click', saveConversationRename);
    modal.querySelector('#conversation-rename-input')?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            saveConversationRename();
        } else if (event.key === 'Escape') {
            closeConversationRenameModal();
        }
    });
    document.body.appendChild(modal);
    if (typeof window.applyTranslations === 'function') window.applyTranslations(modal);
    return modal;
}

// Open the in-app rename dialog to avoid the built-in browser blocking window.prompt.
function renameConversation() {
    const convId = contextMenuConversationId;
    if (!convId) return;

    renameConversationTargetId = convId;
    const currentTitle = contextMenuConversationTitle || '';
    ensureConversationRenameModal();
    const input = document.getElementById('conversation-rename-input');
    if (input) input.value = currentTitle;
    closeContextMenu();
    openAppModal('conversation-rename-modal', { focusEl: input });
    if (input) input.select();
}

function closeConversationRenameModal() {
    renameConversationTargetId = null;
    closeAppModal('conversation-rename-modal');
}

async function saveConversationRename() {
    const convId = renameConversationTargetId;
    const input = document.getElementById('conversation-rename-input');
    const newTitle = (input?.value || '').trim();
    if (!convId || !newTitle) {
        input?.focus();
        return;
    }

    const submitButton = document.getElementById('conversation-rename-submit');
    if (submitButton) submitButton.disabled = true;

    try {
        const response = await apiFetch(`/api/conversations/${convId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ title: newTitle.trim() }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Update failed');
        }

        // Update frontend display
        document.querySelectorAll('[data-conversation-id]').forEach((item) => {
            if (item.dataset.conversationId !== convId) return;
            item.querySelectorAll('.conversation-title, .project-conversation-title')
                .forEach((titleEl) => {
                    titleEl.textContent = newTitle.trim();
                    titleEl.title = newTitle.trim();
                });
        });

        // Also update the running task name in the top bar
        if (typeof updateActiveTaskConversationTitle === 'function') {
            updateActiveTaskConversationTitle(convId, newTitle.trim());
        }

        // Reload conversation list
        await loadConversations();
        if (typeof window.refreshChatProjectFolders === 'function') {
            await window.refreshChatProjectFolders();
        }
        closeConversationRenameModal();
    } catch (error) {
        console.error('Failed to rename conversation:', error);
        const failedLabel = typeof window.t === 'function' ? window.t('chat.renameFailed') : 'Rename failed';
        const unknownErr = 'Unknown error';
        alert(failedLabel + ': ' + (error.message || unknownErr));
    } finally {
        if (submitButton) submitButton.disabled = false;
    }
}

async function assertConversationActionResponse(response, fallbackMessage) {
    if (response && response.ok) return response;
    let payload = {};
    try {
        payload = response ? await response.json() : {};
    } catch (e) { /* ignore */ }
    throw new Error(payload.error || payload.message || fallbackMessage);
}

function notifyConversationPinnedChanged(conversationId, pinned) {
    try {
        document.dispatchEvent(new CustomEvent('conversation-pinned-changed', {
            detail: { conversationId, pinned: !!pinned }
        }));
    } catch (e) { /* ignore */ }
}

// Pin conversation
async function pinConversation() {
    const convId = contextMenuConversationId;
    if (!convId) return;

    // Close the menu immediately after clicking, so it does not look unresponsive during the network request.
    closeContextMenu();

    try {
        const response = await apiFetch(`/api/conversations/${convId}`);
        await assertConversationActionResponse(response, 'Failed to get conversation');
        const conv = await response.json();
        const newPinned = !conv.pinned;

        const updateResponse = await apiFetch(`/api/conversations/${convId}/pinned`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pinned: newPinned }),
        });
        await assertConversationActionResponse(updateResponse, 'Failed to update pin status');

        notifyConversationPinnedChanged(convId, newPinned);
        loadConversations();
    } catch (error) {
        console.error('Failed to pin conversation:', error);
        alert('Pin failed: ' + (error.message || 'Unknown error'));
    }

}

// View attack chain from context menu
function showAttackChainFromContext() {
    const convId = contextMenuConversationId;
    if (!convId) return;

    closeContextMenu();
    showAttackChain(convId);
}

function formatConversationDateForMarkdown(value) {
    if (!value) return '';
    const d = new Date(value);
    if (isNaN(d.getTime())) return '';
    const locale = (typeof window.uiLocale === 'function' ? window.uiLocale() : 'en-US');
    return d.toLocaleString(locale, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

function getConversationRoleLabel(role) {
    switch (role) {
        case 'assistant':
            return 'Assistant';
        case 'user':
            return 'User';
        case 'system':
            return 'System';
        default:
            return role || 'Unknown';
    }
}

function formatConversationAsMarkdown(conversation, options = {}) {
    const includeToolDetails = !!options.includeToolDetails;
    const title = (conversation && conversation.title ? String(conversation.title) : '').trim() || 'Untitled Conversation';
    const createdAt = formatConversationDateForMarkdown(conversation && conversation.createdAt);
    const updatedAt = formatConversationDateForMarkdown(conversation && conversation.updatedAt);
    const messages = Array.isArray(conversation && conversation.messages) ? conversation.messages : [];

    let markdown = `# ${title}\n\n`;
    markdown += `- Conversation ID: \`${conversation && conversation.id ? conversation.id : ''}\`\n`;
    if (createdAt) markdown += `- Created At: ${createdAt}\n`;
    if (updatedAt) markdown += `- Updated At: ${updatedAt}\n`;
    markdown += `- Message Count: ${messages.length}\n\n`;
    markdown += '---\n\n';

    if (messages.length === 0) {
        markdown += '_No messages in this conversation._\n';
        return markdown;
    }

    messages.forEach((msg, index) => {
        if (msg && msg.role === 'user' && isInterruptContinueInjectChatMessage(msg.content)) {
            return;
        }
        const role = getConversationRoleLabel(msg && msg.role);
        const timestamp = formatConversationDateForMarkdown(msg && msg.createdAt);
        const content = msg && typeof msg.content === 'string' ? msg.content : '';

        markdown += `## ${index + 1}. ${role}`;
        if (timestamp) markdown += ` (${timestamp})`;
        markdown += '\n\n';
        markdown += content ? `${content}\n\n` : '_[Empty message]_\n\n';

        if (Array.isArray(msg && msg.processDetails) && msg.processDetails.length > 0) {
            markdown += '### Process Details\n\n';
            msg.processDetails.forEach((detail) => {
                const detailTime = formatConversationDateForMarkdown(detail && detail.timestamp);
                const eventType = detail && detail.eventType ? detail.eventType : 'event';
                const detailMsg = detail && detail.message ? detail.message : '';
                // Avoid "[label]:" pattern because some Markdown parsers treat it as link reference definition.
                markdown += `- \`${eventType}\``;
                if (detailTime) markdown += ` ${detailTime}`;
                if (detailMsg) markdown += `: ${detailMsg}`;
                markdown += '\n';

                if (includeToolDetails && detail && detail.data && (eventType === 'tool_call' || eventType === 'tool_result')) {
                    const pretty = JSON.stringify(detail.data, null, 2);
                    markdown += '\n```json\n';
                    markdown += pretty || '{}';
                    markdown += '\n```\n';
                }
            });
            markdown += '\n';
        }

        if (Array.isArray(msg && msg.mcpExecutionIds) && msg.mcpExecutionIds.length > 0) {
            markdown += `- MCP Execution IDs: ${msg.mcpExecutionIds.join(', ')}\n\n`;
        }

        markdown += '---\n\n';
    });

    return markdown;
}

function buildConversationMarkdownFileName(conversation, options = {}) {
    const includeToolDetails = !!options.includeToolDetails;
    const title = (conversation && conversation.title ? String(conversation.title) : '').trim() || 'conversation';
    const safeTitle = title
        .replace(/[\\/:*?"<>|]/g, '_')
        .replace(/\s+/g, '_')
        .slice(0, 60) || 'conversation';
    const idPart = (conversation && conversation.id ? String(conversation.id) : '').slice(0, 8) || 'export';
    const modePart = includeToolDetails ? 'full' : 'summary';
    return `${safeTitle}_${idPart}_${modePart}.md`;
}

// Download conversation Markdown from context menu
async function downloadConversationMarkdownFromContext(includeToolDetails = false) {
    const convId = contextMenuConversationId;
    if (!convId) return;

    try {
        // Downloading should not affect page performance: fetch all process details from the backend in one request
        const response = await apiFetch(`/api/conversations/${convId}?include_process_details=1`);
        let conversation = null;
        try {
            conversation = await response.json();
        } catch (e) {
            conversation = null;
        }
        if (!response.ok) {
            const errorMsg = conversation && conversation.error ? conversation.error : 'unknown error';
            throw new Error(errorMsg);
        }

        const markdown = formatConversationAsMarkdown(conversation || {}, { includeToolDetails });
        const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = buildConversationMarkdownFileName(conversation || {}, { includeToolDetails });
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    } catch (error) {
        console.error('Failed to download conversation Markdown:', error);
        const failedLabel = typeof window.t === 'function' ? window.t('chat.downloadConversationFailed') : 'Download failed';
        const errMsg = error && error.message ? error.message : 'unknown error';
        alert(failedLabel + ': ' + errMsg);
    }

    closeContextMenu();
}

// Jump to vulnerability management from the context menu, filtered by the current conversation ID
function navigateToVulnerabilitiesForContextConversation() {
    const convId = contextMenuConversationId;
    if (!convId) {
        closeContextMenu();
        return;
    }
    closeContextMenu();
    window.location.hash = 'vulnerabilities?conversation_id=' + encodeURIComponent(convId);
}

// Delete conversation from context menu
function deleteConversationFromContext() {
    if (typeof requirePermission === 'function' && !requirePermission('chat:delete')) return;
    const convId = contextMenuConversationId;
    if (!convId) return;

    const confirmMsg = typeof window.t === 'function' ? window.t('chat.deleteConversationConfirm') : 'Delete this conversation?';
    if (confirm(confirmMsg)) {
        deleteConversation(convId, true); // Skip internal confirmation, since it was already confirmed here
    }
    closeContextMenu();
}

// Close context menu
function closeContextMenu() {
    const menu = document.getElementById('conversation-context-menu');
    if (menu) {
        menu.style.display = 'none';
    }
    const downloadSubmenu = document.getElementById('download-markdown-submenu');
    if (downloadSubmenu) {
        downloadSubmenu.style.display = 'none';
    }
    // Clear all timers
    clearDownloadMarkdownSubmenuHideTimeout();
    contextMenuConversationId = null;
    contextMenuConversationTitle = '';
}

// Show batch management modal
let allConversationsForBatch = [];

function getConversationProjectId(conv) {
    return (conv?.projectId || conv?.project_id || '').trim();
}

function getConversationProjectLabel(conv) {
    const pid = getConversationProjectId(conv);
    if (!pid) {
        return typeof window.t === 'function' ? window.t('batchManageModal.noProject') : 'No project';
    }
    const name = window.projectNameById && window.projectNameById[pid];
    if (name) return name;
    return typeof window.t === 'function' ? window.t('batchManageModal.unknownProject') : 'Unknown project';
}

async function prefetchProjectNamesForConversations(conversations) {
    const missing = new Set();
    for (const conv of conversations || []) {
        const pid = getConversationProjectId(conv);
        if (pid && !(window.projectNameById && window.projectNameById[pid])) {
            missing.add(pid);
        }
    }
    if (!missing.size) return;
    const fetchSummary = typeof window.fetchProjectSummary === 'function'
        ? window.fetchProjectSummary
        : null;
    if (!fetchSummary) return;
    await Promise.all([...missing].map((id) => fetchSummary(id).catch(() => null)));
}

async function refreshBatchProjectFilter() {
    const sel = document.getElementById('batch-project-filter');
    if (!sel) return;
    const saved = sel.value || '';
    appendProjectFilterPinnedNativeOptions(sel);
    const normalized = await resolveProjectFilterSelection(saved);
    if (normalized && normalized !== CONVERSATION_PROJECT_FILTER_NONE) {
        await appendSelectedProjectFilterOption(sel, normalized);
    }
    sel.value = normalized;
    syncProjectFilterCustomSelect(BATCH_PROJECT_FILTER_SELECT_ID);
}

function getBatchFilteredConversations() {
    const query = (document.getElementById('batch-search-input')?.value || '').trim().toLowerCase();
    const projectFilter = (document.getElementById('batch-project-filter')?.value || '').trim();
    return allConversationsForBatch.filter((conv) => {
        const pid = getConversationProjectId(conv);
        if (projectFilter) {
            if (projectFilter === CONVERSATION_PROJECT_FILTER_NONE) {
                if (pid) return false;
            } else if (pid !== projectFilter) {
                return false;
            }
        }
        if (!query) return true;
        const title = (conv.title || '').toLowerCase();
        const projectName = getConversationProjectLabel(conv).toLowerCase();
        return title.includes(query) || projectName.includes(query);
    });
}

function applyBatchConversationFilters() {
    const filtered = getBatchFilteredConversations();
    updateBatchManageTitle(filtered.length);
    renderBatchConversations(filtered);
}

// Update batch management modal title (with count), supports i18n; count is the current count
function updateBatchManageTitle(count) {
    const titleEl = document.getElementById('batch-manage-title');
    if (!titleEl || typeof window.t !== 'function') return;
    const template = window.t('batchManageModal.title', { count: '__C__' });
    const parts = template.split('__C__');
    titleEl.innerHTML = (parts[0] || '') + '<span id="batch-manage-count">' + (count || 0) + '</span>' + (parts[1] || '');
}

async function showBatchManageModal() {
    try {
        initProjectFilterCustomSelect(BATCH_PROJECT_FILTER_SELECT_ID);
        allConversationsForBatch = await fetchAllConversations('');
        await prefetchProjectNamesForConversations(allConversationsForBatch);
        await refreshBatchProjectFilter();
        const sidebarFilter = getConversationProjectFilter();
        const batchSel = document.getElementById('batch-project-filter');
        if (batchSel && sidebarFilter && (
            sidebarFilter === CONVERSATION_PROJECT_FILTER_NONE ||
            (window.projectNameById && window.projectNameById[sidebarFilter])
        )) {
            batchSel.value = sidebarFilter;
        }
        const searchInput = document.getElementById('batch-search-input');
        if (searchInput) searchInput.value = '';
        applyBatchConversationFilters();
        openAppModal('batch-manage-modal', { focus: false });
    } catch (error) {
        console.error('Failed to load conversation list:', error);
        initProjectFilterCustomSelect(BATCH_PROJECT_FILTER_SELECT_ID);
        allConversationsForBatch = [];
        await refreshBatchProjectFilter();
        applyBatchConversationFilters();
        openAppModal('batch-manage-modal', { focus: false });
    }
}

// Safely truncate strings, avoiding cutting in the middle of a character
function safeTruncateText(text, maxLength = 50) {
    if (!text || typeof text !== 'string') {
        return text || '';
    }

    // Use Array.from to convert the string to a character array (correctly handles Unicode surrogate pairs)
    const chars = Array.from(text);

    // If the text length does not exceed the limit, return directly
    if (chars.length <= maxLength) {
        return text;
    }

    // Truncate to max length (by character count, not code units)
    let truncatedChars = chars.slice(0, maxLength);

    // Try truncating at punctuation or spaces to make the cut more natural
    // Search backward from the cut point for a suitable break (no more than 20% of the length)
    const searchRange = Math.floor(maxLength * 0.2);
    const breakChars = ['，', '。', '、', ' ', ',', '.', ';', ':', '!', '?', '！', '？', '/', '\\', '-', '_'];
    let bestBreakPos = truncatedChars.length;

    for (let i = truncatedChars.length - 1; i >= truncatedChars.length - searchRange && i >= 0; i--) {
        if (breakChars.includes(truncatedChars[i])) {
            bestBreakPos = i + 1; // Break after the punctuation mark
            break;
        }
    }

    // If a suitable break is found, use it; otherwise use the original cut position
    if (bestBreakPos < truncatedChars.length) {
        truncatedChars = truncatedChars.slice(0, bestBreakPos);
    }

    // Convert the character array back to a string and append an ellipsis
    return truncatedChars.join('') + '...';
}

// Render batch management conversation list
function renderBatchConversations(filtered = null) {
    const list = document.getElementById('batch-conversations-list');
    if (!list) return;

    const conversations = filtered || allConversationsForBatch;
    list.innerHTML = '';

    conversations.forEach(conv => {
        const row = document.createElement('div');
        row.className = 'batch-conversation-row';
        row.dataset.conversationId = conv.id;

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'batch-conversation-checkbox theme-checkbox';
        checkbox.dataset.conversationId = conv.id;
        checkbox.addEventListener('change', syncSelectAllBatchCheckbox);

        const checkboxCol = document.createElement('div');
        checkboxCol.className = 'batch-table-col-checkbox';
        checkboxCol.appendChild(checkbox);

        const name = document.createElement('div');
        name.className = 'batch-table-col-name';
        const originalTitle = conv.title || (typeof window.t === 'function' ? window.t('batchManageModal.unnamedConversation') : 'Untitled conversation');
        const truncatedTitle = safeTruncateText(originalTitle, 36);
        name.textContent = truncatedTitle;
        name.title = originalTitle;

        const project = document.createElement('div');
        project.className = 'batch-table-col-project';
        const projectLabel = getConversationProjectLabel(conv);
        const truncatedProject = safeTruncateText(projectLabel, 28);
        project.textContent = truncatedProject;
        project.title = projectLabel;
        if (!getConversationProjectId(conv)) {
            project.classList.add('is-unbound');
        }

        const time = document.createElement('div');
        time.className = 'batch-table-col-time';
        const dateObj = conv.updatedAt ? new Date(conv.updatedAt) : new Date();
        const locale = (typeof i18next !== 'undefined' && i18next.language) ? i18next.language : 'zh-CN';
        time.textContent = dateObj.toLocaleString(locale, {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });

        const action = document.createElement('div');
        action.className = 'batch-table-col-action';
        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'batch-delete-btn';
        deleteBtn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6h14zM10 11v6M14 11v6"
                      stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        `;
        const deleteLabel = typeof window.t === 'function' ? window.t('contextMenu.deleteConversation') : 'Delete this conversation';
        deleteBtn.title = deleteLabel;
        deleteBtn.setAttribute('aria-label', deleteLabel);
        deleteBtn.onclick = (e) => {
            e.stopPropagation();
            deleteConversation(conv.id);
        };
        action.appendChild(deleteBtn);

        row.appendChild(checkboxCol);
        row.appendChild(name);
        row.appendChild(project);
        row.appendChild(time);
        row.appendChild(action);

        list.appendChild(row);
    });

    syncSelectAllBatchCheckbox();
}

// Filter batch management conversations
function filterBatchConversations() {
    applyBatchConversationFilters();
}

// Select all / deselect all
function toggleSelectAllBatch() {
    const selectAll = document.getElementById('batch-select-all');
    const checkboxes = document.querySelectorAll('.batch-conversation-checkbox');

    if (selectAll) {
        selectAll.indeterminate = false;
    }
    checkboxes.forEach(cb => {
        cb.checked = selectAll.checked;
    });
}

function syncSelectAllBatchCheckbox() {
    const selectAll = document.getElementById('batch-select-all');
    if (!selectAll) return;

    const checkboxes = document.querySelectorAll('.batch-conversation-checkbox');
    const total = checkboxes.length;
    const checked = document.querySelectorAll('.batch-conversation-checkbox:checked').length;

    if (total === 0 || checked === 0) {
        selectAll.checked = false;
        selectAll.indeterminate = false;
    } else if (checked === total) {
        selectAll.checked = true;
        selectAll.indeterminate = false;
    } else {
        selectAll.checked = false;
        selectAll.indeterminate = true;
    }
}

// Delete selected conversations
async function deleteSelectedConversations() {
    if (typeof requirePermission === 'function' && !requirePermission('chat:delete')) return;
    const checkboxes = document.querySelectorAll('.batch-conversation-checkbox:checked');
    if (checkboxes.length === 0) {
        alert(typeof window.t === 'function' ? window.t('batchManageModal.confirmDeleteNone') : 'Select the conversations to delete first');
        return;
    }

    const confirmMsg = typeof window.t === 'function' ? window.t('batchManageModal.confirmDeleteN', { count: checkboxes.length }) : 'Delete the selected ' + checkboxes.length + ' conversations?';
    if (!confirm(confirmMsg)) {
        return;
    }

    const ids = Array.from(checkboxes).map(cb => cb.dataset.conversationId);

    try {
        for (const id of ids) {
            await deleteConversation(id, true); // Skip internal confirmation, since batch delete already confirmed
        }
        // Keep the dialog open after deletion so the remaining conversations can be managed
        const selectAll = document.getElementById('batch-select-all');
        if (selectAll) {
            selectAll.checked = false;
            selectAll.indeterminate = false;
        }
    } catch (error) {
        console.error('Delete failed:', error);
        const failedMsg = typeof window.t === 'function' ? window.t('batchManageModal.deleteFailed') : 'Delete failed';
        const unknownErr = 'Unknown error';
        alert(failedMsg + ': ' + (error.message || unknownErr));
    }
}

// Close batch management modal
function closeBatchManageModal() {
    closeAllProjectFilterCustomSelects();
    closeAppModal('batch-manage-modal');
    const selectAll = document.getElementById('batch-select-all');
    if (selectAll) {
        selectAll.checked = false;
        selectAll.indeterminate = false;
    }
    const searchInput = document.getElementById('batch-search-input');
    if (searchInput) searchInput.value = '';
    const batchProj = document.getElementById('batch-project-filter');
    if (batchProj) batchProj.value = '';
    allConversationsForBatch = [];
}

// On language switch, refresh the time and dynamic text on the current chat page (message and execution-flow times are handled by monitor's refreshProgressAndTimelineI18n)
function refreshChatPanelI18n() {
    const locale = (typeof window.uiLocale === 'function' ? window.uiLocale() : 'en-US');
    const timeOpts = { hour: '2-digit', minute: '2-digit' };
    if (locale === 'zh-CN' || locale === 'ru-RU') timeOpts.hour12 = false;
    const t = typeof window.t === 'function' ? window.t : function (k) { return k; };

    const messagesEl = document.getElementById('chat-messages');
    if (messagesEl) {
        messagesEl.querySelectorAll('.message-time[data-message-time]').forEach(function (el) {
            try {
                const d = new Date(el.dataset.messageTime);
                if (!isNaN(d.getTime())) {
                    el.textContent = d.toLocaleTimeString(locale, timeOpts);
                }
            } catch (e) { /* ignore */ }
        });
        messagesEl.querySelectorAll('.process-detail-btn').forEach(function (btn) {
            const span = btn.querySelector('span');
            if (!span) return;
            const assistantEl = btn.closest('.message.assistant');
            const messageId = assistantEl && assistantEl.id;
            const detailsId = messageId ? 'process-details-' + messageId : '';
            const timeline = detailsId ? document.getElementById(detailsId) && document.getElementById(detailsId).querySelector('.progress-timeline') : null;
            const expanded = timeline && timeline.classList.contains('expanded');
            span.textContent = expanded ? t('tasks.collapseDetail') : t('chat.expandDetail');
        });
        const copyLabel = t('common.copy');
        const copyTitle = t('chat.copyMessageTitle');
        messagesEl.querySelectorAll('.message-copy-btn').forEach(function (btn) {
            if (btn.dataset.copySuccessActive === '1') return;
            const span = btn.querySelector('span');
            if (span) span.textContent = copyLabel;
            btn.title = copyTitle;
            btn.setAttribute('aria-label', copyTitle);
        });
        messagesEl.querySelectorAll('.message.assistant').forEach(function (msgEl) {
            if (typeof window.syncAssistantTurnSummary === 'function') {
                window.syncAssistantTurnSummary(msgEl);
            }
            if (typeof window.syncMcpToolsToggleButton === 'function') {
                window.syncMcpToolsToggleButton(msgEl);
            }
        });
        if (window.VeritySecChatScroll && typeof window.VeritySecChatScroll.refreshTurnRail === 'function') {
            window.VeritySecChatScroll.refreshTurnRail();
        }
    }

    if (isAppModalOpen('mcp-detail-modal')) {
        const detailTimeEl = document.getElementById('detail-time');
        if (detailTimeEl && detailTimeEl.dataset.detailTimeIso) {
            try {
                const d = new Date(detailTimeEl.dataset.detailTimeIso);
                if (!isNaN(d.getTime())) {
                    detailTimeEl.textContent = d.toLocaleString(locale);
                }
            } catch (e) { /* ignore */ }
        }
        const statusEl = document.getElementById('detail-status');
        if (statusEl && statusEl.dataset.detailStatus !== undefined && typeof getStatusText === 'function') {
            statusEl.textContent = getStatusText(statusEl.dataset.detailStatus);
        }
    }
}

// On language switch, refresh the batch management modal title (if shown); also refresh conversation list time formats and the system-ready hint; refresh current page message times and dynamic text
document.addEventListener('languagechange', function () {
    refreshSystemReadyMessageBubbles();
    refreshChatPanelI18n();
    if (typeof refreshConversationProjectFilter === 'function') {
        refreshConversationProjectFilter();
    }
    if (typeof refreshBatchProjectFilter === 'function') {
        refreshBatchProjectFilter().then(() => {
            const modal = document.getElementById('batch-manage-modal');
            if (modal && isAppModalOpen('batch-manage-modal') && typeof applyBatchConversationFilters === 'function') {
                applyBatchConversationFilters();
            }
        });
    }
    // Timestamps in lists such as the sidebar's recent conversations change with language (24h/12h etc.); re-fetch the lists to unify the format
    if (typeof loadConversations === 'function') {
        loadConversations();
    }
});

// Load conversation list on initialization
document.addEventListener('DOMContentLoaded', async () => {
    ensureProjectSidebarStructure();
    if (window.i18nReady) await window.i18nReady;
    if (typeof window.applyTranslations === 'function') {
        window.applyTranslations(document.getElementById('conversation-sidebar'));
    }
    // The task bar no longer exposes the project filter; clear the old selection so some tasks are not hidden.
    setConversationProjectFilter('');
    restoreRecentConversationsState();
    updateConversationSortMenuUI();
    initConversationProjectCustomSelect();
    initConversationsPaginationEvents();
    await refreshConversationProjectFilter();
    await loadConversations();

    // Auto-refresh the conversation list when the page gains focus
    // This way, when a conversation is created via OpenAPI, switching back to the page shows the new conversation
    let lastFocusTime = Date.now();
    const CONVERSATION_REFRESH_INTERVAL = 30000; // refresh at most once per 30 seconds, to avoid being too frequent

    window.addEventListener('focus', () => {
        const now = Date.now();
        // Refresh the conversation list only if more than 30 seconds have passed since the last refresh
        if (now - lastFocusTime > CONVERSATION_REFRESH_INTERVAL) {
            lastFocusTime = now;
            if (typeof loadConversations === 'function') {
                loadConversations();
            }
        }
    });

    // Listen for page visibility changes (when the user switches back to the tab)
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            // When the page becomes visible, check whether a refresh is needed
            const now = Date.now();
            if (now - lastFocusTime > CONVERSATION_REFRESH_INTERVAL) {
                lastFocusTime = now;
                if (typeof loadConversations === 'function') {
                    loadConversations();
                }
            }
        }
    });

    // Sync after deleting a conversation from any entry point: if the deleted conversation is the current one, clear the main area and refresh the sidebar list (e.g. deleted from the WebShell AI assistant)
    document.addEventListener('conversation-deleted', (e) => {
        const id = e.detail && e.detail.conversationId;
        if (!id) return;
        // Remove the visible list item immediately after the API confirms deletion; the network refresh only calibrates pagination and counts.
        document.querySelectorAll('.conversation-item[data-conversation-id]')
            .forEach((item) => {
                if (item.dataset.conversationId === id) item.remove();
            });
        if (id === currentConversationId) {
            currentConversationId = null;
            try {
                window.currentConversationId = '';
            } catch (e) { /* ignore */ }
            const messagesDiv = document.getElementById('chat-messages');
            if (messagesDiv) messagesDiv.innerHTML = '';
            renderChatWelcomeEmptyState();
            addAttackChainButton(null);
        }
        if (typeof loadConversations === 'function') {
            loadConversations();
        }
    });
});

async function refreshAllProjectFilterSelects() {
    await refreshConversationProjectFilter();
    await refreshBatchProjectFilter();
}

// A top-level async function is not automatically attached to window; hitl and other scripts depend on window.loadConversation
if (typeof window !== 'undefined') {
    window.loadConversation = loadConversation;
    window.startNewConversation = startNewConversation;
    window.refreshChatWelcomeEmptyState = refreshSystemReadyMessageBubbles;
    window.openConversationContextMenuForId = openConversationContextMenuForId;
    window.renameConversation = renameConversation;
    window.closeConversationRenameModal = closeConversationRenameModal;
    window.saveConversationRename = saveConversationRename;
    window.refreshConversationProjectFilter = refreshConversationProjectFilter;
    window.refreshAllProjectFilterSelects = refreshAllProjectFilterSelects;
    window.onConversationProjectFilterChange = onConversationProjectFilterChange;
}
