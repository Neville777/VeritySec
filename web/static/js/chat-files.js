// Chat attachments (chat_uploads) file management

let chatFilesCache = [];
/** Directory relative paths returned by backend GET /api/chat-uploads (including empty folders), merged with files into a tree */
let chatFilesFoldersCache = [];
const chatFilesProjectNameById = {};
const chatFilesConversationTitleById = {};
let chatFilesDisplayed = [];
let chatFilesEditRelativePath = '';
let chatFilesRenameRelativePath = '';
let chatFilesTotal = 0;
let chatFilesPage = 1;
let chatFilesPageSize = 20;
let chatFilesSearchDebounceTimer = null;

function chatFilesEscapeAttr(text) {
    return escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const CHAT_FILES_GROUP_STORAGE_KEY = 'csai_chat_files_group_by';
const CHAT_FILES_BROWSE_PATH_KEY = 'csai_chat_files_browse_path';
const CHAT_FILES_PAGE_SIZE_STORAGE_KEY = 'csai_chat_files_page_size';
const CHAT_FILES_TREE_UPLOAD_ROOT = 'uploads';
const CHAT_FILES_TREE_REDUCTION_ROOT = 'tool_outputs';
const CHAT_FILES_TREE_WORKSPACE_ROOT = 'workspace';
const CHAT_FILES_TREE_ARTIFACT_ROOT = 'conversation_artifacts';

/** Current path in folder browsing mode (virtual root segment array), e.g. ['uploads','2024-03-21','uuid'] */
let chatFilesBrowsePath = [];
/** When non-empty, the next uploaded file goes to this relative path (a directory under chat_uploads), e.g. 2026-03-21/uuid/sub */
let chatFilesPendingUploadDir = '';
/** File upload to the server is in progress; avoid duplicate selection and disable top-bar buttons */
let chatFilesXHRUploadBusy = false;

const CHAT_FILES_FILTER_SELECT_IDS = ['chat-files-filter-source', 'chat-files-group-by'];
const chatFilesFilterSelectMap = {};
let chatFilesFilterSelectDocBound = false;
const CHAT_FILES_FILTER_SELECT_CARET = '<svg class="chat-files-filter-select-caret" width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function closeAllChatFilesFilterSelects() {
    Object.keys(chatFilesFilterSelectMap).forEach(function (id) {
        const reg = chatFilesFilterSelectMap[id];
        if (!reg || !reg.wrapper) return;
        reg.wrapper.classList.remove('open');
        if (reg.trigger) reg.trigger.setAttribute('aria-expanded', 'false');
    });
}

function chatFilesRememberDisplayNames(files) {
    Object.keys(chatFilesProjectNameById).forEach(function (k) { delete chatFilesProjectNameById[k]; });
    Object.keys(chatFilesConversationTitleById).forEach(function (k) { delete chatFilesConversationTitleById[k]; });
    (Array.isArray(files) ? files : []).forEach(function (f) {
        const pid = String((f && f.projectId) || '').trim();
        const pname = String((f && f.projectName) || '').trim();
        if (pid && pname) chatFilesProjectNameById[pid] = pname;
        const cid = String((f && f.conversationId) || '').trim();
        const ctitle = String((f && f.conversationTitle) || '').trim();
        if (cid && ctitle) chatFilesConversationTitleById[cid] = ctitle;
    });
}

function syncChatFilesFilterSelect(selectId) {
    const reg = chatFilesFilterSelectMap[selectId];
    if (!reg) return;
    const select = reg.select;
    const dropdown = reg.dropdown;
    const trigger = reg.trigger;
    const valueSpan = trigger.querySelector('.chat-files-filter-select-value');

    dropdown.innerHTML = '';
    Array.prototype.forEach.call(select.options, function (opt) {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'chat-files-filter-select-option';
        item.setAttribute('role', 'option');
        item.setAttribute('data-value', opt.value);
        if (opt.value === select.value) {
            item.classList.add('is-selected');
            item.setAttribute('aria-selected', 'true');
        } else {
            item.setAttribute('aria-selected', 'false');
        }
        const check = document.createElement('span');
        check.className = 'chat-files-filter-select-check';
        check.setAttribute('aria-hidden', 'true');
        check.textContent = '✓';
        const label = document.createElement('span');
        label.className = 'chat-files-filter-select-label';
        label.textContent = opt.textContent;
        item.appendChild(check);
        item.appendChild(label);
        dropdown.appendChild(item);
    });

    const selectedOpt = select.options[select.selectedIndex];
    if (valueSpan) {
        valueSpan.textContent = selectedOpt ? selectedOpt.textContent : '';
    }
    trigger.disabled = !!select.disabled;
    reg.wrapper.classList.toggle('is-disabled', !!select.disabled);
}

function syncAllChatFilesFilterSelects() {
    CHAT_FILES_FILTER_SELECT_IDS.forEach(syncChatFilesFilterSelect);
}

function enhanceChatFilesFilterSelect(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return;
    const existing = chatFilesFilterSelectMap[selectId];
    if (existing && existing.select !== select) {
        delete chatFilesFilterSelectMap[selectId];
    }
    if (select.dataset.chatFilesCustomSelect === '1') {
        syncChatFilesFilterSelect(selectId);
        return;
    }
    select.dataset.chatFilesCustomSelect = '1';
    select.classList.add('chat-files-filter-native-select');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');

    const wrapper = document.createElement('div');
    wrapper.className = 'chat-files-filter-select-ui';

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'chat-files-filter-select-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    const valueSpan = document.createElement('span');
    valueSpan.className = 'chat-files-filter-select-value';
    trigger.appendChild(valueSpan);
    trigger.insertAdjacentHTML('beforeend', CHAT_FILES_FILTER_SELECT_CARET);

    const dropdown = document.createElement('div');
    dropdown.className = 'chat-files-filter-select-dropdown';
    dropdown.setAttribute('role', 'listbox');

    const parent = select.parentNode;
    parent.insertBefore(wrapper, select);
    wrapper.appendChild(trigger);
    wrapper.appendChild(dropdown);
    wrapper.appendChild(select);

    chatFilesFilterSelectMap[selectId] = { wrapper: wrapper, trigger: trigger, dropdown: dropdown, select: select };

    trigger.addEventListener('click', function (e) {
        e.stopPropagation();
        if (select.disabled) return;
        const open = wrapper.classList.contains('open');
        closeAllChatFilesFilterSelects();
        if (!open) {
            wrapper.classList.add('open');
            trigger.setAttribute('aria-expanded', 'true');
        }
    });

    dropdown.addEventListener('click', function (e) {
        const opt = e.target.closest('.chat-files-filter-select-option');
        if (!opt) return;
        e.stopPropagation();
        const val = opt.getAttribute('data-value');
        if (val === null) return;
        if (select.value !== val) {
            select.value = val;
            select.dispatchEvent(new Event('change', { bubbles: true }));
        }
        wrapper.classList.remove('open');
        trigger.setAttribute('aria-expanded', 'false');
        syncChatFilesFilterSelect(selectId);
    });

    select.addEventListener('change', function () {
        syncChatFilesFilterSelect(selectId);
    });

    if (!select.dataset.chatFilesFilterBound) {
        select.dataset.chatFilesFilterBound = '1';
        select.addEventListener('change', chatFilesGroupByChange);
    }

    syncChatFilesFilterSelect(selectId);
}

function initChatFilesFilterSelects() {
    if (!chatFilesFilterSelectDocBound) {
        document.addEventListener('click', closeAllChatFilesFilterSelects);
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') closeAllChatFilesFilterSelects();
        });
        chatFilesFilterSelectDocBound = true;
    }
    CHAT_FILES_FILTER_SELECT_IDS.forEach(enhanceChatFilesFilterSelect);
    syncAllChatFilesFilterSelects();
}

function chatFilesLoadBrowsePathFromStorage() {
    try {
        const raw = localStorage.getItem(CHAT_FILES_BROWSE_PATH_KEY);
        if (!raw) {
            chatFilesBrowsePath = [];
            return;
        }
        const p = JSON.parse(raw);
        if (Array.isArray(p) && p.every(function (x) {
            return typeof x === 'string';
        })) {
            chatFilesBrowsePath = p;
        }
    } catch (e) {
        chatFilesBrowsePath = [];
    }
}

function chatFilesSetBrowsePath(path) {
    chatFilesBrowsePath = path.slice();
    try {
        localStorage.setItem(CHAT_FILES_BROWSE_PATH_KEY, JSON.stringify(chatFilesBrowsePath));
    } catch (e) {
        /* ignore */
    }
}

function chatFilesLoadPageSizeFromStorage() {
    try {
        const n = parseInt(localStorage.getItem(CHAT_FILES_PAGE_SIZE_STORAGE_KEY) || '', 10);
        if ([10, 20, 50, 100].includes(n)) {
            chatFilesPageSize = n;
        }
    } catch (e) {
        /* ignore */
    }
}

function chatFilesResolveTreeNode(root, path) {
    let node = root;
    let i;
    for (i = 0; i < path.length; i++) {
        const seg = path[i];
        if (!node.dirs[seg]) return null;
        node = node.dirs[seg];
    }
    return node;
}

function chatFilesNormalizeBrowsePathForTree(root) {
    let path = chatFilesBrowsePath.slice();
    while (path.length > 0 && !chatFilesResolveTreeNode(root, path)) {
        path.pop();
    }
    if (path.length !== chatFilesBrowsePath.length) {
        chatFilesSetBrowsePath(path);
    }
}

function initChatFilesPage() {
    chatFilesLoadBrowsePathFromStorage();
    chatFilesLoadPageSizeFromStorage();
    try {
        localStorage.removeItem('csai_chat_files_synthetic_dirs');
    } catch (e) {
        /* ignore */
    }
    ensureChatFilesDocClickClose();
    const sel = document.getElementById('chat-files-group-by');
    if (sel) {
        try {
            const v = localStorage.getItem(CHAT_FILES_GROUP_STORAGE_KEY);
            if (v === 'none' || v === 'date' || v === 'conversation' || v === 'project' || v === 'folder') {
                sel.value = v;
            }
        } catch (e) {
            /* ignore */
        }
    }
    initChatFilesFilterSelects();
    setupChatFilesDragDrop();
    loadChatFilesPage();
}

function chatFilesCloseAllMenus() {
    document.querySelectorAll('.chat-files-dropdown').forEach((el) => {
        el.hidden = true;
        el.style.position = '';
        el.style.left = '';
        el.style.top = '';
        el.style.right = '';
        el.style.minWidth = '';
        el.style.zIndex = '';
        el.classList.remove('chat-files-dropdown-fixed');
    });
}

/**
 * The "More" menu uses fixed positioning so the table's outer overflow does not clip it into a thin line.
 */
function chatFilesToggleMoreMenu(ev, idx) {
    if (ev) ev.stopPropagation();
    const menu = document.getElementById('chat-files-menu-' + idx);
    const btn = ev && ev.currentTarget;
    if (!menu) return;
    const opening = menu.hidden;
    chatFilesCloseAllMenus();
    if (!opening) return;

    menu.hidden = false;
    menu.classList.add('chat-files-dropdown-fixed');
    if (!btn || typeof btn.getBoundingClientRect !== 'function') return;

    requestAnimationFrame(() => {
        const r = btn.getBoundingClientRect();
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const margin = 8;
        const minW = 220;
        menu.style.boxSizing = 'border-box';
        menu.style.position = 'fixed';
        menu.style.zIndex = '5000';
        menu.style.minWidth = minW + 'px';
        menu.style.right = 'auto';

        const w = Math.max(minW, menu.offsetWidth || minW);
        let left = r.right - w;
        if (left < margin) left = margin;
        if (left + w > vw - margin) left = Math.max(margin, vw - margin - w);
        menu.style.left = left + 'px';

        const gap = 6;
        let top = r.bottom + gap;
        const estH = menu.offsetHeight || 120;
        if (top + estH > vh - margin && r.top - gap - estH >= margin) {
            top = r.top - gap - estH;
        }
        menu.style.top = top + 'px';
    });
}

window.chatFilesCloseAllMenus = chatFilesCloseAllMenus;
window.chatFilesToggleMoreMenu = chatFilesToggleMoreMenu;

function ensureChatFilesDocClickClose() {
    if (window.__chatFilesDocClose) return;
    window.__chatFilesDocClose = true;
    document.addEventListener('click', function (ev) {
        if (ev.target.closest && ev.target.closest('.chat-files-dropdown-wrap')) return;
        chatFilesCloseAllMenus();
    });
    document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape') chatFilesCloseAllMenus();
    });
    window.addEventListener(
        'scroll',
        function () {
            chatFilesCloseAllMenus();
        },
        true
    );
    window.addEventListener('resize', function () {
        chatFilesCloseAllMenus();
    });
}

async function loadChatFilesPage() {
    const wrap = document.getElementById('chat-files-list-wrap');
    if (!wrap) return;
    const pager = document.getElementById('chat-files-pagination');
    if (pager) pager.hidden = true;
    wrap.classList.remove('chat-files-table-wrap--grouped');
    wrap.classList.remove('chat-files-table-wrap--tree');
    wrap.innerHTML = '<div class="loading-spinner" data-i18n="common.loading">Loading…</div>';
    if (typeof window.applyTranslations === 'function') {
        window.applyTranslations(wrap);
    }

    const conv = document.getElementById('chat-files-filter-conv');
    const convQ = conv ? conv.value.trim() : '';
    const project = document.getElementById('chat-files-filter-project');
    const projectQ = project ? project.value.trim() : '';
    const source = document.getElementById('chat-files-filter-source');
    const sourceQ = source ? source.value : 'all';
    const search = document.getElementById('chat-files-filter-name');
    const searchQ = search ? search.value.trim() : '';
    const groupMode = chatFilesGetGroupByMode();
    const params = new URLSearchParams();
    if (convQ) {
        params.set('conversation', convQ);
    }
    if (projectQ) {
        params.set('project', projectQ);
    }
    if (sourceQ && sourceQ !== 'all') {
        params.set('source', sourceQ);
    }
    if (searchQ) {
        params.set('search', searchQ);
    }
    params.set('page', String(chatFilesPage));
    params.set('pageSize', groupMode === 'folder' ? 'all' : String(chatFilesPageSize));
    let url = '/api/chat-uploads';
    const query = params.toString();
    if (query) url += '?' + query;

    try {
        const res = await apiFetch(url);
        if (!res.ok) {
            const t = await res.text();
            throw new Error(t || res.status);
        }
        const data = await res.json();
        chatFilesCache = Array.isArray(data.files) ? data.files : [];
        chatFilesRememberDisplayNames(chatFilesCache);
        chatFilesFoldersCache = Array.isArray(data.folders) ? data.folders : [];
        chatFilesTotal = Number.isFinite(Number(data.total)) ? Number(data.total) : chatFilesCache.length;
        chatFilesPage = Number.isFinite(Number(data.page)) ? Math.max(1, Number(data.page)) : chatFilesPage;
        if (Number.isFinite(Number(data.pageSize)) && Number(data.pageSize) > 0) {
            chatFilesPageSize = Number(data.pageSize);
        }
        if (groupMode !== 'folder' && chatFilesTotal > 0 && chatFilesCache.length === 0 && chatFilesPage > chatFilesTotalPages()) {
            chatFilesPage = chatFilesTotalPages();
            loadChatFilesPage();
            return;
        }
        renderChatFilesTable();
    } catch (e) {
        console.error(e);
        wrap.classList.remove('chat-files-table-wrap--grouped');
        wrap.classList.remove('chat-files-table-wrap--tree');
        const msg = (typeof window.t === 'function') ? window.t('chatFilesPage.errorLoad') : 'Failed to load';
        wrap.innerHTML = '<div class="error-message">' + escapeHtml(msg + ': ' + (e.message || String(e))) + '</div>';
        renderChatFilesPagination();
    }
}

async function exportChatFiles() {
    const conv = document.getElementById('chat-files-filter-conv');
    const project = document.getElementById('chat-files-filter-project');
    const convQ = conv ? conv.value.trim() : '';
    const projectQ = project ? project.value.trim() : '';
    const source = document.getElementById('chat-files-filter-source');
    const sourceQ = source ? source.value : 'all';
    const search = document.getElementById('chat-files-filter-name');
    const searchQ = search ? search.value.trim() : '';
    const params = new URLSearchParams();
    if (convQ) params.set('conversation', convQ);
    if (projectQ) params.set('project', projectQ);
    if (sourceQ && sourceQ !== 'all') params.set('source', sourceQ);
    if (searchQ) params.set('search', searchQ);
    const url = '/api/chat-uploads/export' + (params.toString() ? ('?' + params.toString()) : '');
    try {
        const res = await apiFetch(url);
        if (!res.ok) {
            const raw = await res.text();
            let msg = raw;
            try {
                const j = JSON.parse(raw);
                if (j && j.error) msg = j.error;
            } catch (e) {
                /* keep raw */
            }
            if (res.status === 404) {
                msg = (typeof window.t === 'function') ? window.t('chatFilesPage.exportEmpty') : 'No files to export';
            }
            throw new Error(msg || String(res.status));
        }
        const blob = await res.blob();
        const disposition = res.headers.get('Content-Disposition') || '';
        let filename = 'chat-files-export.zip';
        const m = disposition.match(/filename="?([^"]+)"?/i);
        if (m && m[1]) filename = m[1];
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
        const ok = (typeof window.t === 'function') ? window.t('chatFilesPage.exportStarted') : 'Export started';
        chatFilesShowToast(ok);
    } catch (e) {
        alert((e && e.message) ? e.message : String(e));
    }
}

function chatFilesNameFilter(files) {
    return Array.isArray(files) ? files : [];
}

function chatFilesResetToFirstPageAndLoad() {
    chatFilesPage = 1;
    loadChatFilesPage();
}

function chatFilesFilterNameOnInput() {
    if (chatFilesSearchDebounceTimer) clearTimeout(chatFilesSearchDebounceTimer);
    chatFilesSearchDebounceTimer = setTimeout(function () {
        chatFilesSearchDebounceTimer = null;
        chatFilesResetToFirstPageAndLoad();
    }, 250);
}

function chatFilesTotalPages() {
    if (chatFilesGetGroupByMode() === 'folder') return 1;
    return Math.max(1, Math.ceil((chatFilesTotal || 0) / Math.max(1, chatFilesPageSize)));
}

function renderChatFilesPagination() {
    const pager = document.getElementById('chat-files-pagination');
    if (!pager) return;
    const groupMode = chatFilesGetGroupByMode();
    if (groupMode === 'folder' || chatFilesTotal <= 0) {
        pager.hidden = true;
        pager.innerHTML = '';
        if (typeof initPaginationSelects === 'function') initPaginationSelects(pager);
        return;
    }
    const totalPages = chatFilesTotalPages();
    if (chatFilesPage > totalPages) {
        chatFilesPage = totalPages;
    }
    const start = (chatFilesPage - 1) * chatFilesPageSize + 1;
    const end = Math.min(chatFilesTotal, chatFilesPage * chatFilesPageSize);
    const info = (typeof window.t === 'function')
        ? window.t('chatFilesPage.paginationInfo', { start: start, end: end, total: chatFilesTotal })
        : ('Showing ' + start + '-' + end + ' of ' + chatFilesTotal);
    const pageText = (typeof window.t === 'function')
        ? window.t('chatFilesPage.paginationPage', { page: chatFilesPage, totalPages: totalPages })
        : ('Page ' + chatFilesPage + ' / ' + totalPages);
    const pageSizeLabel = (typeof window.t === 'function') ? window.t('chatFilesPage.pageSize') : 'Per page';
    const prevLabel = (typeof window.t === 'function') ? window.t('chatFilesPage.prevPage') : 'Previous page';
    const nextLabel = (typeof window.t === 'function') ? window.t('chatFilesPage.nextPage') : 'Next page';
    const sizes = [10, 20, 50, 100].map(function (n) {
        return '<option value="' + n + '"' + (n === chatFilesPageSize ? ' selected' : '') + '>' + n + '</option>';
    }).join('');
    pager.innerHTML = `
        <div class="pagination-info">
            <span>${escapeHtml(info)}</span>
            <label class="pagination-page-size">${escapeHtml(pageSizeLabel)}
                <select onchange="changeChatFilesPageSize(this.value)">${sizes}</select>
            </label>
        </div>
        <div class="pagination-controls">
            <button type="button" class="btn-secondary" ${chatFilesPage <= 1 ? 'disabled' : ''} onclick="changeChatFilesPage(${chatFilesPage - 1})">${escapeHtml(prevLabel)}</button>
            <span class="pagination-page">${escapeHtml(pageText)}</span>
            <button type="button" class="btn-secondary" ${chatFilesPage >= totalPages ? 'disabled' : ''} onclick="changeChatFilesPage(${chatFilesPage + 1})">${escapeHtml(nextLabel)}</button>
        </div>`;
    pager.hidden = false;
    if (typeof initPaginationSelects === 'function') initPaginationSelects(pager);
}

function changeChatFilesPage(page) {
    const totalPages = chatFilesTotalPages();
    const next = Math.min(totalPages, Math.max(1, parseInt(page, 10) || 1));
    if (next === chatFilesPage) return;
    chatFilesPage = next;
    loadChatFilesPage();
}

function changeChatFilesPageSize(value) {
    const n = parseInt(value, 10);
    if (![10, 20, 50, 100].includes(n)) return;
    chatFilesPageSize = n;
    chatFilesPage = 1;
    try {
        localStorage.setItem(CHAT_FILES_PAGE_SIZE_STORAGE_KEY, String(n));
    } catch (e) {
        /* ignore */
    }
    loadChatFilesPage();
}

function formatChatFileBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
}

function chatFilesShowToast(message) {
    const el = document.createElement('div');
    el.className = 'chat-files-toast';
    el.setAttribute('role', 'status');
    el.textContent = message;
    document.body.appendChild(el);
    requestAnimationFrame(() => el.classList.add('chat-files-toast-visible'));
    setTimeout(() => {
        el.classList.remove('chat-files-toast-visible');
        setTimeout(() => el.remove(), 300);
    }, 2200);
}

async function chatFilesCopyText(text) {
    try {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            await navigator.clipboard.writeText(text);
            return true;
        }
    } catch (e) {
        /* fall through */
    }
    try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
    } catch (e2) {
        return false;
    }
}

async function copyChatFilePathIdx(idx) {
    const f = chatFilesDisplayed[idx];
    if (!f) return;
    const text = (f.absolutePath && String(f.absolutePath).trim())
        ? String(f.absolutePath).trim()
        : ('chat_uploads/' + String(f.relativePath || '').replace(/^\/+/, ''));
    const ok = await chatFilesCopyText(text);
    if (ok) {
        const msg = (typeof window.t === 'function') ? window.t('chatFilesPage.pathCopied') : 'Path copied; paste it into a chat to reference it';
        chatFilesShowToast(msg);
    } else {
        const fail = (typeof window.t === 'function') ? window.t('common.copyFailed') : 'Copy failed';
        alert(fail);
    }
}

/** Common binary extensions: these files cannot be opened in a plain-text editor */
const CHAT_FILES_BINARY_EXT = new Set([
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'tif', 'tiff', 'heic', 'heif', 'svgz',
    'pdf', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'zst',
    'mp3', 'm4a', 'wav', 'ogg', 'flac', 'aac',
    'mp4', 'avi', 'mkv', 'mov', 'wmv', 'webm', 'm4v',
    'exe', 'dll', 'so', 'dylib', 'bin', 'app', 'dmg', 'pkg',
    'woff', 'woff2', 'ttf', 'otf', 'eot',
    'sqlite', 'db', 'sqlite3',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods',
    'class', 'jar', 'war', 'apk', 'ipa',
    'iso', 'img'
]);

function chatFileIsBinaryByName(fileName) {
    if (!fileName || typeof fileName !== 'string') return false;
    const i = fileName.lastIndexOf('.');
    if (i < 0 || i === fileName.length - 1) return false;
    const ext = fileName.slice(i + 1).toLowerCase();
    return CHAT_FILES_BINARY_EXT.has(ext);
}

function chatFilesEditBlockedHint() {
    return (typeof window.t === 'function')
        ? window.t('chatFilesPage.editBinaryHint')
        : 'Images, archives and other binary files cannot be edited as text here; please use "Download".';
}

function chatFilesAlertMessage(raw) {
    const s = (raw == null) ? '' : String(raw).trim();
    const lower = s.toLowerCase();
    if (lower.includes('binary file not editable') || lower.includes('binary')) {
        return chatFilesEditBlockedHint();
    }
    if (lower.includes('file too large') || lower.includes('entity too large') || lower.includes('413')) {
        return (typeof window.t === 'function') ? window.t('chatFilesPage.editTooLarge') : 'File is too large to edit here.';
    }
    return s || ((typeof window.t === 'function') ? window.t('chatFilesPage.errorGeneric') : 'Operation failed');
}

function chatFilesGetGroupByMode() {
    const sel = document.getElementById('chat-files-group-by');
    const v = sel ? sel.value : 'none';
    if (v === 'date' || v === 'conversation' || v === 'project' || v === 'folder') return v;
    return 'none';
}

function chatFilesGroupByChange() {
    const sel = document.getElementById('chat-files-group-by');
    if (sel) {
        try {
            localStorage.setItem(CHAT_FILES_GROUP_STORAGE_KEY, sel.value);
        } catch (e) {
            /* ignore */
        }
    }
    chatFilesResetToFirstPageAndLoad();
}

function chatFilesCompareDateKeysDesc(a, b) {
    const as = String(a);
    const bs = String(b);
    if (as === '—' && bs !== '—') return 1;
    if (bs === '—' && as !== '—') return -1;
    return bs.localeCompare(as);
}

/** Directory tree node: dirs[segment name] -> child node; files: { idx, name }[] */
function chatFilesTreeMakeNode() {
    return { dirs: {}, files: [] };
}

function chatFilesTreeInsertFile(root, f, idx) {
    const rp = chatFilesTreePathForFile(f);
    if (!rp) return;
    const parts = rp.split('/').filter(function (p) {
        return p.length > 0;
    });
    if (parts.length < 2) return;
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
        const seg = parts[i];
        if (!node.dirs[seg]) node.dirs[seg] = chatFilesTreeMakeNode();
        node = node.dirs[seg];
    }
    node.files.push({ idx: idx, name: parts[parts.length - 1] });
}

function chatFilesBuildTree(files) {
    const root = chatFilesTreeMakeNode();
    files.forEach(function (f, idx) {
        chatFilesTreeInsertFile(root, f, idx);
    });
    return root;
}

function chatFilesTreePathForFile(f) {
    const source = f && f.source;
    let rp = String((f && f.relativePath) || '').replace(/\\/g, '/').replace(/^\/+/, '');
    if (!rp) return '';
    if (source === 'reduction') {
        rp = rp.replace(/^__reduction__\//, '');
        return CHAT_FILES_TREE_REDUCTION_ROOT + '/' + rp;
    }
    if (source === 'workspace') {
        rp = rp.replace(/^__workspace__\//, '');
        return CHAT_FILES_TREE_WORKSPACE_ROOT + '/' + rp;
    }
    if (source === 'conversation_artifact') {
        rp = rp.replace(/^__conversation_artifact__\//, '');
        return CHAT_FILES_TREE_ARTIFACT_ROOT + '/' + rp;
    }
    return CHAT_FILES_TREE_UPLOAD_ROOT + '/' + rp;
}

/** Merge backend-returned directory relative paths (e.g. a/b/c) into the tree so empty folders can be shown */
function chatFilesTreeInsertFolderPath(root, relSlash) {
    const rp = String(relSlash || '').replace(/\\/g, '/').replace(/^\/+/, '');
    if (!rp) return;
    const parts = rp.split('/').filter(function (p) {
        return p.length > 0;
    });
    if (!parts.length) return;
    let node = root;
    let i;
    for (i = 0; i < parts.length; i++) {
        const seg = parts[i];
        if (!node.dirs[seg]) node.dirs[seg] = chatFilesTreeMakeNode();
        node = node.dirs[seg];
    }
}

function chatFilesMergeFoldersIntoTree(root, folderPaths) {
    if (!Array.isArray(folderPaths)) return;
    if (!chatFilesShouldMergeUploadFolders()) return;
    let i;
    for (i = 0; i < folderPaths.length; i++) {
        chatFilesTreeInsertFolderPath(root, CHAT_FILES_TREE_UPLOAD_ROOT + '/' + folderPaths[i]);
    }
}

function chatFilesTreeRootMerged() {
    const root = chatFilesBuildTree(chatFilesDisplayed);
    chatFilesMergeFoldersIntoTree(root, chatFilesFoldersCache);
    chatFilesEnsureSourceRoots(root);
    return root;
}

function chatFilesCurrentSourceFilter() {
    const el = document.getElementById('chat-files-filter-source');
    return el ? (el.value || 'all') : 'all';
}

function chatFilesCurrentSearchQuery() {
    const el = document.getElementById('chat-files-filter-name');
    return el ? String(el.value || '').trim() : '';
}

function chatFilesShouldMergeUploadFolders() {
    const source = chatFilesCurrentSourceFilter();
    return (source === 'all' || source === 'upload') && !chatFilesCurrentSearchQuery();
}

function chatFilesEnsureSourceRoots(root) {
    const source = chatFilesCurrentSourceFilter();
    const roots = [];
    if (source === 'all' || source === 'upload') roots.push(CHAT_FILES_TREE_UPLOAD_ROOT);
    if (source === 'all' || source === 'reduction') roots.push(CHAT_FILES_TREE_REDUCTION_ROOT);
    if (source === 'all' || source === 'workspace') roots.push(CHAT_FILES_TREE_WORKSPACE_ROOT);
    if (source === 'all' || source === 'conversation_artifact') roots.push(CHAT_FILES_TREE_ARTIFACT_ROOT);
    roots.forEach(function (name) {
        if (!root.dirs[name]) root.dirs[name] = chatFilesTreeMakeNode();
    });
}

function chatFilesIsInternalSource(f) {
    const source = f && f.source;
    return source === 'reduction' || source === 'workspace' || source === 'conversation_artifact';
}

function chatFilesSourceLabel(source) {
    if (source === 'reduction') {
        return (typeof window.t === 'function') ? window.t('chatFilesPage.sourceReduction') : 'Tool output';
    }
    if (source === 'workspace') {
        return (typeof window.t === 'function') ? window.t('chatFilesPage.sourceWorkspace') : 'Working directory';
    }
    if (source === 'conversation_artifact') {
        return (typeof window.t === 'function') ? window.t('chatFilesPage.sourceConversationArtifact') : 'Session artifacts';
    }
    return (typeof window.t === 'function') ? window.t('chatFilesPage.sourceUpload') : 'Chat attachments';
}

function chatFilesBrowseCanMutateCurrentPath() {
    return chatFilesBrowsePath[0] === CHAT_FILES_TREE_UPLOAD_ROOT;
}

function chatFilesBrowseCanUploadToPath(path) {
    return Array.isArray(path) && path[0] === CHAT_FILES_TREE_UPLOAD_ROOT;
}

function chatFilesBrowseCanDeleteFolderPath(path) {
    return Array.isArray(path) && path[0] === CHAT_FILES_TREE_UPLOAD_ROOT && path.length > 1;
}

function chatFilesTreeDisplayName(name) {
    if (name === CHAT_FILES_TREE_UPLOAD_ROOT) {
        return (typeof window.t === 'function') ? window.t('chatFilesPage.treeUploadsRoot') : 'Chat attachments';
    }
    if (name === CHAT_FILES_TREE_REDUCTION_ROOT) {
        return (typeof window.t === 'function') ? window.t('chatFilesPage.treeReductionRoot') : 'Tool output';
    }
    if (name === CHAT_FILES_TREE_WORKSPACE_ROOT) {
        return (typeof window.t === 'function') ? window.t('chatFilesPage.treeWorkspaceRoot') : 'Working directory';
    }
    if (name === CHAT_FILES_TREE_ARTIFACT_ROOT) {
        return (typeof window.t === 'function') ? window.t('chatFilesPage.treeArtifactsRoot') : 'Session artifacts';
    }
    return name;
}

function chatFilesIDDisplay(id, labelMap, emptyLabel) {
    const raw = id == null ? '' : String(id);
    if (!raw || raw === '—') {
        return { text: emptyLabel || '—', title: '' };
    }
    const label = String((labelMap && labelMap[raw]) || '').trim();
    if (label) {
        return { text: label, title: label + ' (' + raw + ')' };
    }
    if (raw.length > 36) {
        return { text: raw.slice(0, 8) + '…' + raw.slice(-6), title: raw };
    }
    return { text: raw, title: raw };
}

function chatFilesConversationDisplay(id) {
    const c = id == null ? '' : String(id);
    if (typeof window.t === 'function') {
        if (c === '_manual') {
            return { text: window.t('chatFilesPage.convManual'), title: '_manual' };
        }
        if (c === '_new') {
            return { text: window.t('chatFilesPage.convNew'), title: '_new' };
        }
    }
    return chatFilesIDDisplay(c, chatFilesConversationTitleById);
}

function chatFilesProjectDisplay(id) {
    const empty = (typeof window.t === 'function') ? window.t('chatFilesPage.projectUnbound') : 'No project bound';
    return chatFilesIDDisplay(id, chatFilesProjectNameById, empty);
}

function chatFilesTreePathDisplayName(pathParts) {
    const parts = Array.isArray(pathParts) ? pathParts : [];
    const name = parts.length ? parts[parts.length - 1] : '';
    const root = parts[0] || '';
    if ((root === CHAT_FILES_TREE_WORKSPACE_ROOT || root === CHAT_FILES_TREE_REDUCTION_ROOT) && parts.length === 3) {
        if (parts[1] === 'projects') return chatFilesProjectDisplay(name);
        if (parts[1] === 'conversations') return chatFilesConversationDisplay(name);
    }
    if (root === CHAT_FILES_TREE_ARTIFACT_ROOT && parts.length === 2) {
        return chatFilesConversationDisplay(name);
    }
    if (root === CHAT_FILES_TREE_UPLOAD_ROOT && parts.length === 3) {
        return chatFilesConversationDisplay(name);
    }
    const text = chatFilesTreeDisplayName(name);
    return { text: text, title: String(name || '') };
}

function chatFilesUploadRelativeDirFromBrowsePath(path) {
    const parts = Array.isArray(path) ? path.slice() : [];
    if (parts[0] === CHAT_FILES_TREE_UPLOAD_ROOT) {
        parts.shift();
    }
    return parts.join('/');
}

function chatFilesTreeNodeMaxMod(node) {
    let m = 0;
    let i;
    for (i = 0; i < node.files.length; i++) {
        const f = chatFilesDisplayed[node.files[i].idx];
        m = Math.max(m, (f && f.modifiedUnix) || 0);
    }
    const keys = Object.keys(node.dirs);
    for (i = 0; i < keys.length; i++) {
        m = Math.max(m, chatFilesTreeNodeMaxMod(node.dirs[keys[i]]));
    }
    return m;
}

function chatFilesTreeSortDirKeys(node, keys) {
    return keys.slice().sort(function (a, b) {
        const ma = chatFilesTreeNodeMaxMod(node.dirs[a]);
        const mb = chatFilesTreeNodeMaxMod(node.dirs[b]);
        if (mb !== ma) return mb - ma;
        return String(a).localeCompare(String(b));
    });
}

function chatFilesBuildGroups(files, mode) {
    const map = new Map();
    files.forEach(function (f, idx) {
        let key;
        if (mode === 'date') {
            key = f.date || '—';
        } else if (mode === 'project') {
            key = f.projectId || '—';
        } else {
            key = f.conversationId || '—';
        }
        if (!map.has(key)) {
            map.set(key, { key: key, items: [] });
        }
        map.get(key).items.push({ idx: idx, f: f });
    });
    const groups = Array.from(map.values());
    groups.forEach(function (g) {
        g.items.sort(function (a, b) {
            return (b.f.modifiedUnix || 0) - (a.f.modifiedUnix || 0);
        });
    });
    if (mode === 'date') {
        groups.sort(function (a, b) {
            return chatFilesCompareDateKeysDesc(a.key, b.key);
        });
    } else {
        groups.sort(function (a, b) {
            const ma = Math.max.apply(
                null,
                a.items.map(function (x) {
                    return x.f.modifiedUnix || 0;
                })
            );
            const mb = Math.max.apply(
                null,
                b.items.map(function (x) {
                    return x.f.modifiedUnix || 0;
                })
            );
            return mb - ma;
        });
    }
    return groups;
}

/** Group heading: long IDs are shortened for display; the full value goes in title */
function chatFilesGroupHeadingID(key, emptyLabel) {
    return chatFilesIDDisplay(key, null, emptyLabel);
}

function chatFilesGroupHeadingConversation(key) {
    return chatFilesConversationDisplay(key);
}

function chatFilesGroupHeadingProject(key) {
    return chatFilesProjectDisplay(key);
}

function renderChatFilesTable() {
    const wrap = document.getElementById('chat-files-list-wrap');
    if (!wrap) return;

    chatFilesDisplayed = chatFilesNameFilter(chatFilesCache);
    const groupMode = chatFilesGetGroupByMode();
    const emptyMsg = (typeof window.t === 'function') ? window.t('chatFilesPage.empty') : 'No files yet';
    // In "by folder" mode, show the chat_uploads path bar and "New folder" even when there are no files yet; otherwise directories cannot be created first
    if (!chatFilesDisplayed.length && groupMode !== 'folder') {
        wrap.classList.remove('chat-files-table-wrap--grouped');
        wrap.classList.remove('chat-files-table-wrap--tree');
        wrap.innerHTML = '<div class="empty-state" data-i18n="chatFilesPage.empty">' + escapeHtml(emptyMsg) + '</div>';
        if (typeof window.applyTranslations === 'function') {
            window.applyTranslations(wrap);
        }
        renderChatFilesPagination();
        return;
    }

    const thDate = (typeof window.t === 'function') ? window.t('chatFilesPage.colDate') : 'Date';
    const thConv = (typeof window.t === 'function') ? window.t('chatFilesPage.colConversation') : 'Conversation';
    const thSubPath = (typeof window.t === 'function') ? window.t('chatFilesPage.colSubPath') : 'Sub-path';
    const thName = (typeof window.t === 'function') ? window.t('chatFilesPage.colName') : 'File name';
    const thSize = (typeof window.t === 'function') ? window.t('chatFilesPage.colSize') : 'Size';
    const thModified = (typeof window.t === 'function') ? window.t('chatFilesPage.colModified') : 'Modified';
    const thActions = (typeof window.t === 'function') ? window.t('chatFilesPage.colActions') : 'Actions';

    const svgView = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    const svgCopy = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
    const svgDownload = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
    const svgMore = '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>';
    const svgFolder = '<svg class="chat-files-tree-icon" width="16" height="16" viewBox="0 0 24 24" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
    const svgFile = '<svg class="chat-files-tree-file-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';

    const tCopyTitle = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.copyPathTitle') : 'Copy the absolute path on the server; paste it into a chat to reference it');
    const tDlTitle = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.download') : 'Download');
    const tMoreTitle = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.moreActions') : 'More actions');

    function rowHtml(f, idx) {
        const rp = f.relativePath || '';
        const pathForTitle = (f.absolutePath && String(f.absolutePath).trim()) ? String(f.absolutePath).trim() : rp;
        const nameEsc = escapeHtml(f.name || '');
        const isInternal = chatFilesIsInternalSource(f);
        const sourceBadge = isInternal ? '<span class="chat-files-source-badge">' + escapeHtml(chatFilesSourceLabel(f.source)) + '</span>' : '';
        const conv = f.conversationId || '';
        const convDisplay = chatFilesConversationDisplay(conv);
        const convEsc = escapeHtml(convDisplay.text || conv);
        const convTitleEsc = escapeHtml(convDisplay.title || conv);
        const dt = f.modifiedUnix ? new Date(f.modifiedUnix * 1000).toLocaleString() : '—';
        const canOpenChat = conv && conv !== '_manual' && conv !== '_new';

        const bin = chatFileIsBinaryByName(f.name);
        const editHint = escapeHtml(chatFilesEditBlockedHint());
        const editUnavailable = (typeof window.t === 'function') ? escapeHtml(window.t('chatFilesPage.editUnavailable')) : 'Not editable';
        const tEdit = (typeof window.t === 'function') ? escapeHtml(window.t('chatFilesPage.edit')) : 'Edit';
        const tOpenChat = (typeof window.t === 'function') ? escapeHtml(window.t('chatFilesPage.openChat')) : 'Open chat';
        const tRename = (typeof window.t === 'function') ? escapeHtml(window.t('chatFilesPage.rename')) : 'Rename';
        const tDelete = (typeof window.t === 'function') ? escapeHtml(window.t('common.delete')) : 'Delete';

        const menuParts = [];
        if (canOpenChat) {
            menuParts.push(`<button type="button" class="chat-files-dropdown-item" onclick="chatFilesCloseAllMenus(); openChatFilesConversationIdx(${idx});">${tOpenChat}</button>`);
        }
        if (isInternal) {
            menuParts.push(`<div class="chat-files-dropdown-item is-disabled">${escapeHtml(chatFilesSourceLabel(f.source))}</div>`);
        } else if (!bin) {
            menuParts.push(`<button type="button" class="chat-files-dropdown-item" onclick="chatFilesCloseAllMenus(); openChatFilesEditIdx(${idx});">${tEdit}</button>`);
        } else {
            menuParts.push(`<div class="chat-files-dropdown-item is-disabled" title="${editHint}">${editUnavailable}</div>`);
        }
        if (!isInternal) {
            menuParts.push(`<button type="button" class="chat-files-dropdown-item" onclick="chatFilesCloseAllMenus(); openChatFilesRenameIdx(${idx});">${tRename}</button>`);
            menuParts.push(`<button type="button" class="chat-files-dropdown-item is-danger" onclick="chatFilesCloseAllMenus(); deleteChatFileIdx(${idx});">${tDelete}</button>`);
        }
        const menuHtml = menuParts.join('');

        const subRaw = (f.subPath && String(f.subPath).trim()) ? String(f.subPath).trim() : '';
        const rootLabel = (typeof window.t === 'function') ? window.t('chatFilesPage.folderRoot') : '(root)';
        let subCellInner;
        if (subRaw) {
            const segs = subRaw.split('/').filter(function (s) {
                return s.length > 0;
            });
            subCellInner = '<span class="chat-files-path-breadcrumb">' + segs.map(function (seg, i) {
                return (i > 0 ? '<span class="chat-files-path-sep">›</span>' : '') +
                    '<span class="chat-files-path-crumb">' + escapeHtml(seg) + '</span>';
            }).join('') + '</span>';
        } else {
            subCellInner = '<span class="chat-files-path-root">' + escapeHtml(rootLabel) + '</span>';
        }

        return `<tr>
            <td>${escapeHtml(f.date || '—')}</td>
            <td class="chat-files-cell-conv"><code title="${convTitleEsc}">${convEsc}</code></td>
            <td class="chat-files-cell-subpath" title="${escapeHtml(subRaw || '')}">${subCellInner}</td>
            <td class="chat-files-cell-name" title="${chatFilesEscapeAttr(pathForTitle)}">${nameEsc}${sourceBadge}</td>
            <td>${formatChatFileBytes(f.size || 0)}</td>
            <td>${escapeHtml(dt)}</td>
            <td class="chat-files-actions">
                <div class="chat-files-action-bar">
                    <button type="button" class="btn-icon" title="View" onclick="openFileViewerIdx(${idx})">${svgView}</button>
                    <button type="button" class="btn-icon" title="${tCopyTitle}" onclick="copyChatFilePathIdx(${idx})">${svgCopy}</button>
                    <button type="button" class="btn-icon" title="${tDlTitle}" onclick="downloadChatFileIdx(${idx})">${svgDownload}</button>
                    <div class="chat-files-dropdown-wrap">
                        <button type="button" class="btn-icon" title="${tMoreTitle}" aria-haspopup="true" onclick="chatFilesToggleMoreMenu(event, ${idx})">${svgMore}</button>
                        <div class="chat-files-dropdown" id="chat-files-menu-${idx}" hidden>${menuHtml}</div>
                    </div>
                </div>
            </td>
        </tr>`;
    }

    const theadHtml = `<thead><tr>
        <th>${escapeHtml(thDate)}</th>
        <th>${escapeHtml(thConv)}</th>
        <th>${escapeHtml(thSubPath)}</th>
        <th>${escapeHtml(thName)}</th>
        <th>${escapeHtml(thSize)}</th>
        <th>${escapeHtml(thModified)}</th>
        <th>${escapeHtml(thActions)}</th>
    </tr></thead>`;

    const theadCompact = `<thead><tr>
        <th>${escapeHtml(thName)}</th>
        <th>${escapeHtml(thSize)}</th>
        <th>${escapeHtml(thModified)}</th>
        <th>${escapeHtml(thActions)}</th>
    </tr></thead>`;

    let innerHtml;

    if (groupMode === 'folder') {
        const root = chatFilesTreeRootMerged();
        chatFilesNormalizeBrowsePathForTree(root);
        const node = chatFilesResolveTreeNode(root, chatFilesBrowsePath);
        const current = node || root;
        const dirKeys = chatFilesTreeSortDirKeys(current, Object.keys(current.dirs));

        current.files.sort(function (a, b) {
            return (chatFilesDisplayed[b.idx].modifiedUnix || 0) - (chatFilesDisplayed[a.idx].modifiedUnix || 0);
        });

        const tRoot = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.browseRoot') : 'Files');
        const tUp = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.browseUp') : 'Up');
        const tMkdir = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.newFolderButton') : 'New folder');
        const tEmpty = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.folderEmpty') : 'This folder is empty');
        const tCopyFolder = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.copyFolderPathTitle') : 'Copy folder path');
        const tEnter = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.enterFolderTitle') : 'Open');

        let breadcrumbHtml = '<nav class="chat-files-breadcrumb" aria-label="breadcrumb">';
        breadcrumbHtml += '<button type="button" class="chat-files-breadcrumb-link" onclick="chatFilesNavigateBreadcrumb(-1)">' + tRoot + '</button>';
        let bi;
        for (bi = 0; bi < chatFilesBrowsePath.length; bi++) {
            const seg = chatFilesBrowsePath[bi];
            const isLast = bi === chatFilesBrowsePath.length - 1;
            const display = chatFilesTreePathDisplayName(chatFilesBrowsePath.slice(0, bi + 1));
            const displayText = escapeHtml(display.text);
            const displayTitle = display.title ? ' title="' + escapeHtml(display.title) + '"' : '';
            breadcrumbHtml += '<span class="chat-files-breadcrumb-sep">/</span>';
            if (isLast) {
                breadcrumbHtml += '<span class="chat-files-breadcrumb-current"' + displayTitle + '>' + displayText + '</span>';
            } else {
                breadcrumbHtml += '<button type="button" class="chat-files-breadcrumb-link" onclick="chatFilesNavigateBreadcrumb(' + bi + ')"' + displayTitle + '>' + displayText + '</button>';
            }
        }
        breadcrumbHtml += '</nav>';

        const canMutateCurrentPath = chatFilesBrowseCanMutateCurrentPath();
        const upDisabled = chatFilesBrowsePath.length === 0 ? ' disabled' : '';
        const mkdirButton = canMutateCurrentPath
            ? '<button type="button" class="btn-secondary chat-files-mkdir-btn" onclick="openChatFilesMkdirModal()">' + tMkdir + '</button>'
            : '';
        const toolbarHtml = '<div class="chat-files-browse-toolbar">' + breadcrumbHtml +
            mkdirButton +
            '<button type="button" class="btn-secondary chat-files-browse-up"' + upDisabled + ' onclick="chatFilesNavigateUp()">' + tUp + '</button></div>';

        const svgTrash = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
        const svgUploadToFolder = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>';
        const tDeleteFolder = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.deleteFolderTitle') : 'Delete folder');
        const tUploadToFolder = escapeHtml((typeof window.t === 'function') ? window.t('chatFilesPage.uploadToFolderTitle') : 'Upload to this folder');

        function rowHtmlBrowseFolder(name) {
            const nameAttr = encodeURIComponent(String(name));
            const folderPath = chatFilesBrowsePath.concat([name]);
            const folderDisplay = chatFilesTreePathDisplayName(folderPath);
            const folderTitle = folderDisplay.title || tEnter;
            const relToFolder = folderPath.join('/');
            const uploadDirAttr = encodeURIComponent(relToFolder);
            const canUploadFolder = chatFilesBrowseCanUploadToPath(folderPath);
            const canDeleteFolder = chatFilesBrowseCanDeleteFolderPath(folderPath);
            const uploadBtn = canUploadFolder
                ? `<button type="button" class="btn-icon" title="${tUploadToFolder}" data-upload-dir="${uploadDirAttr}" onclick="chatFilesUploadToFolderClick(event, this)">${svgUploadToFolder}</button>`
                : '';
            const deleteBtn = canDeleteFolder
                ? `<button type="button" class="btn-icon btn-danger" title="${tDeleteFolder}" data-chat-folder-name="${nameAttr}" onclick="chatFilesDeleteFolderFromBtn(event, this)">${svgTrash}</button>`
                : '';
            return `<tr class="chat-files-tr-folder chat-files-tr-folder--nav" role="button" tabindex="0" data-chat-folder-name="${nameAttr}" onclick="chatFilesOnFolderRowClick(event)" onkeydown="chatFilesOnFolderRowKeydown(event)">
                <td class="chat-files-tree-name-cell chat-files-tree-name-cell--folder" title="${chatFilesEscapeAttr(folderTitle)}">
                    <span class="chat-files-tree-name-inner">${svgFolder}<span class="chat-files-tree-name-text">${escapeHtml(folderDisplay.text)}</span></span>
                </td>
                <td class="chat-files-tree-muted">—</td>
                <td class="chat-files-tree-muted">—</td>
                <td class="chat-files-actions" data-chat-files-stop="true" onclick="event.stopPropagation()">
                    <div class="chat-files-action-bar">
                        ${uploadBtn}
                        <button type="button" class="btn-icon" title="${tCopyFolder}" data-chat-folder-name="${nameAttr}" onclick="chatFilesCopyFolderPathFromBtn(event, this)">${svgCopy}</button>
                        ${deleteBtn}
                    </div>
                </td>
            </tr>`;
        }

        function rowHtmlTreeFile(f, idx) {
            const pathForTitle = (f.absolutePath && String(f.absolutePath).trim()) ? String(f.absolutePath).trim() : (f.relativePath || '');
            const nameEsc = escapeHtml(f.name || '');
            const isInternal = chatFilesIsInternalSource(f);
            const sourceBadge = isInternal ? '<span class="chat-files-source-badge">' + escapeHtml(chatFilesSourceLabel(f.source)) + '</span>' : '';
            const dt = f.modifiedUnix ? new Date(f.modifiedUnix * 1000).toLocaleString() : '—';
            const conv = f.conversationId || '';
            const canOpenChat = conv && conv !== '_manual' && conv !== '_new';

            const bin = chatFileIsBinaryByName(f.name);
            const editHint = escapeHtml(chatFilesEditBlockedHint());
            const editUnavailable = (typeof window.t === 'function') ? escapeHtml(window.t('chatFilesPage.editUnavailable')) : 'Not editable';
            const tEdit = (typeof window.t === 'function') ? escapeHtml(window.t('chatFilesPage.edit')) : 'Edit';
            const tOpenChat = (typeof window.t === 'function') ? escapeHtml(window.t('chatFilesPage.openChat')) : 'Open chat';
            const tRename = (typeof window.t === 'function') ? escapeHtml(window.t('chatFilesPage.rename')) : 'Rename';
            const tDelete = (typeof window.t === 'function') ? escapeHtml(window.t('common.delete')) : 'Delete';

            const menuParts = [];
            if (canOpenChat) {
                menuParts.push(`<button type="button" class="chat-files-dropdown-item" onclick="chatFilesCloseAllMenus(); openChatFilesConversationIdx(${idx});">${tOpenChat}</button>`);
            }
            if (isInternal) {
                menuParts.push(`<div class="chat-files-dropdown-item is-disabled">${escapeHtml(chatFilesSourceLabel(f.source))}</div>`);
            } else if (!bin) {
                menuParts.push(`<button type="button" class="chat-files-dropdown-item" onclick="chatFilesCloseAllMenus(); openChatFilesEditIdx(${idx});">${tEdit}</button>`);
            } else {
                menuParts.push(`<div class="chat-files-dropdown-item is-disabled" title="${editHint}">${editUnavailable}</div>`);
            }
            if (!isInternal) {
                menuParts.push(`<button type="button" class="chat-files-dropdown-item" onclick="chatFilesCloseAllMenus(); openChatFilesRenameIdx(${idx});">${tRename}</button>`);
                menuParts.push(`<button type="button" class="chat-files-dropdown-item is-danger" onclick="chatFilesCloseAllMenus(); deleteChatFileIdx(${idx});">${tDelete}</button>`);
            }
            const menuHtml = menuParts.join('');

            return `<tr class="chat-files-tr-file">
                <td class="chat-files-tree-name-cell" title="${chatFilesEscapeAttr(pathForTitle)}">
                    <span class="chat-files-tree-name-inner">${svgFile}<span class="chat-files-tree-name-text">${nameEsc}${sourceBadge}</span></span>
                </td>
                <td>${formatChatFileBytes(f.size || 0)}</td>
                <td>${escapeHtml(dt)}</td>
                <td class="chat-files-actions">
                    <div class="chat-files-action-bar">
                        <button type="button" class="btn-icon" title="View" onclick="openFileViewerIdx(${idx})">${svgView}</button>
                        <button type="button" class="btn-icon" title="${tCopyTitle}" onclick="copyChatFilePathIdx(${idx})">${svgCopy}</button>
                        <button type="button" class="btn-icon" title="${tDlTitle}" onclick="downloadChatFileIdx(${idx})">${svgDownload}</button>
                        <div class="chat-files-dropdown-wrap">
                            <button type="button" class="btn-icon" title="${tMoreTitle}" aria-haspopup="true" onclick="chatFilesToggleMoreMenu(event, ${idx})">${svgMore}</button>
                            <div class="chat-files-dropdown" id="chat-files-menu-${idx}" hidden>${menuHtml}</div>
                        </div>
                    </div>
                </td>
            </tr>`;
        }

        const folderRows = dirKeys.map(rowHtmlBrowseFolder).join('');
        const fileRows = current.files.map(function (item) {
            return rowHtmlTreeFile(chatFilesDisplayed[item.idx], item.idx);
        }).join('');

        let bodyRows = folderRows + fileRows;
        if (!bodyRows) {
            bodyRows = '<tr class="chat-files-tr-empty"><td colspan="4" class="chat-files-folder-empty">' + tEmpty + '</td></tr>';
        }

        innerHtml = '<div class="chat-files-browse-wrap">' + toolbarHtml + '<table class="chat-files-table chat-files-table--tree-flat">' + theadCompact + '<tbody>' + bodyRows + '</tbody></table></div>';
    } else if (groupMode === 'none') {
        const rows = chatFilesDisplayed.map(function (f, idx) {
            return rowHtml(f, idx);
        }).join('');
        innerHtml = `<table class="chat-files-table">${theadHtml}<tbody>${rows}</tbody></table>`;
    } else {
        const groups = chatFilesBuildGroups(chatFilesDisplayed, groupMode);
        const blocks = groups.map(function (g) {
            const rows = g.items.map(function (item) {
                return rowHtml(item.f, item.idx);
            }).join('');
            let summaryMain;
            let summaryTitleAttr = '';
            if (groupMode === 'date') {
                summaryMain = escapeHtml(String(g.key));
            } else if (groupMode === 'project') {
                const h = chatFilesGroupHeadingProject(g.key);
                summaryMain = escapeHtml(h.text);
                summaryTitleAttr = h.title ? ' title="' + escapeHtml(h.title) + '"' : '';
            } else {
                const h = chatFilesGroupHeadingConversation(g.key);
                summaryMain = escapeHtml(h.text);
                summaryTitleAttr = h.title ? ' title="' + escapeHtml(h.title) + '"' : '';
            }
            const n = g.items.length;
            const countLabel = (typeof window.t === 'function')
                ? escapeHtml(window.t('chatFilesPage.groupCount', { count: n }))
                : escapeHtml(String(n));
            return `<details class="chat-files-group" open>
                <summary class="chat-files-group-summary"${summaryTitleAttr}>
                    <span class="chat-files-group-title">${summaryMain}</span>
                    <span class="chat-files-group-count">${countLabel}</span>
                </summary>
                <div class="chat-files-group-body">
                    <table class="chat-files-table">${theadHtml}<tbody>${rows}</tbody></table>
                </div>
            </details>`;
        }).join('');
        innerHtml = `<div class="chat-files-grouped">${blocks}</div>`;
    }

    ensureChatFilesDocClickClose();

    wrap.innerHTML = innerHtml;
    wrap.classList.toggle('chat-files-table-wrap--grouped', groupMode !== 'none' && groupMode !== 'folder');
    wrap.classList.toggle('chat-files-table-wrap--tree', groupMode === 'folder');
    renderChatFilesPagination();
}

window.chatFilesGroupByChange = chatFilesGroupByChange;
window.changeChatFilesPage = changeChatFilesPage;
window.changeChatFilesPageSize = changeChatFilesPageSize;
window.chatFilesResetToFirstPageAndLoad = chatFilesResetToFirstPageAndLoad;

function chatFilesNavigateInto(name) {
    const root = chatFilesTreeRootMerged();
    chatFilesNormalizeBrowsePathForTree(root);
    const next = chatFilesBrowsePath.concat([name]);
    if (!chatFilesResolveTreeNode(root, next)) return;
    chatFilesSetBrowsePath(next);
    renderChatFilesTable();
}

function chatFilesNavigateBreadcrumb(level) {
    const root = chatFilesTreeRootMerged();
    chatFilesNormalizeBrowsePathForTree(root);
    if (level < 0) {
        chatFilesSetBrowsePath([]);
    } else {
        chatFilesSetBrowsePath(chatFilesBrowsePath.slice(0, level + 1));
    }
    renderChatFilesTable();
}

function chatFilesNavigateUp() {
    if (chatFilesBrowsePath.length === 0) return;
    chatFilesSetBrowsePath(chatFilesBrowsePath.slice(0, -1));
    renderChatFilesTable();
}

function chatFilesFolderNameFromRow(el) {
    if (!el || !el.getAttribute) return '';
    try {
        return decodeURIComponent(String(el.getAttribute('data-chat-folder-name') || ''));
    } catch (e) {
        return '';
    }
}

function chatFilesOnFolderRowClick(ev) {
    if (ev.target.closest && ev.target.closest('[data-chat-files-stop]')) return;
    const name = chatFilesFolderNameFromRow(ev.currentTarget);
    if (!name) return;
    chatFilesNavigateInto(name);
}

function chatFilesOnFolderRowKeydown(ev) {
    if (ev.key !== 'Enter' && ev.key !== ' ') return;
    ev.preventDefault();
    const name = chatFilesFolderNameFromRow(ev.currentTarget);
    if (!name) return;
    chatFilesNavigateInto(name);
}

function chatFilesCopyFolderPathFromBtn(ev, btn) {
    if (ev) ev.stopPropagation();
    const name = chatFilesFolderNameFromRow(btn);
    if (!name) return;
    copyChatFolderPathFromBrowse(name);
}

async function deleteChatFolderFromBrowse(folderName) {
    const segs = chatFilesBrowsePath.concat([folderName]);
    if (!chatFilesBrowseCanDeleteFolderPath(segs)) return;
    const rel = chatFilesUploadRelativeDirFromBrowsePath(segs);
    const q = (typeof window.t === 'function') ? window.t('chatFilesPage.confirmDeleteFolder') : 'Delete this folder and all files in it?';
    if (!confirm(q)) return;
    try {
        const res = await apiFetch('/api/chat-uploads', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: rel })
        });
        if (!res.ok) {
            const raw = await res.text();
            if (res.status === 404) {
                let errMsg = raw;
                try {
                    const j = JSON.parse(raw);
                    if (j && j.error) errMsg = j.error;
                } catch (eParse) {
                    /* keep raw */
                }
                if (/not\s*found/i.test(String(errMsg))) {
                    loadChatFilesPage();
                    const cleared = (typeof window.t === 'function')
                        ? window.t('chatFilesPage.folderRemovedStale')
                        : 'This directory does not exist on the server; the list has been refreshed.';
                    if (typeof chatFilesShowToast === 'function') {
                        chatFilesShowToast(cleared);
                    } else {
                        alert(cleared);
                    }
                    return;
                }
            }
            throw new Error(raw || String(res.status));
        }
        loadChatFilesPage();
    } catch (e) {
        alert((e && e.message) ? e.message : String(e));
    }
}

function chatFilesDeleteFolderFromBtn(ev, btn) {
    if (ev) ev.stopPropagation();
    const name = chatFilesFolderNameFromRow(btn);
    if (!name) return;
    deleteChatFolderFromBrowse(name);
}

async function copyChatFolderPathFromBrowse(folderName) {
    const segs = chatFilesBrowsePath.concat([folderName]);
    const relativePath = chatFilesRelativePathFromTreeSegments(segs);
    let text = '';
    if (relativePath) {
        try {
            const res = await apiFetch('/api/chat-uploads/path?kind=directory&path=' + encodeURIComponent(relativePath));
            if (!res.ok) {
                const raw = await res.text();
                throw new Error(raw || String(res.status));
            }
            const data = await res.json();
            text = String((data && data.absolutePath) || '').trim();
        } catch (e) {
            alert((e && e.message) ? e.message : String(e));
            return;
        }
    }
    if (!text) {
        text = chatFilesClipboardFolderPath(segs);
    }
    const ok = await chatFilesCopyText(text);
    if (ok) {
        const msg = (typeof window.t === 'function') ? window.t('chatFilesPage.folderPathCopied') : 'Folder path copied';
        chatFilesShowToast(msg);
    } else {
        const fail = (typeof window.t === 'function') ? window.t('common.copyFailed') : 'Copy failed';
        alert(fail);
    }
}

function chatFilesRelativePathFromTreeSegments(segs) {
    const parts = Array.isArray(segs) ? segs.slice() : [];
    if (!parts.length) return '';
    const root = parts.shift();
    if (root === CHAT_FILES_TREE_UPLOAD_ROOT) {
        return parts.length ? parts.join('/') : '.';
    }
    if (root === CHAT_FILES_TREE_REDUCTION_ROOT) {
        return '__reduction__/' + parts.join('/');
    }
    if (root === CHAT_FILES_TREE_WORKSPACE_ROOT) {
        return '__workspace__/' + parts.join('/');
    }
    if (root === CHAT_FILES_TREE_ARTIFACT_ROOT) {
        return '__conversation_artifact__/' + parts.join('/');
    }
    return [root].concat(parts).join('/');
}

function chatFilesClipboardFolderPath(segs) {
    const parts = Array.isArray(segs) ? segs.slice() : [];
    if (!parts.length) return '';
    const root = parts.shift();
    if (root === CHAT_FILES_TREE_UPLOAD_ROOT) {
        return ['chat_uploads'].concat(parts).join('/');
    }
    if (root === CHAT_FILES_TREE_REDUCTION_ROOT) {
        return ['tool_outputs'].concat(parts).join('/');
    }
    if (root === CHAT_FILES_TREE_ARTIFACT_ROOT) {
        return ['conversation_artifacts'].concat(parts).join('/');
    }
    return [root].concat(parts).map(chatFilesTreeDisplayName).join('/');
}

window.chatFilesNavigateInto = chatFilesNavigateInto;
window.chatFilesNavigateBreadcrumb = chatFilesNavigateBreadcrumb;
window.chatFilesNavigateUp = chatFilesNavigateUp;
window.chatFilesOnFolderRowClick = chatFilesOnFolderRowClick;
window.copyChatFolderPathFromBrowse = copyChatFolderPathFromBrowse;
window.chatFilesOnFolderRowKeydown = chatFilesOnFolderRowKeydown;
window.chatFilesCopyFolderPathFromBtn = chatFilesCopyFolderPathFromBtn;
window.chatFilesDeleteFolderFromBtn = chatFilesDeleteFolderFromBtn;
window.chatFilesOpenUploadPicker = chatFilesOpenUploadPicker;
window.chatFilesUploadToFolderClick = chatFilesUploadToFolderClick;
window.exportChatFiles = exportChatFiles;
window.openChatFilesMkdirModal = openChatFilesMkdirModal;
window.closeChatFilesMkdirModal = closeChatFilesMkdirModal;
window.submitChatFilesMkdir = submitChatFilesMkdir;

function openChatFilesConversationIdx(idx) {
    const f = chatFilesDisplayed[idx];
    if (!f || !f.conversationId) return;
    openChatFilesConversation(f.conversationId);
}

function downloadChatFileIdx(idx) {
    const f = chatFilesDisplayed[idx];
    if (!f) return;
    downloadChatFile(f.relativePath, f.name);
}

function openChatFilesEditIdx(idx) {
    const f = chatFilesDisplayed[idx];
    if (!f) return;
    if (chatFileIsBinaryByName(f.name)) {
        alert(chatFilesEditBlockedHint());
        return;
    }
    openChatFilesEdit(f.relativePath);
}

function openChatFilesRenameIdx(idx) {
    const f = chatFilesDisplayed[idx];
    if (!f) return;
    openChatFilesRename(f.relativePath, f.name);
}

function deleteChatFileIdx(idx) {
    const f = chatFilesDisplayed[idx];
    if (!f) return;
    deleteChatFile(f.relativePath);
}

function openChatFilesConversation(conversationId) {
    if (!conversationId) return;
    setRoutePath('chat?conversation=' + encodeURIComponent(conversationId));
    if (typeof switchPage === 'function') {
        switchPage('chat');
    }
    setTimeout(() => {
        if (typeof loadConversation === 'function') {
            loadConversation(conversationId);
        }
    }, 400);
}

async function downloadChatFile(relativePath, filename) {
    try {
        const url = '/api/chat-uploads/download?path=' + encodeURIComponent(relativePath);
        const res = await apiFetch(url);
        if (!res.ok) {
            throw new Error(await res.text());
        }
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename || 'download';
        a.click();
        URL.revokeObjectURL(a.href);
    } catch (e) {
        alert((e && e.message) ? e.message : String(e));
    }
}

async function deleteChatFile(relativePath) {
    const q = (typeof window.t === 'function') ? window.t('chatFilesPage.confirmDelete') : 'Delete this file?';
    if (!confirm(q)) return;
    try {
        const res = await apiFetch('/api/chat-uploads', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: relativePath })
        });
        if (!res.ok) {
            throw new Error(await res.text());
        }
        loadChatFilesPage();
    } catch (e) {
        alert((e && e.message) ? e.message : String(e));
    }
}

async function openChatFilesEdit(relativePath) {
    chatFilesEditRelativePath = relativePath;
    const pathEl = document.getElementById('chat-files-edit-path');
    const ta = document.getElementById('chat-files-edit-textarea');
    const modal = document.getElementById('chat-files-edit-modal');
    if (pathEl) pathEl.textContent = relativePath;
    if (ta) ta.value = '';
    openAppModal('chat-files-edit-modal', { focus: false });

    try {
        const res = await apiFetch('/api/chat-uploads/content?path=' + encodeURIComponent(relativePath));
        if (!res.ok) {
            let errText = '';
            try {
                const err = await res.json();
                errText = err.error || JSON.stringify(err);
            } catch (e2) {
                errText = await res.text();
            }
            throw new Error(errText || res.status);
        }
        const data = await res.json();
        const content = data.content != null ? String(data.content) : '';
        deferModalContent(() => {
            if (ta) ta.value = content;
            ta?.focus();
        });
    } catch (e) {
        closeAppModal('chat-files-edit-modal');
        alert(chatFilesAlertMessage(e && e.message));
    }
}

function closeChatFilesEditModal() {
    closeAppModal('chat-files-edit-modal');
    chatFilesEditRelativePath = '';
}

async function saveChatFilesEdit() {
    const ta = document.getElementById('chat-files-edit-textarea');
    if (!ta || !chatFilesEditRelativePath) return;
    try {
        const res = await apiFetch('/api/chat-uploads/content', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: chatFilesEditRelativePath, content: ta.value })
        });
        if (!res.ok) {
            throw new Error(await res.text());
        }
        closeChatFilesEditModal();
        loadChatFilesPage();
    } catch (e) {
        alert(chatFilesAlertMessage(e && e.message));
    }
}

function openChatFilesRename(relativePath, currentName) {
    chatFilesRenameRelativePath = relativePath;
    const input = document.getElementById('chat-files-rename-input');
    const hint = document.getElementById('chat-files-rename-path-hint');
    const modal = document.getElementById('chat-files-rename-modal');
    const pathText = relativePath ? ('chat_uploads/' + String(relativePath).replace(/\\/g, '/')) : 'chat_uploads';
    if (hint) hint.textContent = pathText;
    if (input) {
        input.value = currentName || '';
        input.select();
    }
    if (modal) openAppModal(modal);
    if (modal && typeof window.applyTranslations === 'function') {
        window.applyTranslations(modal);
    }
    setTimeout(() => { if (input) { input.focus(); input.select(); } }, 100);
}

function closeChatFilesRenameModal() {
    closeAppModal('chat-files-rename-modal');
    const hint = document.getElementById('chat-files-rename-path-hint');
    if (hint) hint.textContent = '';
    chatFilesRenameRelativePath = '';
}

async function submitChatFilesRename() {
    const input = document.getElementById('chat-files-rename-input');
    const newName = input ? input.value.trim() : '';
    if (!newName || !chatFilesRenameRelativePath) {
        closeChatFilesRenameModal();
        return;
    }
    try {
        const res = await apiFetch('/api/chat-uploads/rename', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: chatFilesRenameRelativePath, newName: newName })
        });
        if (!res.ok) {
            throw new Error(await res.text());
        }
        closeChatFilesRenameModal();
        loadChatFilesPage();
    } catch (e) {
        alert((e && e.message) ? e.message : String(e));
    }
}

function openChatFilesMkdirModal() {
    if (chatFilesGetGroupByMode() !== 'folder') return;
    if (!chatFilesBrowseCanMutateCurrentPath()) return;
    const hint = document.getElementById('chat-files-mkdir-parent-hint');
    const input = document.getElementById('chat-files-mkdir-input');
    const modal = document.getElementById('chat-files-mkdir-modal');
    const p = chatFilesBrowsePath.map(chatFilesTreeDisplayName).join('/');
    if (hint) hint.textContent = p || chatFilesTreeDisplayName(CHAT_FILES_TREE_UPLOAD_ROOT);
    if (input) input.value = '';
    if (modal) openAppModal(modal);
    if (modal && typeof window.applyTranslations === 'function') {
        window.applyTranslations(modal);
    }
    setTimeout(() => {
        if (input) input.focus();
    }, 100);
}

function closeChatFilesMkdirModal() {
    closeAppModal('chat-files-mkdir-modal');
    const input = document.getElementById('chat-files-mkdir-input');
    if (input) input.value = '';
}

async function submitChatFilesMkdir() {
    const input = document.getElementById('chat-files-mkdir-input');
    const name = input ? String(input.value).trim() : '';
    if (!name) {
        closeChatFilesMkdirModal();
        return;
    }
    if (name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
        const msg = (typeof window.t === 'function')
            ? window.t('chatFilesPage.mkdirInvalidName')
            : 'Invalid name';
        alert(msg);
        return;
    }
    const parent = chatFilesUploadRelativeDirFromBrowsePath(chatFilesBrowsePath);
    try {
        const res = await apiFetch('/api/chat-uploads/mkdir', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ parent: parent, name: name })
        });
        if (!res.ok) {
            let errText = '';
            try {
                const j = await res.json();
                errText = j.error || JSON.stringify(j);
            } catch (e2) {
                errText = await res.text();
            }
            if (res.status === 409) {
                const msg = (typeof window.t === 'function')
                    ? window.t('chatFilesPage.mkdirExists')
                    : errText;
                alert(msg);
                return;
            }
            throw new Error(errText || String(res.status));
        }
        closeChatFilesMkdirModal();
        loadChatFilesPage();
        const okMsg = (typeof window.t === 'function')
            ? window.t('chatFilesPage.mkdirOk')
            : 'Folder created';
        chatFilesShowToast(okMsg);
    } catch (e) {
        alert((e && e.message) ? e.message : String(e));
    }
}

function chatFilesSetUploadProgressUI(visible, percent, fileName) {
    const wrap = document.getElementById('chat-files-upload-progress');
    const fill = document.getElementById('chat-files-upload-progress-fill');
    const label = document.getElementById('chat-files-upload-progress-label');
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
    const name = fileName || '';
    label.textContent = (typeof window.t === 'function')
        ? window.t('chatFilesPage.uploadingFile', { name: name, percent: p })
        : ('Uploading ' + name + ' · ' + p + '%');
}

function chatFilesSetUploadBusy(busy) {
    chatFilesXHRUploadBusy = !!busy;
    ['chat-files-header-upload-btn', 'chat-files-refresh-btn'].forEach(function (id) {
        const el = document.getElementById(id);
        if (el) el.disabled = chatFilesXHRUploadBusy;
    });
}

function chatFilesOpenUploadPicker() {
    if (chatFilesXHRUploadBusy) return;
    if (chatFilesGetGroupByMode() === 'folder') {
        if (!chatFilesBrowseCanMutateCurrentPath()) return;
        chatFilesPendingUploadDir = chatFilesUploadRelativeDirFromBrowsePath(chatFilesBrowsePath);
    } else {
        chatFilesPendingUploadDir = '';
    }
    const inp = document.getElementById('chat-files-upload-input');
    if (inp) inp.click();
}

function chatFilesUploadToFolderClick(ev, btn) {
    if (ev) ev.stopPropagation();
    if (chatFilesXHRUploadBusy) return;
    const raw = btn.getAttribute('data-upload-dir');
    if (!raw) return;
    try {
        chatFilesPendingUploadDir = decodeURIComponent(raw);
        chatFilesPendingUploadDir = chatFilesUploadRelativeDirFromBrowsePath(chatFilesPendingUploadDir.split('/').filter(Boolean));
    } catch (e) {
        chatFilesPendingUploadDir = '';
        return;
    }
    const inp = document.getElementById('chat-files-upload-input');
    if (inp) inp.click();
}

function chatFilesResolveUploadTarget() {
    const pendingDir = chatFilesPendingUploadDir;
    chatFilesPendingUploadDir = '';
    if (pendingDir) {
        return { relativeDir: pendingDir };
    }
    if (chatFilesGetGroupByMode() === 'folder') {
        if (!chatFilesBrowseCanMutateCurrentPath()) return {};
        const relDir = chatFilesUploadRelativeDirFromBrowsePath(chatFilesBrowsePath);
        return relDir ? { relativeDir: relDir } : {};
    }
    const conv = document.getElementById('chat-files-filter-conv');
    if (conv && conv.value.trim()) {
        return { conversationId: conv.value.trim() };
    }
    return {};
}

async function chatFilesUploadFile(file, target) {
    if (!file || chatFilesXHRUploadBusy) return false;
    const form = new FormData();
    form.append('file', file);
    if (target && target.relativeDir) {
        form.append('relativeDir', target.relativeDir);
    } else if (target && target.conversationId) {
        form.append('conversationId', target.conversationId);
    }
    chatFilesSetUploadBusy(true);
    chatFilesSetUploadProgressUI(true, 0, file.name);
    try {
        const doXhr = typeof apiUploadWithProgress === 'function';
        const res = doXhr
            ? await apiUploadWithProgress('/api/chat-uploads', form, {
                onProgress: function (p) {
                    chatFilesSetUploadProgressUI(true, p.percent, file.name);
                }
            })
            : await apiFetch('/api/chat-uploads', { method: 'POST', body: form });
        if (!res.ok) {
            throw new Error(await res.text());
        }
        const data = await res.json().catch(() => ({}));
        chatFilesSetUploadProgressUI(true, 100, file.name);
        loadChatFilesPage();
        if (data && data.ok) {
            const msg = (typeof window.t === 'function')
                ? window.t('chatFilesPage.uploadOkHint')
                : 'Upload succeeded. Click "Copy path" in the list to paste it into a chat to reference it.';
            chatFilesShowToast(msg);
        }
        return true;
    } catch (e) {
        alert((e && e.message) ? e.message : String(e));
        return false;
    } finally {
        chatFilesSetUploadBusy(false);
        chatFilesSetUploadProgressUI(false);
    }
}

async function chatFilesUploadFiles(fileList) {
    if (!fileList || !fileList.length || chatFilesXHRUploadBusy) return;
    const files = Array.from(fileList).filter(function (f) {
        return f && (f.name || f.size > 0);
    });
    if (!files.length) return;
    const target = chatFilesResolveUploadTarget();
    for (let i = 0; i < files.length; i++) {
        const ok = await chatFilesUploadFile(files[i], target);
        if (!ok) break;
    }
}

async function onChatFilesUploadPick(ev) {
    const input = ev.target;
    const files = input && input.files;
    if (!files || !files.length) return;
    try {
        await chatFilesUploadFiles(files);
    } finally {
        input.value = '';
    }
}

let chatFilesDragDropBound = false;

function setupChatFilesDragDrop() {
    if (chatFilesDragDropBound) return;
    const wrap = document.getElementById('chat-files-list-wrap');
    if (!wrap) return;
    chatFilesDragDropBound = true;

    wrap.addEventListener('dragover', function (e) {
        e.preventDefault();
        e.stopPropagation();
        if (chatFilesXHRUploadBusy) return;
        this.classList.add('drag-over');
    });
    wrap.addEventListener('dragleave', function (e) {
        e.preventDefault();
        e.stopPropagation();
        if (!this.contains(e.relatedTarget)) {
            this.classList.remove('drag-over');
        }
    });
    wrap.addEventListener('drop', function (e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.remove('drag-over');
        if (chatFilesXHRUploadBusy) return;
        const files = e.dataTransfer && e.dataTransfer.files;
        if (files && files.length) {
            chatFilesUploadFiles(files).catch(function (err) {
                if (err) alert((err && err.message) ? err.message : String(err));
            });
        }
    });
}

// After a language switch, re-render the list: the table header and "More" menu are built by JS without data-i18n, so regenerate them with the current language's t()
document.addEventListener('languagechange', function () {
    if (typeof window.currentPage !== 'function') return;
    if (window.currentPage() !== 'chat-files') return;
    syncAllChatFilesFilterSelects();
    if (typeof renderChatFilesTable === 'function') {
        renderChatFilesTable();
    }
});

document.addEventListener('DOMContentLoaded', function () {
    initChatFilesFilterSelects();
});

// =========================================================================
//  FILE VIEWER — inline preview for text, JSON, markdown, images, etc.
// =========================================================================

let _fvRawContent = '';
let _fvCurrentPath = '';

const FV_IMAGE_EXTS = ['.png','.jpg','.jpeg','.gif','.svg','.webp','.bmp','.ico'];
const FV_MD_EXTS = ['.md','.markdown','.mdx'];
const FV_JSON_EXTS = ['.json','.geojson'];
const FV_CSV_EXTS = ['.csv','.tsv'];
const FV_HTML_EXTS = ['.html','.htm'];
const FV_BINARY_EXTS = ['.pdf','.zip','.gz','.tar','.7z','.rar','.exe','.dll','.so','.bin','.db','.sqlite','.sqlite3','.wasm','.mp3','.mp4','.wav','.ogg','.avi','.mov','.docx','.xlsx','.pptx'];

function fvExt(name) {
    var n = String(name || '').toLowerCase();
    var i = n.lastIndexOf('.');
    return i >= 0 ? n.slice(i) : '';
}

function fvIsImage(name) { return FV_IMAGE_EXTS.indexOf(fvExt(name)) >= 0; }
function fvIsMarkdown(name) { return FV_MD_EXTS.indexOf(fvExt(name)) >= 0; }
function fvIsJson(name) { return FV_JSON_EXTS.indexOf(fvExt(name)) >= 0; }
function fvIsJsonl(name) { return fvExt(name) === '.jsonl'; }
function fvIsCsv(name) { return FV_CSV_EXTS.indexOf(fvExt(name)) >= 0; }
function fvIsHtml(name) { return FV_HTML_EXTS.indexOf(fvExt(name)) >= 0; }
function fvIsBinary(name) { return FV_BINARY_EXTS.indexOf(fvExt(name)) >= 0 || chatFileIsBinaryByName(name); }

function fvFormatSize(bytes) {
    if (bytes == null) return '';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function fvEscHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fvRenderJson(obj, indent) {
    indent = indent || 0;
    var pad = '  '.repeat(indent);
    if (obj === null) return '<span class="fv-json-null">null</span>';
    if (typeof obj === 'boolean') return '<span class="fv-json-bool">' + obj + '</span>';
    if (typeof obj === 'number') return '<span class="fv-json-num">' + obj + '</span>';
    if (typeof obj === 'string') return '<span class="fv-json-str">"' + fvEscHtml(obj) + '"</span>';
    if (Array.isArray(obj)) {
        if (obj.length === 0) return '<span class="fv-json-bracket">[]</span>';
        var items = obj.map(function(v, i) {
            return pad + '  ' + fvRenderJson(v, indent + 1) + (i < obj.length - 1 ? ',' : '');
        });
        return '<span class="fv-json-bracket">[</span>\n' + items.join('\n') + '\n' + pad + '<span class="fv-json-bracket">]</span>';
    }
    if (typeof obj === 'object') {
        var keys = Object.keys(obj);
        if (keys.length === 0) return '<span class="fv-json-bracket">{}</span>';
        var rows = keys.map(function(k, i) {
            return pad + '  <span class="fv-json-key">"' + fvEscHtml(k) + '"</span>: ' + fvRenderJson(obj[k], indent + 1) + (i < keys.length - 1 ? ',' : '');
        });
        return '<span class="fv-json-bracket">{</span>\n' + rows.join('\n') + '\n' + pad + '<span class="fv-json-bracket">}</span>';
    }
    return fvEscHtml(String(obj));
}

function fvRenderMarkdown(text) {
    var html = fvEscHtml(text);
    html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, function(_, lang, code) {
        return '<pre><code>' + code + '</code></pre>';
    });
    html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>\n?)+/g, function(m) { return '<ul>' + m + '</ul>'; });
    html = html.replace(/\n{2,}/g, '</p><p>');
    html = '<p>' + html + '</p>';
    html = html.replace(/<p>\s*<(h[123]|ul|pre)/g, '<$1');
    html = html.replace(/<\/(h[123]|ul|pre)>\s*<\/p>/g, '</$1>');
    return html;
}

function fvRenderText(text, name) {
    var lines = text.split('\n');
    var numbered = lines.map(function(line, i) {
        return '<span class="line-num">' + (i + 1) + '</span>' + fvEscHtml(line);
    }).join('\n');
    return '<pre>' + numbered + '</pre>';
}

// --- CSV parser & renderer ---
function fvParseCsvRows(text, fileName) {
    var sep = fvExt(fileName) === '.tsv' ? '\t' : ',';
    var rows = [];
    var current = [];
    var field = '';
    var inQuote = false;
    for (var i = 0; i < text.length; i++) {
        var ch = text[i];
        if (inQuote) {
            if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
            else if (ch === '"') { inQuote = false; }
            else { field += ch; }
        } else {
            if (ch === '"') { inQuote = true; }
            else if (ch === sep) { current.push(field); field = ''; }
            else if (ch === '\n' || (ch === '\r' && text[i + 1] === '\n')) {
                current.push(field); field = '';
                if (current.length > 1 || current[0] !== '') rows.push(current);
                current = [];
                if (ch === '\r') i++;
            } else { field += ch; }
        }
    }
    if (field || current.length) { current.push(field); rows.push(current); }
    return rows;
}

function fvRenderCsv(text, fileName) {
    var rows = fvParseCsvRows(text, fileName);
    if (rows.length === 0) return '<div class="fv-binary"><div>Empty CSV</div></div>';
    var header = rows[0];
    var dataRows = rows.slice(1);
    var summary = fvCsvSummary(header, dataRows);
    var html = '<div class="fv-csv-wrap">';
    if (summary) html += '<div class="fv-csv-summary">' + summary + '</div>';
    html += '<div class="fv-csv-table-scroll"><table class="fv-csv-table"><thead><tr>';
    html += '<th class="fv-csv-rownum">#</th>';
    for (var c = 0; c < header.length; c++) {
        html += '<th>' + fvEscHtml(header[c]) + '</th>';
    }
    html += '</tr></thead><tbody>';
    var limit = Math.min(dataRows.length, 500);
    for (var r = 0; r < limit; r++) {
        html += '<tr><td class="fv-csv-rownum">' + (r + 1) + '</td>';
        for (var c = 0; c < header.length; c++) {
            var val = (dataRows[r] && dataRows[r][c]) || '';
            var cls = fvCsvCellClass(val, header[c]);
            html += '<td' + (cls ? ' class="' + cls + '"' : '') + '>' + fvEscHtml(val) + '</td>';
        }
        html += '</tr>';
    }
    html += '</tbody></table></div>';
    if (dataRows.length > 500) html += '<div class="fv-csv-truncated">Showing 500 of ' + dataRows.length + ' rows</div>';
    html += '</div>';
    return html;
}

function fvCsvCellClass(val, header) {
    var h = (header || '').toLowerCase();
    var v = (val || '').toLowerCase().trim();
    if (h.indexOf('severity') >= 0 || h.indexOf('risk') >= 0 || h.indexOf('level') >= 0) {
        if (v === 'critical' || v === 'crit') return 'fv-csv-sev-critical';
        if (v === 'high') return 'fv-csv-sev-high';
        if (v === 'medium' || v === 'med') return 'fv-csv-sev-medium';
        if (v === 'low') return 'fv-csv-sev-low';
        if (v === 'info' || v === 'informational') return 'fv-csv-sev-info';
    }
    if (h.indexOf('status') >= 0) {
        if (v === 'open' || v === 'active' || v === 'vulnerable') return 'fv-csv-status-open';
        if (v === 'closed' || v === 'fixed' || v === 'resolved') return 'fv-csv-status-closed';
    }
    return '';
}

function fvCsvSummary(header, dataRows) {
    if (dataRows.length === 0) return '';
    var parts = [];
    parts.push('<span class="fv-csv-stat">' + dataRows.length + ' rows</span>');
    parts.push('<span class="fv-csv-stat">' + header.length + ' columns</span>');
    var sevIdx = -1;
    for (var i = 0; i < header.length; i++) {
        var h = header[i].toLowerCase();
        if (h.indexOf('severity') >= 0 || h.indexOf('risk') >= 0) { sevIdx = i; break; }
    }
    if (sevIdx >= 0) {
        var counts = {};
        for (var r = 0; r < dataRows.length; r++) {
            var v = ((dataRows[r] && dataRows[r][sevIdx]) || '').trim().toLowerCase();
            if (v) counts[v] = (counts[v] || 0) + 1;
        }
        var order = ['critical','high','medium','low','info','informational'];
        for (var o = 0; o < order.length; o++) {
            if (counts[order[o]]) {
                parts.push('<span class="fv-csv-sev-' + (order[o] === 'informational' ? 'info' : order[o]) + ' fv-csv-stat-pill">' + counts[order[o]] + ' ' + order[o] + '</span>');
            }
        }
    }
    return parts.join(' ');
}

// --- JSONL renderer (line-delimited JSON) ---
function fvRenderJsonl(text) {
    var lines = text.split('\n').filter(function(l) { return l.trim(); });
    if (lines.length === 0) return '<div class="fv-binary"><div>Empty JSONL</div></div>';
    var html = '<div class="fv-jsonl-wrap">';
    html += '<div class="fv-jsonl-header">' + lines.length + ' records</div>';
    var limit = Math.min(lines.length, 200);
    for (var i = 0; i < limit; i++) {
        try {
            var obj = JSON.parse(lines[i]);
            html += '<div class="fv-jsonl-entry"><span class="fv-jsonl-idx">' + (i + 1) + '</span><pre>' + fvRenderJson(obj, 0) + '</pre></div>';
        } catch(_) {
            html += '<div class="fv-jsonl-entry"><span class="fv-jsonl-idx">' + (i + 1) + '</span><pre>' + fvEscHtml(lines[i]) + '</pre></div>';
        }
    }
    if (lines.length > 200) html += '<div class="fv-csv-truncated">Showing 200 of ' + lines.length + ' records</div>';
    html += '</div>';
    return html;
}

// --- HTML preview (sandboxed iframe) ---
function fvRenderHtmlPreview(content) {
    var blob = new Blob([content], { type: 'text/html' });
    var url = URL.createObjectURL(blob);
    return '<iframe class="fv-html-iframe" sandbox="allow-same-origin" src="' + url + '"></iframe>';
}

function openFileViewer(relativePath, fileName, sizeBytes) {
    _fvCurrentPath = relativePath;
    _fvRawContent = '';
    var body = document.getElementById('file-viewer-body');
    var nameEl = document.getElementById('file-viewer-filename');
    var metaEl = document.getElementById('file-viewer-meta');
    var dlBtn = document.getElementById('file-viewer-download-btn');
    var copyBtn = document.getElementById('file-viewer-copy-btn');

    if (nameEl) nameEl.textContent = fileName || relativePath;
    if (metaEl) metaEl.textContent = fvFormatSize(sizeBytes);
    if (body) body.innerHTML = '<div class="loading-spinner">Loading…</div>';

    var iconEl = document.getElementById('file-viewer-icon');
    if (iconEl) {
        if (fvIsImage(fileName)) {
            iconEl.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>';
        } else {
            iconEl.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
        }
    }

    if (dlBtn) {
        dlBtn.onclick = function() { fvDownload(relativePath); };
    }
    if (copyBtn) {
        copyBtn.style.display = fvIsBinary(fileName) || fvIsImage(fileName) ? 'none' : '';
        copyBtn.onclick = function() { fvCopyContent(); };
    }

    openAppModal('file-viewer-modal', { focus: false });

    if (fvIsImage(fileName)) {
        fvShowImage(relativePath, body);
    } else if (fvIsBinary(fileName)) {
        fvShowBinary(fileName, sizeBytes, body);
    } else {
        fvLoadTextContent(relativePath, fileName, body);
    }
}

function closeFileViewer() {
    closeAppModal('file-viewer-modal');
    _fvRawContent = '';
    _fvCurrentPath = '';
}

function fvDownload(relativePath) {
    var token = localStorage.getItem('auth_token') || '';
    var url = getApiBase() + '/api/chat-uploads/download?path=' + encodeURIComponent(relativePath);
    var a = document.createElement('a');
    a.href = url + '&token=' + encodeURIComponent(token);
    a.target = '_blank';
    a.click();
}

function fvCopyContent() {
    if (!_fvRawContent) return;
    navigator.clipboard.writeText(_fvRawContent).then(function() {
        var btn = document.getElementById('file-viewer-copy-btn');
        if (btn) {
            var orig = btn.innerHTML;
            btn.textContent = 'Copied!';
            setTimeout(function() { btn.innerHTML = orig; }, 1500);
        }
    });
}

function fvShowImage(relativePath, body) {
    var token = localStorage.getItem('auth_token') || '';
    var url = getApiBase() + '/api/chat-uploads/download?path=' + encodeURIComponent(relativePath) + '&token=' + encodeURIComponent(token);
    body.innerHTML = '<div class="fv-image-wrap"><img src="' + fvEscHtml(url) + '" alt="Preview" /></div>';
}

function fvShowBinary(fileName, sizeBytes, body) {
    body.innerHTML = '<div class="fv-binary">' +
        '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>' +
        '<div style="font-size:15px;font-weight:500;">' + fvEscHtml(fileName) + '</div>' +
        '<div>' + fvFormatSize(sizeBytes) + '</div>' +
        '<div style="opacity:0.6;">Binary file — click Download to save</div>' +
        '</div>';
}

async function fvLoadTextContent(relativePath, fileName, body) {
    try {
        var res = await apiFetch('/api/chat-uploads/content?path=' + encodeURIComponent(relativePath));
        if (!res.ok) {
            var errText = '';
            try { var e = await res.json(); errText = e.error || ''; } catch(_) { errText = await res.text(); }
            throw new Error(errText || 'HTTP ' + res.status);
        }
        var data = await res.json();
        var content = data.content != null ? String(data.content) : '';
        _fvRawContent = content;

        if (fvIsJson(fileName)) {
            try {
                var parsed = JSON.parse(content);
                body.innerHTML = '<div class="fv-json-wrap"><pre>' + fvRenderJson(parsed, 0) + '</pre></div>';
            } catch(_) {
                body.innerHTML = fvRenderText(content, fileName);
            }
        } else if (fvIsJsonl(fileName)) {
            body.innerHTML = fvRenderJsonl(content);
        } else if (fvIsCsv(fileName)) {
            body.innerHTML = fvRenderCsv(content, fileName);
        } else if (fvIsHtml(fileName)) {
            body.innerHTML = fvRenderHtmlPreview(content);
        } else if (fvIsMarkdown(fileName)) {
            body.innerHTML = '<div class="fv-markdown">' + fvRenderMarkdown(content) + '</div>';
        } else {
            body.innerHTML = fvRenderText(content, fileName);
        }

        var lineCount = content.split('\n').length;
        var metaEl = document.getElementById('file-viewer-meta');
        var metaParts = [fvFormatSize(new Blob([content]).size), lineCount + ' lines'];
        if (fvIsCsv(fileName)) {
            var rows = fvParseCsvRows(content, fileName);
            metaParts.push((rows.length > 0 ? rows.length - 1 : 0) + ' rows');
            if (rows.length > 0) metaParts.push(rows[0].length + ' cols');
        }
        if (metaEl) {
            metaEl.textContent = metaParts.join('  ·  ');
        }
    } catch(e) {
        body.innerHTML = '<div class="fv-binary">' +
            '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>' +
            '<div style="font-size:14px;">' + fvEscHtml(e.message) + '</div>' +
            '<div style="opacity:0.6;">Could not load content — try downloading instead</div>' +
            '</div>';
    }
}

function openFileViewerIdx(idx) {
    var f = chatFilesDisplayed[idx];
    if (!f) return;
    openFileViewer(f.relativePath, f.name, f.sizeBytes);
}

window.openFileViewer = openFileViewer;
window.closeFileViewer = closeFileViewer;
window.openFileViewerIdx = openFileViewerIdx;

// =========================================================================
//  CHAT PAGE FILES BADGE — shows count + pulses on new files
// =========================================================================

let _fvLastKnownCount = -1;

function updateChatFilesBadge(count) {
    var badge = document.getElementById('chat-files-badge');
    if (!badge) return;
    if (count > 0) {
        badge.textContent = count > 99 ? '99+' : count;
        badge.hidden = false;
        if (_fvLastKnownCount >= 0 && count > _fvLastKnownCount) {
            badge.classList.remove('pulse');
            void badge.offsetWidth;
            badge.classList.add('pulse');
        }
    } else {
        badge.hidden = true;
    }
    _fvLastKnownCount = count;
}

var _origLoadChatFilesPage = typeof loadChatFilesPage === 'function' ? loadChatFilesPage : null;
if (_origLoadChatFilesPage) {
    var _patchedLoad = loadChatFilesPage;
}

(function patchBadgeOnLoad() {
    var origRender = renderChatFilesTable;
    renderChatFilesTable = function() {
        origRender.apply(this, arguments);
        updateChatFilesBadge(chatFilesTotal || chatFilesCache.length);
    };
})();

async function refreshChatFilesBadge() {
    if (typeof apiFetch === 'undefined') return;
    try {
        var res = await apiFetch('/api/chat-uploads?pageSize=1');
        if (!res || !res.ok) return;
        var data = await res.json();
        updateChatFilesBadge(data.total || 0);
    } catch(_) {}
}

setInterval(refreshChatFilesBadge, 60000);
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(refreshChatFilesBadge, 2000);
});
