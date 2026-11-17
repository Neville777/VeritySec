function knowledgeIndexErrorAdvice(error) {
    const text = String(error || '');
    if (/\b401\b|incorrect api key|invalid api key|unauthorized/i.test(text)) return 'The embedding service rejected authentication. Check the API key and service address in the knowledge base embedding config, then save and retry.';
    if (/\b403\b|forbidden/i.test(text)) return 'The embedding service denied access. Check account permissions and access to the selected embedding model.';
    if (/\b429\b|rate limit|quota/i.test(text)) return 'The embedding service is rate-limiting requests. Check request frequency and account quota, then retry later.';
    if (/timeout|deadline exceeded/i.test(text)) return 'The embedding service request timed out. Check service availability, network and proxy settings, then retry.';
    if (/connection refused|no such host|network is unreachable/i.test(text)) return 'Cannot connect to the embedding service. Check the service address, DNS, network and proxy settings.';
    return 'Check the embedding model and service configuration based on the error above, fix it, and retry.';
}

// Knowledge base management features
function _t(key, opts) {
    return typeof window.t === 'function' ? window.t(key, opts) : key;
}

// Returns the HTML for the "knowledge base disabled" notice block (uses data-i18n so it updates automatically on language switch)
function getKnowledgeNotEnabledHTML() {
    return `
        <div class="empty-state" style="text-align: center; padding: 40px 20px;">
            <div style="font-size: 48px; margin-bottom: 20px;">📚</div>
            <h3 data-i18n="knowledge.notEnabledTitle" style="margin-bottom: 10px; color: #666;"></h3>
            <p data-i18n="knowledge.notEnabledHint" style="color: #999; margin-bottom: 20px;"></p>
            <button data-i18n="knowledge.goToSettings" onclick="switchToSettings()" style="
                background: #007bff;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 14px;
            "></button>
        </div>
    `;
}

// Render the "knowledge base disabled" state into the container and apply the current language
function renderKnowledgeNotEnabledState(container) {
    if (!container) return;
    container.innerHTML = getKnowledgeNotEnabledHTML();
    if (typeof window.applyTranslations === 'function') {
        window.applyTranslations(container);
    }
}

let knowledgeCategories = [];
let knowledgeItems = [];
let currentEditingItemId = null;
let isSavingKnowledgeItem = false; // Prevent duplicate submission
let retrievalLogsData = []; // Stores retrieval log data for detail view
let knowledgePagination = {
    currentPage: 1,
    pageSize: 10, // Categories per page (pagination is by category)
    total: 0,
    currentCategory: ''
};
let knowledgeSearchTimeout = null; // Search debounce timer

// Load knowledge categories
async function loadKnowledgeCategories() {
    try {
        // Add timestamp parameter to avoid caching
        const timestamp = Date.now();
        const response = await apiFetch(`/api/knowledge/categories?_t=${timestamp}`, {
            method: 'GET',
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        });
        if (!response.ok) {
            throw new Error('Failed to get categories');
        }
        const data = await response.json();
        
        // Check whether the knowledge base feature is enabled
        if (data.enabled === false) {
            // Feature disabled: show a friendly notice (uses data-i18n, updates automatically on language switch)
            renderKnowledgeNotEnabledState(document.getElementById('knowledge-items-list'));
            return [];
        }
        
        knowledgeCategories = data.categories || [];
        
        // Update the category filter dropdown
        const filterDropdown = document.getElementById('knowledge-category-filter-dropdown');
        if (filterDropdown) {
            filterDropdown.innerHTML = '<div class="custom-select-option" data-value="" onclick="selectKnowledgeCategory(\'\')">All</div>';
            knowledgeCategories.forEach(category => {
                const option = document.createElement('div');
                option.className = 'custom-select-option';
                option.setAttribute('data-value', category);
                option.textContent = category;
                option.onclick = function() {
                    selectKnowledgeCategory(category);
                };
                filterDropdown.appendChild(option);
            });
        }
        
        return knowledgeCategories;
    } catch (error) {
        console.error('Failed to load categories:', error);
        // Only show errors when the feature is not disabled
        if (!error.message.includes('Knowledge base feature is not enabled')) {
            showNotification('Failed to load categories: ' + error.message, 'error');
        }
        return [];
    }
}

// Load knowledge item list (supports per-category pagination; does not load full content by default)
async function loadKnowledgeItems(category = '', page = 1, pageSize = 10) {
    try {
        // Update pagination state
        knowledgePagination.currentCategory = category;
        knowledgePagination.currentPage = page;
        knowledgePagination.pageSize = pageSize;
        
        // Build URL (per-category pagination mode, without full content)
        const timestamp = Date.now();
        const offset = (page - 1) * pageSize;
        let url = `/api/knowledge/items?categoryPage=true&limit=${pageSize}&offset=${offset}&_t=${timestamp}`;
        if (category) {
            url += `&category=${encodeURIComponent(category)}`;
        }
        
        const response = await apiFetch(url, {
            method: 'GET',
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to get knowledge items');
        }
        const data = await response.json();
        
        // Check whether the knowledge base feature is enabled
        if (data.enabled === false) {
            // Feature disabled: show a friendly notice (if not already shown; uses data-i18n, updates automatically on language switch)
            const container = document.getElementById('knowledge-items-list');
            if (container && !container.querySelector('.empty-state')) {
                renderKnowledgeNotEnabledState(container);
            }
            knowledgeItems = [];
            knowledgePagination.total = 0;
            renderKnowledgePagination();
            return [];
        }
        
        // Handle the per-category paginated response data
        const categoriesWithItems = data.categories || [];
        knowledgePagination.total = data.total || 0; // Total categories
        
        renderKnowledgeItemsByCategories(categoriesWithItems);
        
        // If a single category is selected, hide pagination (only one category is shown)
        if (category) {
            const paginationContainer = document.getElementById('knowledge-pagination');
            if (paginationContainer) {
                paginationContainer.innerHTML = '';
            }
        } else {
            renderKnowledgePagination();
        }
        return categoriesWithItems;
    } catch (error) {
        console.error('Failed to load knowledge items:', error);
        // Only show errors when the feature is not disabled
        if (!error.message.includes('Knowledge base feature is not enabled')) {
            showNotification('Failed to load knowledge items: ' + error.message, 'error');
        }
        return [];
    }
}

// Render the knowledge item list (per-category paginated data structure)
function renderKnowledgeItemsByCategories(categoriesWithItems) {
    const container = document.getElementById('knowledge-items-list');
    if (!container) return;
    
    if (categoriesWithItems.length === 0) {
        container.innerHTML = '<div class="empty-state">No knowledge items yet</div>';
        return;
    }
    
    // Compute total items and categories
    const totalItems = categoriesWithItems.reduce((sum, cat) => sum + (cat.items?.length || 0), 0);
    const categoryCount = categoriesWithItems.length;
    
    // Update statistics
    updateKnowledgeStats(categoriesWithItems, categoryCount);
    
    // Render categories and knowledge items
    let html = '<div class="knowledge-categories-container">';
    
    categoriesWithItems.forEach(categoryData => {
        const category = categoryData.category || 'uncategorized';
        const categoryItems = categoryData.items || [];
        const categoryCount = categoryData.itemCount || categoryItems.length;
        
        html += `
            <div class="knowledge-category-section" data-category="${escapeAttr(category)}">
                <div class="knowledge-category-header">
                    <div class="knowledge-category-info">
                        <h3 class="knowledge-category-title">${escapeHtml(category)}</h3>
                        <span class="knowledge-category-count">${categoryCount} items</span>
                    </div>
                </div>
                <div class="knowledge-items-grid">
                    ${categoryItems.map(item => renderKnowledgeItemCard(item)).join('')}
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
    if (typeof rbacAfterDynamicRender === 'function') rbacAfterDynamicRender(container);
}

// Render the knowledge item list (backward compatible; for legacy per-item pagination)
function renderKnowledgeItems(items) {
    const container = document.getElementById('knowledge-items-list');
    if (!container) return;
    
    if (items.length === 0) {
        container.innerHTML = '<div class="empty-state">No knowledge items yet</div>';
        return;
    }
    
    // Group by category
    const groupedByCategory = {};
    items.forEach(item => {
        const category = item.category || 'uncategorized';
        if (!groupedByCategory[category]) {
            groupedByCategory[category] = [];
        }
        groupedByCategory[category].push(item);
    });
    
    // Update statistics
    updateKnowledgeStats(items, Object.keys(groupedByCategory).length);
    
    // Render grouped content
    const categories = Object.keys(groupedByCategory).sort();
    let html = '<div class="knowledge-categories-container">';
    
    categories.forEach(category => {
        const categoryItems = groupedByCategory[category];
        const categoryCount = categoryItems.length;
        
        html += `
            <div class="knowledge-category-section" data-category="${escapeAttr(category)}">
                <div class="knowledge-category-header">
                    <div class="knowledge-category-info">
                        <h3 class="knowledge-category-title">${escapeHtml(category)}</h3>
                        <span class="knowledge-category-count">${categoryCount} items</span>
                    </div>
                </div>
                <div class="knowledge-items-grid">
                    ${categoryItems.map(item => renderKnowledgeItemCard(item)).join('')}
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
    if (typeof rbacAfterDynamicRender === 'function') rbacAfterDynamicRender(container);
}

// Render pagination controls (per-category)
function renderKnowledgePagination() {
    const container = document.getElementById('knowledge-pagination');
    if (!container) return;
    
    const { currentPage, pageSize, total } = knowledgePagination;
    const totalPages = Math.ceil(total / pageSize); // total is the total category count
    
    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }
    
    let html = '<div class="knowledge-pagination" style="display: flex; justify-content: center; align-items: center; gap: 8px; padding: 20px; flex-wrap: wrap;">';
    
    // Previous page button
    html += `<button class="pagination-btn" onclick="loadKnowledgePage(${currentPage - 1})" ${currentPage <= 1 ? 'disabled style="opacity: 0.5; cursor: not-allowed;"' : ''}>Previous page</button>`;
    
    // Page number display (shows category count)
    html += `<span style="padding: 0 12px;">Page ${currentPage} of ${totalPages} (${total} categories total)</span>`;
    
    // Next page button
    html += `<button class="pagination-btn" onclick="loadKnowledgePage(${currentPage + 1})" ${currentPage >= totalPages ? 'disabled style="opacity: 0.5; cursor: not-allowed;"' : ''}>Next page</button>`;
    
    html += '</div>';
    container.innerHTML = html;
}

// Load knowledge items for the specified page
function loadKnowledgePage(page) {
    const { currentCategory, pageSize, total } = knowledgePagination;
    const totalPages = Math.ceil(total / pageSize);
    
    if (page < 1 || page > totalPages) {
        return;
    }
    
    loadKnowledgeItems(currentCategory, page, pageSize);
}

// Render a single knowledge item card
function renderKnowledgeItemCard(item) {
    // Extract content preview (if item has no content field, it is a summary and no preview is shown)
    let previewText = '';
    if (item.content) {
        // Strip markdown formatting, take the first 150 characters
        let preview = item.content;
        // Remove markdown heading markers
        preview = preview.replace(/^#+\s+/gm, '');
        // Remove code blocks
        preview = preview.replace(/```[\s\S]*?```/g, '');
        // Remove inline code
        preview = preview.replace(/`[^`]+`/g, '');
        // Remove links
        preview = preview.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1');
        // Clean up extra whitespace
        preview = preview.replace(/\n+/g, ' ').replace(/\s+/g, ' ').trim();
        
        previewText = preview.length > 150 ? preview.substring(0, 150) + '...' : preview;
    }
    
    // Extract file path for display
    const filePath = item.filePath || '';
    const relativePath = filePath.split(/[/\\]/).slice(-2).join('/'); // Show the last two path levels
    
    // Format time
    const createdTime = formatTime(item.createdAt);
    const updatedTime = formatTime(item.updatedAt);
    
    // Prefer showing the update time; fall back to the creation time if there is none
    const displayTime = updatedTime || createdTime;
    const timeLabel = updatedTime ? 'Updated' : 'Created';
    
    // Check whether recently updated (within 7 days)
    let isRecent = false;
    if (item.updatedAt && updatedTime) {
        const updateDate = new Date(item.updatedAt);
        if (!isNaN(updateDate.getTime())) {
            isRecent = (Date.now() - updateDate.getTime()) < 7 * 24 * 60 * 60 * 1000;
        }
    }
    
    return `
        <div class="knowledge-item-card" data-id="${escapeAttr(item.id)}" data-category="${escapeAttr(item.category)}">
            <div class="knowledge-item-card-header">
                <div class="knowledge-item-card-title-row">
                    <h4 class="knowledge-item-card-title" title="${escapeAttr(item.title)}">${escapeHtml(item.title)}</h4>
                    <div class="knowledge-item-card-actions">
                        <button class="knowledge-item-action-btn" data-require-permission="knowledge:write" onclick="editKnowledgeItem('${item.id}')" title="Edit">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </button>
                        <button class="knowledge-item-action-btn knowledge-item-delete-btn" data-require-permission="knowledge:delete" onclick="deleteKnowledgeItem('${item.id}')" title="Delete">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                        </button>
                    </div>
                </div>
                ${relativePath ? `<div class="knowledge-item-path">📁 ${escapeHtml(relativePath)}</div>` : ''}
            </div>
            ${previewText ? `
            <div class="knowledge-item-card-content">
                <p class="knowledge-item-preview">${escapeHtml(previewText)}</p>
            </div>
            ` : ''}
            <div class="knowledge-item-card-footer">
                <div class="knowledge-item-meta">
                    ${displayTime ? `<span class="knowledge-item-time" title="${timeLabel}">🕒 ${displayTime}</span>` : ''}
                    ${isRecent ? '<span class="knowledge-item-badge-new">New</span>' : ''}
                </div>
            </div>
        </div>
    `;
}

// Update statistics (supports per-category paginated data structure)
function updateKnowledgeStats(data, categoryCount) {
    const statsContainer = document.getElementById('knowledge-stats');
    if (!statsContainer) return;
    
    // Count knowledge items on the current page
    let currentPageItemCount = 0;
    if (Array.isArray(data) && data.length > 0) {
        // Check whether it is categoriesWithItems or the items array
        if (data[0].category !== undefined && data[0].items !== undefined) {
            // Per-category paginated data structure
            currentPageItemCount = data.reduce((sum, cat) => sum + (cat.items?.length || 0), 0);
        } else {
            // Per-item paginated data structure (backward compatible)
            currentPageItemCount = data.length;
        }
    }
    
    // Total categories (from pagination info; only falls back to the current page's category count when undefined)
    const totalCategories = (knowledgePagination.total != null) ? knowledgePagination.total : categoryCount;
    
    statsContainer.innerHTML = `
        <div class="knowledge-stat-item">
            <span class="knowledge-stat-label">Total categories</span>
            <span class="knowledge-stat-value">${totalCategories}</span>
        </div>
        <div class="knowledge-stat-item">
            <span class="knowledge-stat-label">Categories on this page</span>
            <span class="knowledge-stat-value">${categoryCount}</span>
        </div>
        <div class="knowledge-stat-item">
            <span class="knowledge-stat-label">Items on this page</span>
            <span class="knowledge-stat-value">${currentPageItemCount} items</span>
        </div>
    `;
    
    // Update index progress
    updateIndexProgress();
}

// Update index progress
let indexProgressInterval = null;

async function updateIndexProgress() {
    try {
        const response = await apiFetch('/api/knowledge/index-status', {
            method: 'GET',
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        });
        
        if (!response.ok) {
            return; // Fail silently; does not affect the main UI
        }
        
        const status = await response.json();
        const progressContainer = document.getElementById('knowledge-index-progress');
        if (!progressContainer) return;
        
        // Check whether the knowledge base feature is enabled
        if (status.enabled === false) {
            // Feature disabled: hide the progress bar
            progressContainer.style.display = 'none';
            if (indexProgressInterval) {
                clearInterval(indexProgressInterval);
                indexProgressInterval = null;
            }
            return;
        }
        
        const totalItems = status.total_items || 0;
        const indexedItems = status.indexed_items || 0;
        const progressPercent = status.progress_percent || 0;
        const isComplete = status.is_complete || false;
        const lastError = status.last_error || '';
        
        // Check whether an index rebuild is in progress (rebuild state takes priority)
        const isRebuilding = status.is_rebuilding || false;
        
        if (totalItems === 0 && !lastError) {
            // No knowledge items: hide the progress bar
            progressContainer.style.display = 'none';
            if (indexProgressInterval) {
                clearInterval(indexProgressInterval);
                indexProgressInterval = null;
            }
            return;
        }
        
        // Show progress bar
        progressContainer.style.display = 'block';
        
        // If there is an error message, show the error
        if (lastError) {
            progressContainer.innerHTML = `
                <div class="knowledge-index-progress-error" style="
                    background: #fee;
                    border: 1px solid #fcc;
                    border-radius: 8px;
                    padding: 16px;
                    margin-bottom: 16px;
                ">
                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 20px; margin-right: 8px;">❌</span>
                        <span style="font-weight: bold; color: #c00;">Index build failed</span>
                    </div>
                    <div style="color: #666; font-size: 14px; margin-bottom: 12px; line-height: 1.5;">
                        ${escapeHtml(lastError)}
                    </div>
                    <div style="color: #999; font-size: 12px; margin-bottom: 12px;">
                        ${escapeHtml(knowledgeIndexErrorAdvice(lastError))}
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                        <button onclick="buildKnowledgeIndex()" style="
                            background: #007bff;
                            color: white;
                            border: none;
                            padding: 6px 12px;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 13px;
                        ">Retry</button>
                        <button onclick="rebuildKnowledgeIndexFull()" style="
                            background: #6c757d;
                            color: white;
                            border: none;
                            padding: 6px 12px;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 13px;
                        ">Full rebuild</button>
                        <button onclick="stopIndexProgressPolling()" style="
                            background: #6c757d;
                            color: white;
                            border: none;
                            padding: 6px 12px;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 13px;
                        ">Close</button>
                    </div>
                </div>
            `;
            // Stop polling
            if (indexProgressInterval) {
                clearInterval(indexProgressInterval);
                indexProgressInterval = null;
            }
            // Show error notification
            showNotification('Index build failed: ' + lastError.substring(0, 100), 'error');
            return;
        }
        

        // Handle rebuild state first
        if (isRebuilding) {
            const rebuildTotal = status.rebuild_total || totalItems;
            const rebuildCurrent = status.rebuild_current || 0;
            const rebuildFailed = status.rebuild_failed || 0;
            const rebuildLastItemID = status.rebuild_last_item_id || '';
            const rebuildLastChunks = status.rebuild_last_chunks || 0;
            const rebuildStartTime = status.rebuild_start_time || '';

            // Compute progress percentage (using rebuild progress)
            let rebuildProgress = progressPercent;
            if (rebuildTotal > 0) {
                rebuildProgress = (rebuildCurrent / rebuildTotal) * 100;
            }

            progressContainer.innerHTML = `
                <div class="knowledge-index-progress">
                    <div class="progress-header">
                        <span class="progress-icon">🔨</span>
                        <span class="progress-text">Building index: ${rebuildCurrent}/${rebuildTotal} (${rebuildProgress.toFixed(1)}%) - failed: ${rebuildFailed}</span>
                    </div>
                    <div class="progress-bar-container">
                        <div class="progress-bar" style="width: ${rebuildProgress}%"></div>
                    </div>
                    <div class="progress-hint">
                        ${rebuildLastItemID ? `Processing:${escapeHtml(rebuildLastItemID.substring(0, 36))}... (${rebuildLastChunks} chunks)` : 'Processing...'}
                        ${rebuildStartTime ? `<br>Started:${new Date(rebuildStartTime).toLocaleString()}` : ''}
                    </div>
                </div>
            `;

            // Keep polling while rebuilding
            if (!indexProgressInterval) {
                indexProgressInterval = setInterval(updateIndexProgress, 2000);
            }
            return;
        }
        
        if (isComplete) {
            progressContainer.innerHTML = `
                <div class="knowledge-index-progress-complete">
                    <span class="progress-icon">✅</span>
                    <span class="progress-text">Index build complete (${indexedItems}/${totalItems})</span>
                </div>
            `;
            // Stop polling when complete
            if (indexProgressInterval) {
                clearInterval(indexProgressInterval);
                indexProgressInterval = null;
            }
        } else {
            const showResume = indexedItems < totalItems;
            progressContainer.innerHTML = `
                <div class="knowledge-index-progress">
                    <div class="progress-header">
                        <span class="progress-icon">🔨</span>
                        <span class="progress-text">Building index: ${indexedItems}/${totalItems} (${progressPercent.toFixed(1)}%)</span>
                    </div>
                    <div class="progress-bar-container">
                        <div class="progress-bar" style="width: ${progressPercent}%"></div>
                    </div>
                    <div class="progress-hint">
                        Semantic search will be available after the index build completes
                        ${showResume ? '<br><button type="button" onclick="buildKnowledgeIndex()" style="margin-top:8px;background:#007bff;color:#fff;border:none;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px;">Build index</button>' : ''}
                    </div>
                </div>
            `;
            
            // Start polling if not already started
            if (!indexProgressInterval) {
                indexProgressInterval = setInterval(updateIndexProgress, 3000); // Refresh every 3 seconds
            }
        }
    } catch (error) {
        // Show error message
        console.error('Failed to get index status:', error);
        const progressContainer = document.getElementById('knowledge-index-progress');
        if (progressContainer) {
            progressContainer.style.display = 'block';
            progressContainer.innerHTML = `
                <div class="knowledge-index-progress-error" style="
                    background: #fee;
                    border: 1px solid #fcc;
                    border-radius: 8px;
                    padding: 16px;
                    margin-bottom: 16px;
                ">
                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 20px; margin-right: 8px;">⚠️</span>
                        <span style="font-weight: bold; color: #c00;">Unable to get index status</span>
                    </div>
                    <div style="color: #666; font-size: 14px;">
                        Unable to reach the server to get index status; check your network connection or refresh the page.
                    </div>
                </div>
            `;
        }
        // Stop polling
        if (indexProgressInterval) {
            clearInterval(indexProgressInterval);
            indexProgressInterval = null;
        }
    }
}

// Stop index progress polling
function stopIndexProgressPolling() {
    if (indexProgressInterval) {
        clearInterval(indexProgressInterval);
        indexProgressInterval = null;
    }
    const progressContainer = document.getElementById('knowledge-index-progress');
    if (progressContainer) {
        progressContainer.style.display = 'none';
    }
}

// Select knowledge category
function selectKnowledgeCategory(category) {
    const trigger = document.getElementById('knowledge-category-filter-trigger');
    const wrapper = document.getElementById('knowledge-category-filter-wrapper');
    const dropdown = document.getElementById('knowledge-category-filter-dropdown');
    
    if (trigger && wrapper && dropdown) {
        const displayText = category || 'All';
        trigger.querySelector('span').textContent = displayText;
        wrapper.classList.remove('open');
        
        // Update selected state
        dropdown.querySelectorAll('.custom-select-option').forEach(opt => {
            opt.classList.remove('selected');
            if (opt.getAttribute('data-value') === category) {
                opt.classList.add('selected');
            }
        });
    }
    // Reset to the first page when switching category (if a category is selected, the API returns all items of that category)
    loadKnowledgeItems(category, 1, knowledgePagination.pageSize);
}

// Filter knowledge items
function filterKnowledgeItems() {
    const wrapper = document.getElementById('knowledge-category-filter-wrapper');
    if (wrapper) {
        const selectedOption = wrapper.querySelector('.custom-select-option.selected');
        const category = selectedOption ? selectedOption.getAttribute('data-value') : '';
        // Reset to first page
        loadKnowledgeItems(category, 1, knowledgePagination.pageSize);
    }
}

// Handle search input (with debounce)
function handleKnowledgeSearchInput() {
    const searchInput = document.getElementById('knowledge-search');
    const searchTerm = searchInput?.value.trim() || '';
    
    // Clear the previous timer
    if (knowledgeSearchTimeout) {
        clearTimeout(knowledgeSearchTimeout);
    }
    
    // If the search box is empty, restore the list immediately
    if (!searchTerm) {
        const wrapper = document.getElementById('knowledge-category-filter-wrapper');
        let category = '';
        if (wrapper) {
            const selectedOption = wrapper.querySelector('.custom-select-option.selected');
            category = selectedOption ? selectedOption.getAttribute('data-value') : '';
        }
        loadKnowledgeItems(category, 1, knowledgePagination.pageSize);
        return;
    }
    
    // When there is a search term, run the search after a 500ms delay (debounce)
    knowledgeSearchTimeout = setTimeout(() => {
        searchKnowledgeItems();
    }, 500);
}

// Search knowledge items (backend keyword matching across all data)
async function searchKnowledgeItems() {
    const searchInput = document.getElementById('knowledge-search');
    const searchTerm = searchInput?.value.trim() || '';
    
    if (!searchTerm) {
        // Restore the original list (reset to first page)
        const wrapper = document.getElementById('knowledge-category-filter-wrapper');
        let category = '';
        if (wrapper) {
            const selectedOption = wrapper.querySelector('.custom-select-option.selected');
            category = selectedOption ? selectedOption.getAttribute('data-value') : '';
        }
        await loadKnowledgeItems(category, 1, knowledgePagination.pageSize);
        return;
    }
    
    try {
        // Get currently selected category
        const wrapper = document.getElementById('knowledge-category-filter-wrapper');
        let category = '';
        if (wrapper) {
            const selectedOption = wrapper.querySelector('.custom-select-option.selected');
            category = selectedOption ? selectedOption.getAttribute('data-value') : '';
        }
        
        // Call the backend API for a full search
        const timestamp = Date.now();
        let url = `/api/knowledge/items?search=${encodeURIComponent(searchTerm)}&_t=${timestamp}`;
        if (category) {
            url += `&category=${encodeURIComponent(category)}`;
        }
        
        const response = await apiFetch(url, {
            method: 'GET',
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        });
        
        if (!response.ok) {
            throw new Error('Search failed');
        }
        
        const data = await response.json();
        
        // Check whether the knowledge base feature is enabled
        if (data.enabled === false) {
            renderKnowledgeNotEnabledState(document.getElementById('knowledge-items-list'));
            return;
        }
        
        // Handle search results
        const categoriesWithItems = data.categories || [];
        
        // Render search results
        const container = document.getElementById('knowledge-items-list');
        if (!container) return;
        
        if (categoriesWithItems.length === 0) {
            container.innerHTML = `
                <div class="empty-state" style="text-align: center; padding: 40px 20px;">
                    <div style="font-size: 48px; margin-bottom: 20px;">🔍</div>
                    <h3 style="margin-bottom: 10px;">No matching knowledge items found</h3>
                    <p style="color: #999;">No matches for keyword "<strong>${escapeHtml(searchTerm)}</strong>" in any data</p>
                    <p style="color: #999; margin-top: 10px; font-size: 0.9em;">Try other keywords, or use category filtering</p>
                </div>
            `;
        } else {
            // Compute total items and categories
            const totalItems = categoriesWithItems.reduce((sum, cat) => sum + (cat.items?.length || 0), 0);
            const categoryCount = categoriesWithItems.length;
            
            // Update statistics
            updateKnowledgeStats(categoriesWithItems, categoryCount);
            
            // Render search results
            renderKnowledgeItemsByCategories(categoriesWithItems);
        }
        
        // Hide pagination during search (search results show all matches)
        const paginationContainer = document.getElementById('knowledge-pagination');
        if (paginationContainer) {
            paginationContainer.innerHTML = '';
        }
        
    } catch (error) {
        console.error('Search knowledge items failed:', error);
        showNotification('Search failed: ' + error.message, 'error');
    }
}

// Refresh knowledge base
async function refreshKnowledgeBase() {
    try {
        showNotification('Scanning knowledge base...', 'info');
        const response = await apiFetch('/api/knowledge/scan', {
            method: 'POST'
        });
        if (!response.ok) {
            throw new Error('Failed to scan knowledge base');
        }
        const data = await response.json();
        // Show different messages based on the returned message
        if (data.items_to_index && data.items_to_index > 0) {
            showNotification(`Scan complete; indexing ${data.items_to_index} newly added or updated knowledge items`, 'success');
        } else {
            showNotification(data.message || 'Scan complete; no new or updated items need indexing', 'success');
        }
        // Reload knowledge items (reset to first page)
        await loadKnowledgeCategories();
        await loadKnowledgeItems(knowledgePagination.currentCategory, 1, knowledgePagination.pageSize);
        
        // Stop existing polling
        if (indexProgressInterval) {
            clearInterval(indexProgressInterval);
            indexProgressInterval = null;
        }
        
        // If there are items to index, wait briefly and then update progress immediately
        if (data.items_to_index && data.items_to_index > 0) {
            await new Promise(resolve => setTimeout(resolve, 500));
            updateIndexProgress();
            // Start polling progress (refresh every 2 seconds)
            if (!indexProgressInterval) {
                indexProgressInterval = setInterval(updateIndexProgress, 2000);
            }
        } else {
            // No items to index; still update once to show current status
            updateIndexProgress();
        }
    } catch (error) {
        console.error('Failed to refresh knowledge base:', error);
        showNotification('Failed to refresh knowledge base: ' + error.message, 'error');
    }
}

// Start knowledge base index task (mode: missing | full)
async function startKnowledgeIndexJob(mode = 'missing') {
    const fullRebuild = mode === 'full';
    const confirmMessage = fullRebuild
        ? 'This will re-index all knowledge items, which may take a long time. Continue?'
        : 'This will build indexes for knowledge items that do not have vectors yet. Continue?';
    if (!confirm(confirmMessage)) {
        return;
    }

    const actionLabel = fullRebuild ? 'Full index rebuild' : 'Build index';
    showNotification(`Starting ${actionLabel}...`, 'info');

    if (indexProgressInterval) {
        clearInterval(indexProgressInterval);
        indexProgressInterval = null;
    }

    const progressContainer = document.getElementById('knowledge-index-progress');
    if (progressContainer) {
        progressContainer.style.display = 'block';
        progressContainer.innerHTML = `
            <div class="knowledge-index-progress">
                <div class="progress-header">
                    <span class="progress-icon">🔨</span>
                    <span class="progress-text">${actionLabel} in progress: preparing...</span>
                </div>
                <div class="progress-bar-container">
                    <div class="progress-bar" style="width: 0%"></div>
                </div>
                <div class="progress-hint">Semantic search will be available after the index build completes</div>
            </div>
        `;
    }

    const query = fullRebuild ? '?mode=full' : '';
    const response = await apiFetch(`/api/knowledge/index${query}`, {
        method: 'POST'
    });

    let payload = {};
    try {
        payload = await response.json();
    } catch (_) {
        payload = {};
    }

    if (response.status === 409) {
        showNotification(payload.error || 'An index task is already running; please wait for it to finish', 'warning');
        updateIndexProgress();
        return;
    }
    if (!response.ok) {
        throw new Error(payload.error || `${actionLabel} failed`);
    }

    showNotification(payload.message || `${actionLabel} started; it will run in the background`, 'success');
    await new Promise(resolve => setTimeout(resolve, 500));
    updateIndexProgress();
    if (!indexProgressInterval) {
        indexProgressInterval = setInterval(updateIndexProgress, 2000);
    }
}

// Build index (default: only process knowledge items without vectors yet)
async function buildKnowledgeIndex() {
    try {
        await startKnowledgeIndexJob('missing');
    } catch (error) {
        console.error('Failed to build index:', error);
        showNotification('Failed to build index: ' + error.message, 'error');
    }
}

// Full index rebuild (explicit opt-in)
async function rebuildKnowledgeIndexFull() {
    try {
        await startKnowledgeIndexJob('full');
    } catch (error) {
        console.error('Full index rebuild failed:', error);
        showNotification('Full index rebuild failed: ' + error.message, 'error');
    }
}

// Show add knowledge item modal
function showAddKnowledgeItemModal() {
    if (typeof requirePermission === 'function' && !requirePermission('knowledge:write')) return;
    currentEditingItemId = null;
    document.getElementById('knowledge-item-modal-title').textContent = 'Add knowledge';
    document.getElementById('knowledge-item-category').value = '';
    document.getElementById('knowledge-item-title').value = '';
    document.getElementById('knowledge-item-content').value = '';
    openAppModal('knowledge-item-modal');
}

// Edit knowledge item
async function editKnowledgeItem(id) {
    try {
        currentEditingItemId = id;
        document.getElementById('knowledge-item-modal-title').textContent = 'Edit knowledge';
        document.getElementById('knowledge-item-category').value = '';
        document.getElementById('knowledge-item-title').value = '';
        document.getElementById('knowledge-item-content').value = '';
        openAppModal('knowledge-item-modal', { focus: false });
        const response = await apiFetch(`/api/knowledge/items/${id}`);
        if (!response.ok) {
            throw new Error('Failed to get knowledge items');
        }
        const item = await response.json();
        deferModalContent(() => {
            document.getElementById('knowledge-item-category').value = item.category;
            document.getElementById('knowledge-item-title').value = item.title;
            document.getElementById('knowledge-item-content').value = item.content;
            document.getElementById('knowledge-item-title')?.focus();
        });
    } catch (error) {
        closeAppModal('knowledge-item-modal');
        currentEditingItemId = null;
        console.error('Failed to edit knowledge item:', error);
        showNotification('Failed to edit knowledge item: ' + error.message, 'error');
    }
}

// Save knowledge item
async function saveKnowledgeItem() {
    if (typeof requirePermission === 'function' && !requirePermission('knowledge:write')) return;
    // Prevent duplicate submission
    if (isSavingKnowledgeItem) {
        showNotification('Saving, please do not click repeatedly...', 'warning');
        return;
    }
    
    const category = document.getElementById('knowledge-item-category').value.trim();
    const title = document.getElementById('knowledge-item-title').value.trim();
    const content = document.getElementById('knowledge-item-content').value.trim();
    
    if (!category || !title || !content) {
        showNotification('Please fill in all required fields', 'error');
        return;
    }
    
    // Set saving flag
    isSavingKnowledgeItem = true;
    
    // Get save and cancel buttons
    const saveButton = document.querySelector('#knowledge-item-modal .modal-footer .btn-primary');
    const cancelButton = document.querySelector('#knowledge-item-modal .modal-footer .btn-secondary');
    const modal = document.getElementById('knowledge-item-modal');
    
    const originalButtonText = saveButton ? saveButton.textContent : 'Save';
    const originalButtonDisabled = saveButton ? saveButton.disabled : false;
    
    // Disable all input fields and buttons
    const categoryInput = document.getElementById('knowledge-item-category');
    const titleInput = document.getElementById('knowledge-item-title');
    const contentInput = document.getElementById('knowledge-item-content');
    
    if (categoryInput) categoryInput.disabled = true;
    if (titleInput) titleInput.disabled = true;
    if (contentInput) contentInput.disabled = true;
    if (cancelButton) cancelButton.disabled = true;
    
    // Set save button loading state
    if (saveButton) {
        saveButton.disabled = true;
        saveButton.style.opacity = '0.6';
        saveButton.style.cursor = 'not-allowed';
        saveButton.textContent = 'Saving...';
    }
    
    try {
        const url = currentEditingItemId 
            ? `/api/knowledge/items/${currentEditingItemId}`
            : '/api/knowledge/items';
        const method = currentEditingItemId ? 'PUT' : 'POST';
        
        const response = await apiFetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                category,
                title,
                content
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to save knowledge item');
        }
        
        const item = await response.json();
        const action = currentEditingItemId ? 'Updated' : 'Created';
        const newItemCategory = item.category || category; // Save the category of the newly added knowledge item
        
        // Get the current filter state so it is kept after refresh
        const currentCategory = document.getElementById('knowledge-category-filter-wrapper');
        let selectedCategory = '';
        if (currentCategory) {
            const selectedOption = currentCategory.querySelector('.custom-select-option.selected');
            if (selectedOption) {
                selectedCategory = selectedOption.getAttribute('data-value') || '';
            }
        }
        
        // Close the modal immediately to give the user clear feedback
        closeKnowledgeItemModal();
        
        // Show loading state and refresh data (wait for completion to ensure data sync)
        const itemsListContainer = document.getElementById('knowledge-items-list');
        const originalContent = itemsListContainer ? itemsListContainer.innerHTML : '';
        
        if (itemsListContainer) {
            itemsListContainer.innerHTML = '<div class="loading-spinner">Refreshing...</div>';
        }
        
        try {
            // Refresh categories first, then knowledge items
            console.log('Refreshing knowledge base data...');
            await loadKnowledgeCategories();
            console.log('Category refresh complete; refreshing knowledge items...');
            
            // If the newly added knowledge item is not in the currently filtered category, switch to its category
            let categoryToShow = selectedCategory;
            if (!currentEditingItemId && selectedCategory && selectedCategory !== '' && newItemCategory !== selectedCategory) {
                // For a newly added item: if the current filter is not its category, switch to the item's category
                categoryToShow = newItemCategory;
                // Update filter display (does not trigger loading, since we load manually below)
                const trigger = document.getElementById('knowledge-category-filter-trigger');
                const wrapper = document.getElementById('knowledge-category-filter-wrapper');
                const dropdown = document.getElementById('knowledge-category-filter-dropdown');
                if (trigger && wrapper && dropdown) {
                    trigger.querySelector('span').textContent = newItemCategory || 'All';
                    dropdown.querySelectorAll('.custom-select-option').forEach(opt => {
                        opt.classList.remove('selected');
                        if (opt.getAttribute('data-value') === newItemCategory) {
                            opt.classList.add('selected');
                        }
                    });
                }
                showNotification(`✅ ${action} successfully! Switched to category "${newItemCategory}" to view the new knowledge item.`, 'success');
            }
            
            // Refresh knowledge item list (reset to first page)
            await loadKnowledgeItems(categoryToShow, 1, knowledgePagination.pageSize);
            console.log('Knowledge item refresh complete');
        } catch (err) {
            console.error('Failed to refresh data:', err);
            // If refresh failed, restore the original content
            if (itemsListContainer && originalContent) {
                itemsListContainer.innerHTML = originalContent;
            }
            showNotification('⚠️ Knowledge item saved, but refreshing the list failed; please refresh the page to check', 'warning');
        }
        
    } catch (error) {
        console.error('Failed to save knowledge item:', error);
        showNotification('❌ Failed to save knowledge item: ' + error.message, 'error');
        
        // If the notification system is unavailable, use alert
        if (typeof window.showNotification !== 'function') {
            alert('❌ Failed to save knowledge item: ' + error.message);
        }
        
        // Restore input fields and button state (on error, keep the modal open so the user can edit and retry)
        if (categoryInput) categoryInput.disabled = false;
        if (titleInput) titleInput.disabled = false;
        if (contentInput) contentInput.disabled = false;
        if (cancelButton) cancelButton.disabled = false;
        if (saveButton) {
            saveButton.disabled = false;
            saveButton.style.opacity = '';
            saveButton.style.cursor = '';
            saveButton.textContent = originalButtonText;
        }
    } finally {
        // Clear saving flag
        isSavingKnowledgeItem = false;
    }
}

// Delete knowledge item
async function deleteKnowledgeItem(id) {
    if (!confirm('Are you sure you want to delete this knowledge item?')) {
        return;
    }
    
    // Find the knowledge item card and delete button to remove
    const itemCard = document.querySelector(`.knowledge-item-card[data-id="${id}"]`);
    const deleteButton = itemCard ? itemCard.querySelector('.knowledge-item-delete-btn') : null;
    const categorySection = itemCard ? itemCard.closest('.knowledge-category-section') : null;
    let originalDisplay = '';
    let originalOpacity = '';
    let originalButtonOpacity = '';
    
    // Set the delete button loading state
    if (deleteButton) {
        originalButtonOpacity = deleteButton.style.opacity;
        deleteButton.style.opacity = '0.5';
        deleteButton.style.cursor = 'not-allowed';
        deleteButton.disabled = true;
        
        // Add loading animation
        const svg = deleteButton.querySelector('svg');
        if (svg) {
            svg.style.animation = 'spin 1s linear infinite';
        }
    }
    
    // Immediately remove the item from the UI (optimistic update)
    if (itemCard) {
        originalDisplay = itemCard.style.display;
        originalOpacity = itemCard.style.opacity;
        itemCard.style.transition = 'opacity 0.3s ease-out, transform 0.3s ease-out';
        itemCard.style.opacity = '0';
        itemCard.style.transform = 'translateX(-20px)';
        
        // Remove after the animation completes
        setTimeout(() => {
            if (itemCard.parentElement) {
                itemCard.remove();
                
                // Check whether the category still has items; if not, hide the category heading
                if (categorySection) {
                    const remainingItems = categorySection.querySelectorAll('.knowledge-item-card');
                    if (remainingItems.length === 0) {
                        categorySection.style.transition = 'opacity 0.3s ease-out';
                        categorySection.style.opacity = '0';
                        setTimeout(() => {
                            if (categorySection.parentElement) {
                                categorySection.remove();
                            }
                        }, 300);
                    } else {
                        // Update category count
                        const categoryCount = categorySection.querySelector('.knowledge-category-count');
                        if (categoryCount) {
                            const newCount = remainingItems.length;
                            categoryCount.textContent = `${newCount} items`;
                        }
                    }
                }
                
                // Do not update statistics here; wait for the data reload, which updates them correctly
            }
        }, 300);
    }
    
    try {
        const response = await apiFetch(`/api/knowledge/items/${id}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to delete knowledge item');
        }
        
        // Show success notification
        showNotification('✅ Deleted successfully! The knowledge item has been removed from the system.', 'success');
        
        // Reload data to keep it in sync (keep the current page number)
        await loadKnowledgeCategories();
        await loadKnowledgeItems(knowledgePagination.currentCategory, knowledgePagination.currentPage, knowledgePagination.pageSize);
        
    } catch (error) {
        console.error('Failed to delete knowledge item:', error);
        
        // If delete failed, restore the item display
        if (itemCard && originalDisplay !== 'none') {
            itemCard.style.display = originalDisplay || '';
            itemCard.style.opacity = originalOpacity || '1';
            itemCard.style.transform = '';
            itemCard.style.transition = '';
            
            // If the category was removed, it needs to be restored
            if (categorySection && !categorySection.parentElement) {
                // Reload is needed to restore (keeping the current pagination state)
                await loadKnowledgeItems(knowledgePagination.currentCategory, knowledgePagination.currentPage, knowledgePagination.pageSize);
            }
        }
        
        // Restore delete button state
        if (deleteButton) {
            deleteButton.style.opacity = originalButtonOpacity || '';
            deleteButton.style.cursor = '';
            deleteButton.disabled = false;
            const svg = deleteButton.querySelector('svg');
            if (svg) {
                svg.style.animation = '';
            }
        }
        
        showNotification('❌ Failed to delete knowledge item: ' + error.message, 'error');
    }
}

// Temporarily update statistics (after delete)
function updateKnowledgeStatsAfterDelete() {
    const statsContainer = document.getElementById('knowledge-stats');
    if (!statsContainer) return;
    
    const allItems = document.querySelectorAll('.knowledge-item-card');
    const allCategories = document.querySelectorAll('.knowledge-category-section');
    
    const totalItems = allItems.length;
    const categoryCount = allCategories.length;
    
    // Compute total content size (simplified here; should actually come from the server)
    const statsItems = statsContainer.querySelectorAll('.knowledge-stat-item');
    if (statsItems.length >= 2) {
        const totalItemsSpan = statsItems[0].querySelector('.knowledge-stat-value');
        const categoryCountSpan = statsItems[1].querySelector('.knowledge-stat-value');
        
        if (totalItemsSpan) {
            totalItemsSpan.textContent = totalItems;
        }
        if (categoryCountSpan) {
            categoryCountSpan.textContent = categoryCount;
        }
    }
}

// Close knowledge item modal
function closeKnowledgeItemModal() {
    closeAppModal('knowledge-item-modal');
    
    // Reset edit state
    currentEditingItemId = null;
    isSavingKnowledgeItem = false;
    
    // Restore all input fields and button state
    const categoryInput = document.getElementById('knowledge-item-category');
    const titleInput = document.getElementById('knowledge-item-title');
    const contentInput = document.getElementById('knowledge-item-content');
    const saveButton = document.querySelector('#knowledge-item-modal .modal-footer .btn-primary');
    const cancelButton = document.querySelector('#knowledge-item-modal .modal-footer .btn-secondary');
    
    if (categoryInput) {
        categoryInput.disabled = false;
        categoryInput.value = '';
    }
    if (titleInput) {
        titleInput.disabled = false;
        titleInput.value = '';
    }
    if (contentInput) {
        contentInput.disabled = false;
        contentInput.value = '';
    }
    if (saveButton) {
        saveButton.disabled = false;
        saveButton.style.opacity = '';
        saveButton.style.cursor = '';
        saveButton.textContent = 'Save';
    }
    if (cancelButton) {
        cancelButton.disabled = false;
    }
}

// Load retrieval logs
async function loadRetrievalLogs(conversationId = '', messageId = '') {
    try {
        let url = '/api/knowledge/retrieval-logs?limit=100';
        if (conversationId) {
            url += `&conversationId=${encodeURIComponent(conversationId)}`;
        }
        if (messageId) {
            url += `&messageId=${encodeURIComponent(messageId)}`;
        }
        
        const response = await apiFetch(url);
        if (!response.ok) {
            throw new Error('Failed to get retrieval logs');
        }
        const data = await response.json();
        renderRetrievalLogs(data.logs || []);
    } catch (error) {
        console.error('Failed to load retrieval logs:', error);
        // Even if loading fails, show the empty state instead of always showing "Loading..."
        renderRetrievalLogs([]);
        // Only show an error notification when a filter is applied (avoids showing errors when there is no data)
        if (conversationId || messageId) {
            showNotification(_t('retrievalLogs.loadError') + ': ' + error.message, 'error');
        }
    }
}

// Render retrieval logs
function renderRetrievalLogs(logs) {
    const container = document.getElementById('retrieval-logs-list');
    if (!container) return;
    
    // Update statistics (even when the array is empty)
    updateRetrievalStats(logs);
    
    if (logs.length === 0) {
        container.innerHTML = '<div class="empty-state">' + _t('retrievalLogs.noRecords') + '</div>';
        retrievalLogsData = [];
        return;
    }
    
    // Save log data for detail view
    retrievalLogsData = logs;
    
    container.innerHTML = logs.map((log, index) => {
        // Handle retrievedItems: may be an array, a string array, or a special marker
        let itemCount = 0;
        let hasResults = false;
        
        if (log.retrievedItems) {
            if (Array.isArray(log.retrievedItems)) {
                // Filter out special markers
                const realItems = log.retrievedItems.filter(id => id !== '_has_results');
                itemCount = realItems.length;
                // A special marker means there are results but the IDs are unknown; display as "Has results"
                if (log.retrievedItems.includes('_has_results')) {
                    hasResults = true;
                    // If real IDs exist, use the real count; otherwise display as "Has results" (without a specific count)
                    if (itemCount === 0) {
                        itemCount = -1; // -1 means results exist but the count is unknown
                    }
                } else {
                    hasResults = itemCount > 0;
                }
            } else if (typeof log.retrievedItems === 'string') {
                // If it is a string, try parsing it as JSON
                try {
                    const parsed = JSON.parse(log.retrievedItems);
                    if (Array.isArray(parsed)) {
                        const realItems = parsed.filter(id => id !== '_has_results');
                        itemCount = realItems.length;
                        if (parsed.includes('_has_results')) {
                            hasResults = true;
                            if (itemCount === 0) {
                                itemCount = -1;
                            }
                        } else {
                            hasResults = itemCount > 0;
                        }
                    }
                } catch (e) {
                    // Parse failed; ignore
                }
            }
        }
        
        const timeAgo = getTimeAgo(log.createdAt);
        
        return `
            <div class="retrieval-log-card ${hasResults ? 'has-results' : 'no-results'}" data-index="${index}">
                <div class="retrieval-log-card-header">
                    <div class="retrieval-log-icon">
                        ${hasResults ? '🔍' : '⚠️'}
                    </div>
                    <div class="retrieval-log-main-info">
                        <div class="retrieval-log-query">
                            ${escapeHtml(log.query || _t('retrievalLogs.noQuery'))}
                        </div>
                        <div class="retrieval-log-meta">
                            <span class="retrieval-log-time" title="${formatTime(log.createdAt)}">
                                🕒 ${timeAgo}
                            </span>
                            ${log.riskType ? `<span class="retrieval-log-risk-type">📁 ${escapeHtml(log.riskType)}</span>` : ''}
                        </div>
                    </div>
                    <div class="retrieval-log-result-badge ${hasResults ? 'success' : 'empty'}">
                        ${hasResults ? (itemCount > 0 ? itemCount + ' ' + _t('retrievalLogs.itemsUnit') : _t('retrievalLogs.hasResults')) : _t('retrievalLogs.noResults')}
                    </div>
                </div>
                <div class="retrieval-log-card-body">
                    <div class="retrieval-log-details-grid">
                        ${log.conversationId ? `
                            <div class="retrieval-log-detail-item">
                                <span class="detail-label">${_t('retrievalLogs.conversationId')}</span>
                                <code class="detail-value" title="${escapeAttr(_t('retrievalLogs.clickToCopy'))}" data-copy-title-copied="${escapeAttr(_t('common.copied'))}" data-copy-title-click="${escapeAttr(_t('retrievalLogs.clickToCopy'))}" onclick="var t=this; navigator.clipboard.writeText(${escapeJsStringAttr(log.conversationId)}).then(function(){ t.title=t.getAttribute('data-copy-title-copied')||'Copied!'; setTimeout(function(){ t.title=t.getAttribute('data-copy-title-click')||'Click to copy'; }, 2000); });" style="cursor: pointer;">${escapeHtml(log.conversationId)}</code>
                            </div>
                        ` : ''}
                        ${log.messageId ? `
                            <div class="retrieval-log-detail-item">
                                <span class="detail-label">${_t('retrievalLogs.messageId')}</span>
                                <code class="detail-value" title="${escapeAttr(_t('retrievalLogs.clickToCopy'))}" data-copy-title-copied="${escapeAttr(_t('common.copied'))}" data-copy-title-click="${escapeAttr(_t('retrievalLogs.clickToCopy'))}" onclick="var el=this; navigator.clipboard.writeText(${escapeJsStringAttr(log.messageId)}).then(function(){ el.title=el.getAttribute('data-copy-title-copied')||el.title; setTimeout(function(){ el.title=el.getAttribute('data-copy-title-click')||el.title; }, 2000); });" style="cursor: pointer;">${escapeHtml(log.messageId)}</code>
                            </div>
                        ` : ''}
                        <div class="retrieval-log-detail-item">
                            <span class="detail-label">${_t('retrievalLogs.retrievalResult')}</span>
                            <span class="detail-value ${hasResults ? 'text-success' : 'text-muted'}">
                                ${hasResults ? (itemCount > 0 ? _t('retrievalLogs.foundCount', { count: itemCount }) : _t('retrievalLogs.foundUnknown')) : _t('retrievalLogs.noMatch')}
                            </span>
                        </div>
                    </div>
                    ${hasResults && log.retrievedItems && log.retrievedItems.length > 0 ? `
                        <div class="retrieval-log-items-preview">
                            <div class="retrieval-log-items-label">${_t('retrievalLogs.retrievedItemsLabel')}</div>
                            <div class="retrieval-log-items-list">
                                ${log.retrievedItems.slice(0, 3).map((itemId, idx) => `
                                    <span class="retrieval-log-item-tag">${idx + 1}</span>
                                `).join('')}
                                ${log.retrievedItems.length > 3 ? `<span class="retrieval-log-item-tag more">+${log.retrievedItems.length - 3}</span>` : ''}
                            </div>
                        </div>
                    ` : ''}
                    <div class="retrieval-log-actions">
                        <button class="btn-secondary btn-sm" onclick="showRetrievalLogDetails(${index})" style="margin-top: 12px; display: inline-flex; align-items: center; gap: 4px;">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                                <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            ${_t('retrievalLogs.viewDetails')}
                        </button>
                        <button class="btn-secondary btn-sm retrieval-log-delete-btn" onclick="deleteRetrievalLog(${escapeJsStringAttr(log.id)}, ${index})" style="margin-top: 12px; margin-left: 8px; display: inline-flex; align-items: center; gap: 4px; color: var(--error-color, #dc3545); border-color: var(--error-color, #dc3545);" onmouseover="this.style.backgroundColor='rgba(220, 53, 69, 0.1)'; this.style.color='#dc3545';" onmouseout="this.style.backgroundColor=''; this.style.color='var(--error-color, #dc3545)';" title="${escapeAttr(_t('common.delete'))}">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            ${_t('common.delete')}
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Update retrieval statistics
function updateRetrievalStats(logs) {
    const statsContainer = document.getElementById('retrieval-stats');
    if (!statsContainer) return;
    
    const totalLogs = logs.length;
    // Determine whether there are results: check the retrievedItems array; after filtering special markers the length is > 0, or it contains a special marker
    const successfulLogs = logs.filter(log => {
        if (!log.retrievedItems) return false;
        if (Array.isArray(log.retrievedItems)) {
            const realItems = log.retrievedItems.filter(id => id !== '_has_results');
            return realItems.length > 0 || log.retrievedItems.includes('_has_results');
        }
        return false;
    }).length;
    // Compute total knowledge items (only real IDs; special markers excluded)
    const totalItems = logs.reduce((sum, log) => {
        if (!log.retrievedItems) return sum;
        if (Array.isArray(log.retrievedItems)) {
            const realItems = log.retrievedItems.filter(id => id !== '_has_results');
            return sum + realItems.length;
        }
        return sum;
    }, 0);
    const successRate = totalLogs > 0 ? ((successfulLogs / totalLogs) * 100).toFixed(1) : 0;
    
    statsContainer.innerHTML = `
        <div class="retrieval-stat-item">
            <span class="retrieval-stat-label" data-i18n="retrievalLogs.totalRetrievals">Total retrievals</span>
            <span class="retrieval-stat-value">${totalLogs}</span>
        </div>
        <div class="retrieval-stat-item">
            <span class="retrieval-stat-label" data-i18n="retrievalLogs.successRetrievals">Successful retrievals</span>
            <span class="retrieval-stat-value text-success">${successfulLogs}</span>
        </div>
        <div class="retrieval-stat-item">
            <span class="retrieval-stat-label" data-i18n="retrievalLogs.successRate">Success rate</span>
            <span class="retrieval-stat-value">${successRate}%</span>
        </div>
        <div class="retrieval-stat-item">
            <span class="retrieval-stat-label" data-i18n="retrievalLogs.retrievedItems">Knowledge items retrieved</span>
            <span class="retrieval-stat-value">${totalItems}</span>
        </div>
    `;
    if (typeof window.applyTranslations === 'function') {
        window.applyTranslations(statsContainer);
    }
}

// Get relative time
function getTimeAgo(timeStr) {
    if (!timeStr) return '';
    
    // Handle time strings, supporting multiple formats
    let date;
    if (typeof timeStr === 'string') {
        // First try direct parsing (supports RFC3339/ISO8601)
        date = new Date(timeStr);
        
        // If parsing fails, try other formats
        if (isNaN(date.getTime())) {
            // SQLite format: "2006-01-02 15:04:05" or with timezone
            const sqliteMatch = timeStr.match(/(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)/);
            if (sqliteMatch) {
                let timeStr2 = sqliteMatch[1].replace(' ', 'T');
                // If there is no timezone info, append Z to denote UTC
                if (!timeStr2.includes('Z') && !timeStr2.match(/[+-]\d{2}:\d{2}$/)) {
                    timeStr2 += 'Z';
                }
                date = new Date(timeStr2);
            }
        }
        
        // If still failing, try a looser format
        if (isNaN(date.getTime())) {
            // Try matching the "YYYY-MM-DD HH:MM:SS" format
            const match = timeStr.match(/(\d{4})-(\d{2})-(\d{2})[\sT](\d{2}):(\d{2}):(\d{2})/);
            if (match) {
                date = new Date(
                    parseInt(match[1]), 
                    parseInt(match[2]) - 1, 
                    parseInt(match[3]),
                    parseInt(match[4]),
                    parseInt(match[5]),
                    parseInt(match[6])
                );
            }
        }
    } else {
        date = new Date(timeStr);
    }
    
    // Check whether the date is valid
    if (isNaN(date.getTime())) {
        return formatTime(timeStr);
    }
    
    // Check whether the date is reasonable (not before 1970, not too far in the future)
    const year = date.getFullYear();
    if (year < 1970 || year > 2100) {
        return formatTime(timeStr);
    }
    
    const now = new Date();
    const diff = now - date;
    
    // If the time difference is negative or too large (possibly a parse error), return the formatted time
    if (diff < 0 || diff > 365 * 24 * 60 * 60 * 1000 * 10) { // more than 10 years is treated as an error
        return formatTime(timeStr);
    }
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} days ago`;
    if (hours > 0) return `${hours} hours ago`;
    if (minutes > 0) return `${minutes} min ago`;
    return 'Just now';
}

// Truncate ID for display
function truncateId(id) {
    if (!id || id.length <= 16) return id;
    return id.substring(0, 8) + '...' + id.substring(id.length - 8);
}

// Filter retrieval logs
function filterRetrievalLogs() {
    const conversationId = document.getElementById('retrieval-logs-conversation-id').value.trim();
    const messageId = document.getElementById('retrieval-logs-message-id').value.trim();
    loadRetrievalLogs(conversationId, messageId);
}

// Refresh retrieval logs
function refreshRetrievalLogs() {
    filterRetrievalLogs();
}

// Delete retrieval log
async function deleteRetrievalLog(id, index) {
    if (!confirm(_t('retrievalLogs.deleteConfirm'))) {
        return;
    }
    
    // Find the log card and delete button to remove
    const logCard = document.querySelector(`.retrieval-log-card[data-index="${index}"]`);
    const deleteButton = logCard ? logCard.querySelector('.retrieval-log-delete-btn') : null;
    let originalButtonOpacity = '';
    let originalButtonDisabled = false;
    
    // Set the delete button loading state
    if (deleteButton) {
        originalButtonOpacity = deleteButton.style.opacity;
        originalButtonDisabled = deleteButton.disabled;
        deleteButton.style.opacity = '0.5';
        deleteButton.style.cursor = 'not-allowed';
        deleteButton.disabled = true;
        
        // Add loading animation
        const svg = deleteButton.querySelector('svg');
        if (svg) {
            svg.style.animation = 'spin 1s linear infinite';
        }
    }
    
    // Immediately remove the item from the UI (optimistic update)
    if (logCard) {
        logCard.style.transition = 'opacity 0.3s ease-out, transform 0.3s ease-out';
        logCard.style.opacity = '0';
        logCard.style.transform = 'translateX(-20px)';
        
        // Remove after the animation completes
        setTimeout(() => {
            if (logCard.parentElement) {
                logCard.remove();
                
                // Update statistics (temporary; will reload later)
                updateRetrievalStatsAfterDelete();
            }
        }, 300);
    }
    
    try {
        const response = await apiFetch(`/api/knowledge/retrieval-logs/${id}`, {
            method: 'DELETE'
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Failed to delete retrieval log');
        }
        
        // Show success notification
        showNotification('✅ Deleted successfully! The retrieval record has been removed from the system.', 'success');
        
        // Remove the item from memory
        if (retrievalLogsData && index >= 0 && index < retrievalLogsData.length) {
            retrievalLogsData.splice(index, 1);
        }
        
        // Reload data to keep it in sync
        const conversationId = document.getElementById('retrieval-logs-conversation-id')?.value.trim() || '';
        const messageId = document.getElementById('retrieval-logs-message-id')?.value.trim() || '';
        await loadRetrievalLogs(conversationId, messageId);
        
    } catch (error) {
        console.error('Failed to delete retrieval log:', error);
        
        // If delete failed, restore the item display
        if (logCard) {
            logCard.style.opacity = '1';
            logCard.style.transform = '';
            logCard.style.transition = '';
        }
        
        // Restore delete button state
        if (deleteButton) {
            deleteButton.style.opacity = originalButtonOpacity || '';
            deleteButton.style.cursor = '';
            deleteButton.disabled = originalButtonDisabled;
            const svg = deleteButton.querySelector('svg');
            if (svg) {
                svg.style.animation = '';
            }
        }
        
        showNotification(_t('retrievalLogs.deleteError') + ': ' + error.message, 'error');
    }
}

// Temporarily update statistics (after delete)
function updateRetrievalStatsAfterDelete() {
    const statsContainer = document.getElementById('retrieval-stats');
    if (!statsContainer) return;
    
    const allLogs = document.querySelectorAll('.retrieval-log-card');
    const totalLogs = allLogs.length;
    
    // Compute successful retrieval count
    const successfulLogs = Array.from(allLogs).filter(card => {
        return card.classList.contains('has-results');
    }).length;
    
    // Compute total knowledge items (simplified; should actually come from the server)
    const totalItems = Array.from(allLogs).reduce((sum, card) => {
        const badge = card.querySelector('.retrieval-log-result-badge');
        if (badge && badge.classList.contains('success')) {
            const text = badge.textContent.trim();
            const match = text.match(/(\d+)/);
            if (match) {
                return sum + parseInt(match[1], 10);
            }
            return sum + 1; // Results exist but count unknown (e.g. "Has results")
        }
        return sum;
    }, 0);
    
    const successRate = totalLogs > 0 ? ((successfulLogs / totalLogs) * 100).toFixed(1) : 0;
    
    statsContainer.innerHTML = `
        <div class="retrieval-stat-item">
            <span class="retrieval-stat-label" data-i18n="retrievalLogs.totalRetrievals">Total retrievals</span>
            <span class="retrieval-stat-value">${totalLogs}</span>
        </div>
        <div class="retrieval-stat-item">
            <span class="retrieval-stat-label" data-i18n="retrievalLogs.successRetrievals">Successful retrievals</span>
            <span class="retrieval-stat-value text-success">${successfulLogs}</span>
        </div>
        <div class="retrieval-stat-item">
            <span class="retrieval-stat-label" data-i18n="retrievalLogs.successRate">Success rate</span>
            <span class="retrieval-stat-value">${successRate}%</span>
        </div>
        <div class="retrieval-stat-item">
            <span class="retrieval-stat-label" data-i18n="retrievalLogs.retrievedItems">Knowledge items retrieved</span>
            <span class="retrieval-stat-value">${totalItems}</span>
        </div>
    `;
    if (typeof window.applyTranslations === 'function') {
        window.applyTranslations(statsContainer);
    }
}

// Show retrieval log details
async function showRetrievalLogDetails(index) {
    if (!retrievalLogsData || index < 0 || index >= retrievalLogsData.length) {
        showNotification(_t('retrievalLogs.detailError'), 'error');
        return;
    }
    
    const log = retrievalLogsData[index];
    
    // Get details of retrieved knowledge items
    let retrievedItemsDetails = [];
    if (log.retrievedItems && Array.isArray(log.retrievedItems)) {
        const realItemIds = log.retrievedItems.filter(id => id !== '_has_results');
        if (realItemIds.length > 0) {
            try {
                // Batch fetch knowledge item details
                const itemPromises = realItemIds.map(async (itemId) => {
                    try {
                        const response = await apiFetch(`/api/knowledge/items/${itemId}`);
                        if (response.ok) {
                            return await response.json();
                        }
                        return null;
                    } catch (err) {
                        console.error(`Failed to get knowledge item ${itemId}:`, err);
                        return null;
                    }
                });
                
                const items = await Promise.all(itemPromises);
                retrievedItemsDetails = items.filter(item => item !== null);
            } catch (err) {
                console.error('Batch fetch of knowledge item details failed:', err);
            }
        }
    }
    
    // Show details modal
    showRetrievalLogDetailsModal(log, retrievedItemsDetails);
}

// Show retrieval log details modal
function showRetrievalLogDetailsModal(log, retrievedItems) {
    // Create or get the modal
    let modal = document.getElementById('retrieval-log-details-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'retrieval-log-details-modal';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 900px; max-height: 90vh; overflow-y: auto;">
                <div class="modal-header">
                    <h2 data-i18n="retrievalLogs.detailsTitle">Retrieval details</h2>
                    <span class="modal-close" onclick="closeRetrievalLogDetailsModal()">&times;</span>
                </div>
                <div class="modal-body" id="retrieval-log-details-content">
                </div>
                <div class="modal-footer">
                    <button class="btn-secondary" onclick="closeRetrievalLogDetailsModal()" data-i18n="common.close">Close</button>
                </div>
            </div>
        `;
        if (typeof window.applyTranslations === 'function') {
            window.applyTranslations(modal);
        }
        document.body.appendChild(modal);
    }
    
    const content = document.getElementById('retrieval-log-details-content');
    if (content) content.innerHTML = '<p style="color:#64748b;margin:0;">…</p>';
    openAppModal(modal, { focus: false });

    deferModalContent(() => {
    const timeAgo = getTimeAgo(log.createdAt);
    const fullTime = formatTime(log.createdAt);
    
    let itemsHtml = '';
    if (retrievedItems.length > 0) {
        itemsHtml = retrievedItems.map((item, idx) => {
            // Extract content preview
            let preview = item.content || '';
            preview = preview.replace(/^#+\s+/gm, '');
            preview = preview.replace(/```[\s\S]*?```/g, '');
            preview = preview.replace(/`[^`]+`/g, '');
            preview = preview.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1');
            preview = preview.replace(/\n+/g, ' ').replace(/\s+/g, ' ').trim();
            const previewText = preview.length > 200 ? preview.substring(0, 200) + '...' : preview;
            
            return `
                <div class="retrieval-detail-item-card" style="margin-bottom: 16px; padding: 16px; border: 1px solid var(--border-color); border-radius: 8px; background: var(--bg-secondary);">
                    <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                        <h4 style="margin: 0; color: var(--text-primary);">${idx + 1}. ${escapeHtml(item.title || _t('retrievalLogs.untitled'))}</h4>
                        <span style="font-size: 0.875rem; color: var(--text-secondary);">${escapeHtml(item.category || _t('retrievalLogs.uncategorized'))}</span>
                    </div>
                    ${item.filePath ? `<div style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 8px;">📁 ${escapeHtml(item.filePath)}</div>` : ''}
                    <div style="font-size: 0.875rem; color: var(--text-secondary); line-height: 1.6;">
                        ${escapeHtml(previewText || _t('retrievalLogs.noContentPreview'))}
                    </div>
                </div>
            `;
        }).join('');
    } else {
        itemsHtml = '<div style="padding: 16px; text-align: center; color: var(--text-muted);">' + _t('retrievalLogs.noItemDetails') + '</div>';
    }
    
    content.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 20px;">
            <div class="retrieval-detail-section">
                <h3 style="margin: 0 0 12px 0; font-size: 1.125rem; color: var(--text-primary);">${_t('retrievalLogs.queryInfo')}</h3>
                <div style="padding: 12px; background: var(--bg-secondary); border-radius: 6px; border-left: 3px solid var(--accent-color);">
                    <div style="font-weight: 500; margin-bottom: 8px; color: var(--text-primary);">${_t('retrievalLogs.queryContent')}</div>
                    <div style="color: var(--text-primary); line-height: 1.6; word-break: break-word;">${escapeHtml(log.query || _t('retrievalLogs.noQuery'))}</div>
                </div>
            </div>
            
            <div class="retrieval-detail-section">
                <h3 style="margin: 0 0 12px 0; font-size: 1.125rem; color: var(--text-primary);">${_t('retrievalLogs.retrievalInfo')}</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                    ${log.riskType ? `
                        <div style="padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
                            <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">${_t('retrievalLogs.riskType')}</div>
                            <div style="font-weight: 500; color: var(--text-primary);">${escapeHtml(log.riskType)}</div>
                        </div>
                    ` : ''}
                    <div style="padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
                        <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">${_t('retrievalLogs.retrievalTime')}</div>
                        <div style="font-weight: 500; color: var(--text-primary);" title="${fullTime}">${timeAgo}</div>
                    </div>
                    <div style="padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
                        <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">${_t('retrievalLogs.retrievalResult')}</div>
                        <div style="font-weight: 500; color: var(--text-primary);">${_t('retrievalLogs.itemsCount', { count: retrievedItems.length })}</div>
                    </div>
                </div>
            </div>
            
            ${log.conversationId || log.messageId ? `
                <div class="retrieval-detail-section">
                    <h3 style="margin: 0 0 12px 0; font-size: 1.125rem; color: var(--text-primary);">${_t('retrievalLogs.relatedInfo')}</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px;">
                        ${log.conversationId ? `
                            <div style="padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
                                <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">${_t('retrievalLogs.conversationId')}</div>
                                <code style="font-size: 0.8125rem; color: var(--text-primary); word-break: break-all; cursor: pointer;" 
                                      onclick="navigator.clipboard.writeText(${escapeJsStringAttr(log.conversationId)}); this.title='Copied!'; setTimeout(() => this.title='Click to copy', 2000);" 
                                      title="Click to copy">${escapeHtml(log.conversationId)}</code>
                            </div>
                        ` : ''}
                        ${log.messageId ? `
                            <div style="padding: 12px; background: var(--bg-secondary); border-radius: 6px;">
                                <div style="font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 4px;">${_t('retrievalLogs.messageId')}</div>
                                <code style="font-size: 0.8125rem; color: var(--text-primary); word-break: break-all; cursor: pointer;" 
                                      onclick="navigator.clipboard.writeText(${escapeJsStringAttr(log.messageId)}); this.title='Copied!'; setTimeout(() => this.title='Click to copy', 2000);" 
                                      title="Click to copy">${escapeHtml(log.messageId)}</code>
                            </div>
                        ` : ''}
                    </div>
                </div>
            ` : ''}
            
            <div class="retrieval-detail-section">
                <h3 style="margin: 0 0 12px 0; font-size: 1.125rem; color: var(--text-primary);">Retrieved knowledge items (${retrievedItems.length})</h3>
                ${itemsHtml}
            </div>
        </div>
    `;
    });
}

// Close retrieval log details modal
function closeRetrievalLogDetailsModal() {
    closeAppModal('retrieval-log-details-modal');
}

// Click outside the modal to close
window.addEventListener('click', function(event) {
    const modal = document.getElementById('retrieval-log-details-modal');
    if (event.target === modal) {
        closeRetrievalLogDetailsModal();
    }
});

// On language switch, re-render the retrieval history list and statistics so dynamic content follows the language; the knowledge page's "disabled" block already uses data-i18n and is updated automatically by applyTranslations(document)
document.addEventListener('languagechange', function () {
    var cur = typeof window.currentPage === 'function' ? window.currentPage() : (window.currentPage || '');
    if (cur === 'knowledge-retrieval-logs') {
        if (retrievalLogsData && retrievalLogsData.length >= 0) {
            renderRetrievalLogs(retrievalLogsData);
        }
    } else if (cur === 'knowledge-management') {
        // For the "knowledge base disabled" state only: it already has data-i18n and applyTranslations handles it; optionally re-apply here once for compatibility with old DOM
        var listEl = document.getElementById('knowledge-items-list');
        if (listEl && typeof window.applyTranslations === 'function') {
            window.applyTranslations(listEl);
        }
    }
});

// Load data on page switch
if (typeof switchPage === 'function') {
    const originalSwitchPage = switchPage;
    window.switchPage = function(page) {
        originalSwitchPage(page);
        
        if (page === 'knowledge-management') {
            loadKnowledgeCategories();
            loadKnowledgeItems(knowledgePagination.currentCategory, 1, knowledgePagination.pageSize);
            updateIndexProgress(); // Update index progress
        } else if (page === 'knowledge-retrieval-logs') {
            loadRetrievalLogs();
            // Stop polling when switching to another page
            if (indexProgressInterval) {
                clearInterval(indexProgressInterval);
                indexProgressInterval = null;
            }
        } else {
            // Stop polling when switching to another page
            if (indexProgressInterval) {
                clearInterval(indexProgressInterval);
                indexProgressInterval = null;
            }
        }
    };
}

// Clear timers on page unload
window.addEventListener('beforeunload', function() {
    if (indexProgressInterval) {
        clearInterval(indexProgressInterval);
        indexProgressInterval = null;
    }
});

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeJsString(text) {
    return JSON.stringify(String(text == null ? '' : text));
}

function escapeAttr(text) {
    return escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function escapeJsStringAttr(text) {
    return escapeAttr(escapeJsString(text));
}

function formatTime(timeStr) {
    if (!timeStr) return '';
    
    // Handle time strings, supporting multiple formats
    let date;
    if (typeof timeStr === 'string') {
        // First try direct parsing (supports RFC3339/ISO8601)
        date = new Date(timeStr);
        
        // If parsing fails, try other formats
        if (isNaN(date.getTime())) {
            // SQLite format: "2006-01-02 15:04:05" or with timezone
            const sqliteMatch = timeStr.match(/(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)/);
            if (sqliteMatch) {
                let timeStr2 = sqliteMatch[1].replace(' ', 'T');
                // If there is no timezone info, append Z to denote UTC
                if (!timeStr2.includes('Z') && !timeStr2.match(/[+-]\d{2}:\d{2}$/)) {
                    timeStr2 += 'Z';
                }
                date = new Date(timeStr2);
            }
        }
        
        // If still failing, try a looser format
        if (isNaN(date.getTime())) {
            // Try matching the "YYYY-MM-DD HH:MM:SS" format
            const match = timeStr.match(/(\d{4})-(\d{2})-(\d{2})[\sT](\d{2}):(\d{2}):(\d{2})/);
            if (match) {
                date = new Date(
                    parseInt(match[1]), 
                    parseInt(match[2]) - 1, 
                    parseInt(match[3]),
                    parseInt(match[4]),
                    parseInt(match[5]),
                    parseInt(match[6])
                );
            }
        }
    } else {
        date = new Date(timeStr);
    }
    
    // If the date is invalid, check whether it is a zero-value time
    if (isNaN(date.getTime())) {
        // Check whether it is the string form of a zero-value time
        if (typeof timeStr === 'string' && (timeStr.includes('0001-01-01') || timeStr.startsWith('0001'))) {
            return '';
        }
        console.warn('Unable to parse time:', timeStr);
        return '';
    }
    
    // Check whether the date is reasonable (not before 1970, not too far in the future)
    const year = date.getFullYear();
    if (year < 1970 || year > 2100) {
        // If it is a zero-value time (0001-01-01), return an empty string and display nothing
        if (year === 1) {
            return '';
        }
        console.warn('Time value is unreasonable:', timeStr, 'parsed as:', date);
        return '';
    }
    
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

// Show notification
function showNotification(message, type = 'info') {
    // If a global notification system exists (and is not this function), use it
    if (typeof window.showNotification === 'function' && window.showNotification !== showNotification) {
        window.showNotification(message, type);
        return;
    }
    
    // Otherwise use the custom toast notification
    showToastNotification(message, type);
}

// Show toast notification
function showToastNotification(message, type = 'info') {
    // Create notification container (if it does not exist)
    let container = document.getElementById('toast-notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-notification-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10100;
            display: flex;
            flex-direction: column;
            gap: 12px;
            pointer-events: none;
        `;
        document.body.appendChild(container);
    }
    
    // Create notification element
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;
    
    const typeStyles = {
        success: {
            background: '#f4fbf6',
            border: '1px solid #cce8d4',
            color: '#3d6654',
            iconColor: '#52a06a',
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.2"/><path d="M5 8l2 2 4-4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>'
        },
        error: {
            background: '#fef7f7',
            border: '1px solid #f3d0d0',
            color: '#8b4444',
            iconColor: '#c96a6a',
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.2"/><path d="M6 6l4 4M10 6l-4 4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>'
        },
        info: {
            background: '#f5f9ff',
            border: '1px solid #cfe0f5',
            color: '#4a6078',
            iconColor: '#6b8fbf',
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.2"/><path d="M8 7v4M8 5.5v.01" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>'
        },
        warning: {
            background: '#fffbf3',
            border: '1px solid #f0dfc0',
            color: '#7a6535',
            iconColor: '#c4a04a',
            icon: '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 2.5l6 10.5H2L8 2.5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/><path d="M8 7v2.5M8 11v.01" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>'
        }
    };

    const style = typeStyles[type] || typeStyles.info;

    toast.style.cssText = `
        background: ${style.background};
        border: ${style.border};
        color: ${style.color};
        padding: 10px 14px;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(15, 23, 42, 0.06);
        min-width: 220px;
        max-width: 420px;
        pointer-events: auto;
        animation: slideInRight 0.25s ease-out;
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 0.875rem;
        line-height: 1.45;
        word-wrap: break-word;
        backdrop-filter: none;
        -webkit-backdrop-filter: none;
    `;

    toast.innerHTML = `
        <span style="color: ${style.iconColor}; flex-shrink: 0; display: flex; align-items: center;">${style.icon}</span>
        <span style="flex: 1;">${escapeHtml(message)}</span>
        <button onclick="this.parentElement.remove()" style="
            background: transparent;
            border: none;
            color: ${style.color};
            cursor: pointer;
            font-size: 1rem;
            padding: 0;
            margin-left: 4px;
            opacity: 0.45;
            flex-shrink: 0;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        " onmouseover="this.style.opacity='0.75'" onmouseout="this.style.opacity='0.45'">×</button>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove (success messages show for 5 seconds, errors for 7 seconds, others for 4 seconds)
    const duration = type === 'success' ? 5000 : type === 'error' ? 7000 : 4000;
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.animation = 'slideOutRight 0.3s ease-out';
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 300);
        }
    }, duration);
}

// Add CSS animation (if it does not exist)
if (!document.getElementById('toast-notification-styles')) {
    const style = document.createElement('style');
    style.id = 'toast-notification-styles';
    style.textContent = `
        @keyframes slideInRight {
            from {
                transform: translateX(16px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        @keyframes slideOutRight {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(16px);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);
}

// Click outside the modal to close
window.addEventListener('click', function(event) {
    const modal = document.getElementById('knowledge-item-modal');
    if (event.target === modal) {
        closeKnowledgeItemModal();
    }
});

// Switch to settings page (used for the disabled-feature notice)
function switchToSettings() {
    if (typeof switchPage === 'function') {
        switchPage('settings');
        // Wait for the settings page to load, then switch to the knowledge base config section
        setTimeout(() => {
            if (typeof switchSettingsSection === 'function') {
                // Find the knowledge base config section (usually in basic settings)
                const knowledgeSection = document.querySelector('[data-section="knowledge"]');
                if (knowledgeSection) {
                    switchSettingsSection('knowledge');
                } else {
                    // If there is no separate knowledge base section, switch to basic settings
                    switchSettingsSection('basic');
                    // Scroll to the knowledge base config area
                    setTimeout(() => {
                        const knowledgeEnabledCheckbox = document.getElementById('knowledge-enabled');
                        if (knowledgeEnabledCheckbox) {
                            knowledgeEnabledCheckbox.scrollIntoView({ behavior: 'smooth', block: 'center' });
                            // Highlight
                            knowledgeEnabledCheckbox.parentElement.style.transition = 'background-color 0.3s';
                            knowledgeEnabledCheckbox.parentElement.style.backgroundColor = '#e3f2fd';
                            setTimeout(() => {
                                knowledgeEnabledCheckbox.parentElement.style.backgroundColor = '';
                            }, 2000);
                        }
                    }, 300);
                }
            }
        }, 100);
    }
}

// Custom dropdown component interaction
document.addEventListener('DOMContentLoaded', function() {
    const wrapper = document.getElementById('knowledge-category-filter-wrapper');
    const trigger = document.getElementById('knowledge-category-filter-trigger');
    
    if (wrapper && trigger) {
        // Click the trigger to open/close the dropdown
        trigger.addEventListener('click', function(e) {
            e.stopPropagation();
            wrapper.classList.toggle('open');
        });
        
        // Click outside to close the dropdown
        document.addEventListener('click', function(e) {
            if (!wrapper.contains(e.target)) {
                wrapper.classList.remove('open');
            }
        });
        
        // Update selected state when an option is chosen
        const dropdown = document.getElementById('knowledge-category-filter-dropdown');
        if (dropdown) {
            // Select the "All" option by default
            const defaultOption = dropdown.querySelector('.custom-select-option[data-value=""]');
            if (defaultOption) {
                defaultOption.classList.add('selected');
            }
            
            dropdown.addEventListener('click', function(e) {
                const option = e.target.closest('.custom-select-option');
                if (option) {
                    // Remove previous selected state
                    dropdown.querySelectorAll('.custom-select-option').forEach(opt => {
                        opt.classList.remove('selected');
                    });
                    // Add selected state
                    option.classList.add('selected');
                }
            });
        }
    }
});
