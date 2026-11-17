package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"veritysec/internal/audit"
	"veritysec/internal/database"
	"veritysec/internal/knowledge"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// KnowledgeHandler is the knowledge base handler
type KnowledgeHandler struct {
	manager   *knowledge.Manager
	retriever *knowledge.Retriever
	indexer   *knowledge.Indexer
	db        *database.DB
	logger    *zap.Logger
	audit     *audit.Service
}

// SetAudit wires platform audit logging.
func (h *KnowledgeHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

// NewKnowledgeHandler creates a new knowledge base handler
func NewKnowledgeHandler(
	manager *knowledge.Manager,
	retriever *knowledge.Retriever,
	indexer *knowledge.Indexer,
	db *database.DB,
	logger *zap.Logger,
) *KnowledgeHandler {
	return &KnowledgeHandler{
		manager:   manager,
		retriever: retriever,
		indexer:   indexer,
		db:        db,
		logger:    logger,
	}
}

// GetCategories gets all categories
func (h *KnowledgeHandler) GetCategories(c *gin.Context) {
	categories, err := h.manager.GetCategories()
	if err != nil {
		h.logger.Error("failed to get categories", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

// GetItems gets the knowledge item list (supports category pagination and keyword search; full content is not returned by default)
func (h *KnowledgeHandler) GetItems(c *gin.Context) {
	category := c.Query("category")
	searchKeyword := c.Query("search") // search keyword

	// If a search keyword is provided, perform keyword search (across all data)
	if searchKeyword != "" {
		items, err := h.manager.SearchItemsByKeyword(searchKeyword, category)
		if err != nil {
			h.logger.Error("failed to search knowledge items", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Group results by category
		groupedByCategory := make(map[string][]*knowledge.KnowledgeItemSummary)
		for _, item := range items {
			cat := item.Category
			if cat == "" {
				cat = "uncategorized"
			}
			groupedByCategory[cat] = append(groupedByCategory[cat], item)
		}

		// Convert to CategoryWithItems format
		categoriesWithItems := make([]*knowledge.CategoryWithItems, 0, len(groupedByCategory))
		for cat, catItems := range groupedByCategory {
			categoriesWithItems = append(categoriesWithItems, &knowledge.CategoryWithItems{
				Category:  cat,
				ItemCount: len(catItems),
				Items:     catItems,
			})
		}

		// Sort by category name
		for i := 0; i < len(categoriesWithItems)-1; i++ {
			for j := i + 1; j < len(categoriesWithItems); j++ {
				if categoriesWithItems[i].Category > categoriesWithItems[j].Category {
					categoriesWithItems[i], categoriesWithItems[j] = categoriesWithItems[j], categoriesWithItems[i]
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"categories": categoriesWithItems,
			"total":      len(categoriesWithItems),
			"search":     searchKeyword,
			"is_search":  true,
		})
		return
	}

	// Pagination mode: categoryPage=true means paginate by category, otherwise by item (backward compatible)
	categoryPageMode := c.Query("categoryPage") != "false" // category pagination by default

	// Pagination parameters
	limit := 50 // default 50 per page (number of categories in category pagination, number of items in item pagination)
	offset := 0
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := parseInt(limitStr); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsed, err := parseInt(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// If the category parameter is specified in category pagination mode, return only that category
	if category != "" && categoryPageMode {
		// Single-category mode: return all knowledge items in that category (no pagination)
		items, total, err := h.manager.GetItemsSummary(category, 0, 0)
		if err != nil {
			h.logger.Error("failed to get knowledge items", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Wrap into category structure
		categoriesWithItems := []*knowledge.CategoryWithItems{
			{
				Category:  category,
				ItemCount: total,
				Items:     items,
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"categories": categoriesWithItems,
			"total":      1, // only one category
			"limit":      limit,
			"offset":     offset,
		})
		return
	}

	if categoryPageMode {
		// Category pagination mode (default)
		// limit is the number of categories per page; 5-10 categories recommended
		if limit <= 0 || limit > 100 {
			limit = 10 // default 10 categories per page
		}

		categoriesWithItems, totalCategories, err := h.manager.GetCategoriesWithItems(limit, offset)
		if err != nil {
			h.logger.Error("failed to get category knowledge items", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"categories": categoriesWithItems,
			"total":      totalCategories,
			"limit":      limit,
			"offset":     offset,
		})
		return
	}

	// Item pagination mode (backward compatible)
	// whether to include full content (default false; only summaries are returned)
	includeContent := c.Query("includeContent") == "true"

	if includeContent {
		// Return full content (backward compatible)
		items, err := h.manager.GetItemsWithOptions(category, limit, offset, true)
		if err != nil {
			h.logger.Error("failed to get knowledge items", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Get total count
		total, err := h.manager.GetItemsCount(category)
		if err != nil {
			h.logger.Warn("failed to get total knowledge item count", zap.Error(err))
			total = len(items)
		}

		c.JSON(http.StatusOK, gin.H{
			"items":  items,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
	} else {
		// Return summaries (without full content; recommended)
		items, total, err := h.manager.GetItemsSummary(category, limit, offset)
		if err != nil {
			h.logger.Error("failed to get knowledge items", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"items":  items,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
	}
}

// GetItem gets a single knowledge item
func (h *KnowledgeHandler) GetItem(c *gin.Context) {
	id := c.Param("id")

	item, err := h.manager.GetItem(id)
	if err != nil {
		h.logger.Error("failed to get knowledge items", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, item)
}

// CreateItem creates a knowledge item
func (h *KnowledgeHandler) CreateItem(c *gin.Context) {
	var req struct {
		Category string `json:"category" binding:"required"`
		Title    string `json:"title" binding:"required"`
		Content  string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	item, err := h.manager.CreateItem(req.Category, req.Title, req.Content)
	if err != nil {
		h.logger.Error("failed to create knowledge item", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Asynchronous indexing
	go func() {
		ctx := context.Background()
		if err := h.indexer.IndexItem(ctx, item.ID); err != nil {
			h.logger.Warn("failed to index knowledge item", zap.String("itemId", item.ID), zap.Error(err))
		}
	}()

	c.JSON(http.StatusOK, item)
}

// UpdateItem updates a knowledge item
func (h *KnowledgeHandler) UpdateItem(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Category string `json:"category" binding:"required"`
		Title    string `json:"title" binding:"required"`
		Content  string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	item, err := h.manager.UpdateItem(id, req.Category, req.Title, req.Content)
	if err != nil {
		h.logger.Error("failed to update knowledge item", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Asynchronous re-indexing
	go func() {
		ctx := context.Background()
		if err := h.indexer.IndexItem(ctx, item.ID); err != nil {
			h.logger.Warn("failed to re-index knowledge item", zap.String("itemId", item.ID), zap.Error(err))
		}
	}()

	c.JSON(http.StatusOK, item)
}

// DeleteItem deletes a knowledge item
func (h *KnowledgeHandler) DeleteItem(c *gin.Context) {
	id := c.Param("id")

	if err := h.manager.DeleteItem(id); err != nil {
		h.logger.Error("failed to delete knowledge item", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if h.audit != nil {
		h.audit.RecordOK(c, "knowledge", "item_delete", "deleted knowledge item", "knowledge_item", id, nil)
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted successfully"})
}

// StartIndex builds the knowledge base vector index. By default only fills in knowledge items without vectors; mode=full rebuilds everything.
func (h *KnowledgeHandler) StartIndex(c *gin.Context) {
	if err := h.indexer.TryBeginIndexRun(); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "an indexing task is already in progress; please wait for it to complete"})
		return
	}

	mode := strings.TrimSpace(c.Query("mode"))
	if mode == "" {
		mode = "missing"
	}
	if mode != "full" && mode != "missing" {
		h.indexer.FinishIndexRun()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mode parameter; allowed values: missing, full"})
		return
	}

	fullRebuild := mode == "full"
	message := "index build started; it will run in the background"
	auditAction := "index_build"
	auditDetail := "build knowledge base index"
	if fullRebuild {
		message = "full index rebuild started; it will run in the background"
		auditAction = "index_rebuild_full"
		auditDetail = "full rebuild of knowledge base index"
	}

	go func() {
		defer h.indexer.FinishIndexRun()
		ctx := context.Background()
		var err error
		if fullRebuild {
			err = h.indexer.RunRebuildIndex(ctx)
		} else {
			err = h.indexer.RunIndexMissing(ctx)
		}
		if err != nil {
			if fullRebuild {
				h.logger.Error("failed to rebuild the full index", zap.Error(err))
			} else {
				h.logger.Error("failed to build knowledge base index", zap.Error(err))
			}
		}
	}()

	if h.audit != nil {
		h.audit.RecordOK(c, "knowledge", auditAction, auditDetail, "knowledge", "", nil)
	}
	c.JSON(http.StatusOK, gin.H{"message": message, "mode": mode})
}

// ScanKnowledgeBase scans the knowledge base
func (h *KnowledgeHandler) ScanKnowledgeBase(c *gin.Context) {
	itemsToIndex, err := h.manager.ScanKnowledgeBase()
	if err != nil {
		h.logger.Error("failed to scan knowledge base", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if len(itemsToIndex) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "scan completed; no new or updated items need indexing"})
		return
	}

	// Asynchronously index newly added or updated items (incremental indexing)
	go func() {
		ctx := context.Background()
		h.logger.Info("starting incremental indexing", zap.Int("count", len(itemsToIndex)))
		failedCount := 0
		consecutiveFailures := 0
		var firstFailureItemID string
		var firstFailureError error

		for i, itemID := range itemsToIndex {
			if err := h.indexer.IndexItem(ctx, itemID); err != nil {
				failedCount++
				consecutiveFailures++

				// Log details only for the first failure
				if consecutiveFailures == 1 {
					firstFailureItemID = itemID
					firstFailureError = err
					h.logger.Warn("failed to index knowledge item",
						zap.String("itemId", itemID),
						zap.Int("totalItems", len(itemsToIndex)),
						zap.Error(err),
					)
				}

				// Stop incremental indexing immediately after 2 consecutive failures
				if consecutiveFailures >= 2 {
					h.logger.Error("too many consecutive indexing failures; stopping incremental indexing immediately",
						zap.Int("consecutiveFailures", consecutiveFailures),
						zap.Int("totalItems", len(itemsToIndex)),
						zap.Int("processedItems", i+1),
						zap.String("firstFailureItemId", firstFailureItemID),
						zap.Error(firstFailureError),
					)
					break
				}
				continue
			}

			// Reset the consecutive failure count on success
			if consecutiveFailures > 0 {
				consecutiveFailures = 0
				firstFailureItemID = ""
				firstFailureError = nil
			}

			// Reduce the frequency of progress logs
			if (i+1)%10 == 0 || i+1 == len(itemsToIndex) {
				h.logger.Info("indexing progress", zap.Int("current", i+1), zap.Int("total", len(itemsToIndex)), zap.Int("failed", failedCount))
			}
		}
		h.logger.Info("incremental indexing completed", zap.Int("totalItems", len(itemsToIndex)), zap.Int("failedCount", failedCount))
	}()

	c.JSON(http.StatusOK, gin.H{
		"message":        fmt.Sprintf("scan completed; indexing %d newly added or updated knowledge items", len(itemsToIndex)),
		"items_to_index": len(itemsToIndex),
	})
}

// GetRetrievalLogs gets retrieval logs
func (h *KnowledgeHandler) GetRetrievalLogs(c *gin.Context) {
	conversationID := c.Query("conversationId")
	messageID := c.Query("messageId")
	limit := 50 // default 50 items

	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := parseInt(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	logs, err := h.manager.GetRetrievalLogs(conversationID, messageID, limit)
	if err != nil {
		h.logger.Error("failed to get retrieval logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// DeleteRetrievalLog deletes a retrieval log
func (h *KnowledgeHandler) DeleteRetrievalLog(c *gin.Context) {
	id := c.Param("id")

	if err := h.manager.DeleteRetrievalLog(id); err != nil {
		h.logger.Error("failed to delete retrieval log", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "deleted successfully"})
}

// GetIndexStatus gets the index status
func (h *KnowledgeHandler) GetIndexStatus(c *gin.Context) {
	status, err := h.manager.GetIndexStatus()
	if err != nil {
		h.logger.Error("failed to get index status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Get the indexer error info
	if h.indexer != nil {
		lastError, lastErrorTime := h.indexer.GetLastError()
		// Keep a failed operation visible until the indexer clears it for the next run.
		appendKnowledgeIndexError(status, lastError, lastErrorTime)

		// Get rebuild status
		isRebuilding, totalItems, current, failed, lastItemID, lastChunks, startTime := h.indexer.GetRebuildStatus()
		if isRebuilding {
			status["is_rebuilding"] = true
			status["rebuild_total"] = totalItems
			status["rebuild_current"] = current
			status["rebuild_failed"] = failed
			status["rebuild_start_time"] = startTime.Format(time.RFC3339)
			if lastItemID != "" {
				status["rebuild_last_item_id"] = lastItemID
			}
			if lastChunks > 0 {
				status["rebuild_last_chunks"] = lastChunks
			}
			// while rebuilding, is_complete is false
			status["is_complete"] = false
			// compute rebuild progress percentage
			if totalItems > 0 {
				status["progress_percent"] = float64(current) / float64(totalItems) * 100
			}
		}
	}

	c.JSON(http.StatusOK, status)
}

// Search searches the knowledge base (for API calls; the Agent internally uses Retriever)
func (h *KnowledgeHandler) Search(c *gin.Context) {
	var req knowledge.SearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Retriever.Search goes through Eino VectorEinoRetriever, consistent with the MCP tool chain.
	results, err := h.retriever.Search(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("failed to search knowledge base", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// GetStats gets knowledge base statistics
func (h *KnowledgeHandler) GetStats(c *gin.Context) {
	totalCategories, totalItems, err := h.manager.GetStats()
	if err != nil {
		h.logger.Error("failed to get knowledge base statistics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":          true,
		"total_categories": totalCategories,
		"total_items":      totalItems,
	})
}

// Helper function: parse integer
func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

func appendKnowledgeIndexError(status map[string]interface{}, message string, occurredAt time.Time) {
	if message == "" {
		return
	}
	status["last_error"] = message
	status["last_error_time"] = occurredAt.Format(time.RFC3339)
}
