package knowledge

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Manager knowledge base manager
type Manager struct {
	db       *sql.DB
	basePath string
	logger   *zap.Logger
}

// NewManager creates a new knowledge base manager
func NewManager(db *sql.DB, basePath string, logger *zap.Logger) *Manager {
	return &Manager{
		db:       db,
		basePath: basePath,
		logger:   logger,
	}
}

// ScanKnowledgeBase scans the knowledge base directory and updates the database
// returns the list of knowledge item IDs that need indexing (newly added or updated)
func (m *Manager) ScanKnowledgeBase() ([]string, error) {
	if m.basePath == "" {
		return nil, fmt.Errorf("knowledge base path is not configured")
	}

	// ensure the directory exists
	if err := os.MkdirAll(m.basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create knowledge base directory: %w", err)
	}

	var itemsToIndex []string

	// walk the knowledge base directory
	err := filepath.WalkDir(m.basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// skip directories and non-markdown files
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".md") {
			return nil
		}

		// compute the relative path and category
		relPath, err := filepath.Rel(m.basePath, path)
		if err != nil {
			return err
		}

		// use the first directory name as the category (risk type)
		parts := strings.Split(relPath, string(filepath.Separator))
		category := "uncategorized"
		if len(parts) > 1 {
			category = parts[0]
		}

		// use the file name as the title
		title := strings.TrimSuffix(filepath.Base(path), ".md")

		// read file content
		content, err := os.ReadFile(path)
		if err != nil {
			m.logger.Warn("failed to read knowledge base file", zap.String("path", path), zap.Error(err))
			return nil // continue processing other files
		}

		// check whether it already exists
		var existingID string
		var existingContent string
		var existingUpdatedAt time.Time
		err = m.db.QueryRow(
			"SELECT id, content, updated_at FROM knowledge_base_items WHERE file_path = ?",
			path,
		).Scan(&existingID, &existingContent, &existingUpdatedAt)

		if err == sql.ErrNoRows {
			// create a new item
			id := uuid.New().String()
			now := time.Now()
			_, err = m.db.Exec(
				"INSERT INTO knowledge_base_items (id, category, title, file_path, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
				id, category, title, path, string(content), now, now,
			)
			if err != nil {
				return fmt.Errorf("failed to insert knowledge item: %w", err)
			}
			m.logger.Info("added knowledge item", zap.String("id", id), zap.String("title", title), zap.String("category", category))
			// newly added items need indexing
			itemsToIndex = append(itemsToIndex, id)
		} else if err == nil {
			// check whether the content has changed
			contentChanged := existingContent != string(content)
			if contentChanged {
				// update the existing item
				_, err = m.db.Exec(
					"UPDATE knowledge_base_items SET category = ?, title = ?, content = ?, updated_at = ? WHERE id = ?",
					category, title, string(content), time.Now(), existingID,
				)
				if err != nil {
					return fmt.Errorf("failed to update knowledge item: %w", err)
				}
				m.logger.Info("updated knowledge item", zap.String("id", existingID), zap.String("title", title))
				// items with updated content need re-indexing
				itemsToIndex = append(itemsToIndex, existingID)
			} else {
				m.logger.Debug("knowledge item unchanged, skipping", zap.String("id", existingID), zap.String("title", title))
			}
		} else {
			return fmt.Errorf("failed to query knowledge item: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return itemsToIndex, nil
}

// GetCategories gets all categories (risk types)
func (m *Manager) GetCategories() ([]string, error) {
	rows, err := m.db.Query("SELECT DISTINCT category FROM knowledge_base_items ORDER BY category")
	if err != nil {
		return nil, fmt.Errorf("failed to query categories: %w", err)
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			return nil, fmt.Errorf("failed to scan category: %w", err)
		}
		categories = append(categories, category)
	}

	return categories, nil
}

// GetStats gets knowledge base statistics
func (m *Manager) GetStats() (int, int, error) {
	// get total category count
	categories, err := m.GetCategories()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get categories: %w", err)
	}
	totalCategories := len(categories)

	// get total knowledge item count
	var totalItems int
	err = m.db.QueryRow("SELECT COUNT(*) FROM knowledge_base_items").Scan(&totalItems)
	if err != nil {
		return totalCategories, 0, fmt.Errorf("failed to get total knowledge item count: %w", err)
	}

	return totalCategories, totalItems, nil
}

// GetCategoriesWithItems gets knowledge items paginated by category (each category contains all its knowledge items)
// limit: number of categories per page (0 = unlimited)
// offset: offset (by category)
func (m *Manager) GetCategoriesWithItems(limit, offset int) ([]*CategoryWithItems, int, error) {
	// first get all categories (with count statistics)
	rows, err := m.db.Query(`
		SELECT category, COUNT(*) as item_count 
		FROM knowledge_base_items 
		GROUP BY category 
		ORDER BY category
	`)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query categories: %w", err)
	}
	defer rows.Close()

	// collect all category information
	type categoryInfo struct {
		name      string
		itemCount int
	}
	var allCategories []categoryInfo
	for rows.Next() {
		var info categoryInfo
		if err := rows.Scan(&info.name, &info.itemCount); err != nil {
			return nil, 0, fmt.Errorf("failed to scan category: %w", err)
		}
		allCategories = append(allCategories, info)
	}

	totalCategories := len(allCategories)

	// apply pagination (by category)
	var paginatedCategories []categoryInfo
	if limit > 0 {
		start := offset
		end := offset + limit
		if start >= totalCategories {
			paginatedCategories = []categoryInfo{}
		} else {
			if end > totalCategories {
				end = totalCategories
			}
			paginatedCategories = allCategories[start:end]
		}
	} else {
		paginatedCategories = allCategories
	}

	// for each category, get its knowledge items (summaries only, without full content)
	result := make([]*CategoryWithItems, 0, len(paginatedCategories))
	for _, catInfo := range paginatedCategories {
		// get all knowledge items under this category
		items, _, err := m.GetItemsSummary(catInfo.name, 0, 0)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get knowledge items for category %s: %w", catInfo.name, err)
		}

		result = append(result, &CategoryWithItems{
			Category:  catInfo.name,
			ItemCount: catInfo.itemCount,
			Items:     items,
		})
	}

	return result, totalCategories, nil
}

// GetItems gets the knowledge item list (full content; kept for backward compatibility)
func (m *Manager) GetItems(category string) ([]*KnowledgeItem, error) {
	return m.GetItemsWithOptions(category, 0, 0, true)
}

// GetItemsWithOptions gets the knowledge item list (supports pagination and optional content)
// category: category filter (empty string = all categories)
// limit: items per page (0 = unlimited)
// offset: offset
// includeContent: whether to include full content (false returns summaries only)
func (m *Manager) GetItemsWithOptions(category string, limit, offset int, includeContent bool) ([]*KnowledgeItem, error) {
	var rows *sql.Rows
	var err error

	// build the SQL query
	var query string
	var args []interface{}

	if includeContent {
		query = "SELECT id, category, title, file_path, content, created_at, updated_at FROM knowledge_base_items"
	} else {
		query = "SELECT id, category, title, file_path, created_at, updated_at FROM knowledge_base_items"
	}

	if category != "" {
		query += " WHERE category = ?"
		args = append(args, category)
	}

	query += " ORDER BY category, title"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
		if offset > 0 {
			query += " OFFSET ?"
			args = append(args, offset)
		}
	}

	rows, err = m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query knowledge item: %w", err)
	}
	defer rows.Close()

	var items []*KnowledgeItem
	for rows.Next() {
		item := &KnowledgeItem{}
		var createdAt, updatedAt string

		if includeContent {
			if err := rows.Scan(&item.ID, &item.Category, &item.Title, &item.FilePath, &item.Content, &createdAt, &updatedAt); err != nil {
				return nil, fmt.Errorf("failed to scan knowledge item: %w", err)
			}
		} else {
			if err := rows.Scan(&item.ID, &item.Category, &item.Title, &item.FilePath, &createdAt, &updatedAt); err != nil {
				return nil, fmt.Errorf("failed to scan knowledge item: %w", err)
			}
			// when content is not included, Content is an empty string
			item.Content = ""
		}

		// parse time - supports multiple formats
		timeFormats := []string{
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
			time.RFC3339,
			time.RFC3339Nano,
		}

		// parse creation time
		if createdAt != "" {
			for _, format := range timeFormats {
				parsed, err := time.Parse(format, createdAt)
				if err == nil && !parsed.IsZero() {
					item.CreatedAt = parsed
					break
				}
			}
		}

		// parse update time
		if updatedAt != "" {
			for _, format := range timeFormats {
				parsed, err := time.Parse(format, updatedAt)
				if err == nil && !parsed.IsZero() {
					item.UpdatedAt = parsed
					break
				}
			}
		}

		// if the update time is empty, use the creation time
		if item.UpdatedAt.IsZero() && !item.CreatedAt.IsZero() {
			item.UpdatedAt = item.CreatedAt
		}

		items = append(items, item)
	}

	return items, nil
}

// GetItemsCount gets the total knowledge item count
func (m *Manager) GetItemsCount(category string) (int, error) {
	var count int
	var err error

	if category != "" {
		err = m.db.QueryRow("SELECT COUNT(*) FROM knowledge_base_items WHERE category = ?", category).Scan(&count)
	} else {
		err = m.db.QueryRow("SELECT COUNT(*) FROM knowledge_base_items").Scan(&count)
	}

	if err != nil {
		return 0, fmt.Errorf("failed to query total knowledge item count: %w", err)
	}

	return count, nil
}

// SearchItemsByKeyword searches knowledge items by keyword (across all data; matches title, category, path, and content)
func (m *Manager) SearchItemsByKeyword(keyword string, category string) ([]*KnowledgeItemSummary, error) {
	if keyword == "" {
		return nil, fmt.Errorf("search keyword cannot be empty")
	}

	// build SQL query, using LIKE for keyword matching (case-insensitive)
	var query string
	var args []interface{}

	// SQLite's LIKE is case-insensitive; COLLATE NOCASE or LOWER() is used
	// fuzzy match with %keyword%
	searchPattern := "%" + keyword + "%"

	query = `
		SELECT id, category, title, file_path, created_at, updated_at 
		FROM knowledge_base_items 
		WHERE (LOWER(title) LIKE LOWER(?) OR LOWER(category) LIKE LOWER(?) OR LOWER(file_path) LIKE LOWER(?) OR LOWER(content) LIKE LOWER(?))
	`
	args = append(args, searchPattern, searchPattern, searchPattern, searchPattern)

	// if a category is specified, add a category filter
	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}

	query += " ORDER BY category, title"

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to search knowledge items: %w", err)
	}
	defer rows.Close()

	var items []*KnowledgeItemSummary
	for rows.Next() {
		item := &KnowledgeItemSummary{}
		var createdAt, updatedAt string

		if err := rows.Scan(&item.ID, &item.Category, &item.Title, &item.FilePath, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan knowledge item: %w", err)
		}

		// parse time
		timeFormats := []string{
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
			time.RFC3339,
			time.RFC3339Nano,
		}

		if createdAt != "" {
			for _, format := range timeFormats {
				parsed, err := time.Parse(format, createdAt)
				if err == nil && !parsed.IsZero() {
					item.CreatedAt = parsed
					break
				}
			}
		}

		if updatedAt != "" {
			for _, format := range timeFormats {
				parsed, err := time.Parse(format, updatedAt)
				if err == nil && !parsed.IsZero() {
					item.UpdatedAt = parsed
					break
				}
			}
		}

		if item.UpdatedAt.IsZero() && !item.CreatedAt.IsZero() {
			item.UpdatedAt = item.CreatedAt
		}

		items = append(items, item)
	}

	return items, nil
}

// GetItemsSummary gets knowledge item summaries (without full content; supports pagination)
func (m *Manager) GetItemsSummary(category string, limit, offset int) ([]*KnowledgeItemSummary, int, error) {
	// get total count
	total, err := m.GetItemsCount(category)
	if err != nil {
		return nil, 0, err
	}

	// get list data (without content)
	var rows *sql.Rows
	var query string
	var args []interface{}

	query = "SELECT id, category, title, file_path, created_at, updated_at FROM knowledge_base_items"

	if category != "" {
		query += " WHERE category = ?"
		args = append(args, category)
	}

	query += " ORDER BY category, title"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
		if offset > 0 {
			query += " OFFSET ?"
			args = append(args, offset)
		}
	}

	rows, err = m.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query knowledge item: %w", err)
	}
	defer rows.Close()

	var items []*KnowledgeItemSummary
	for rows.Next() {
		item := &KnowledgeItemSummary{}
		var createdAt, updatedAt string

		if err := rows.Scan(&item.ID, &item.Category, &item.Title, &item.FilePath, &createdAt, &updatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan knowledge item: %w", err)
		}

		// parse time
		timeFormats := []string{
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
			time.RFC3339,
			time.RFC3339Nano,
		}

		if createdAt != "" {
			for _, format := range timeFormats {
				parsed, err := time.Parse(format, createdAt)
				if err == nil && !parsed.IsZero() {
					item.CreatedAt = parsed
					break
				}
			}
		}

		if updatedAt != "" {
			for _, format := range timeFormats {
				parsed, err := time.Parse(format, updatedAt)
				if err == nil && !parsed.IsZero() {
					item.UpdatedAt = parsed
					break
				}
			}
		}

		if item.UpdatedAt.IsZero() && !item.CreatedAt.IsZero() {
			item.UpdatedAt = item.CreatedAt
		}

		items = append(items, item)
	}

	return items, total, nil
}

// GetItem gets a single knowledge item
func (m *Manager) GetItem(id string) (*KnowledgeItem, error) {
	item := &KnowledgeItem{}
	var createdAt, updatedAt string
	err := m.db.QueryRow(
		"SELECT id, category, title, file_path, content, created_at, updated_at FROM knowledge_base_items WHERE id = ?",
		id,
	).Scan(&item.ID, &item.Category, &item.Title, &item.FilePath, &item.Content, &createdAt, &updatedAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("knowledge item does not exist")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query knowledge item: %w", err)
	}

	// parse time - supports multiple formats
	timeFormats := []string{
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	}

	// parse creation time
	if createdAt != "" {
		for _, format := range timeFormats {
			parsed, err := time.Parse(format, createdAt)
			if err == nil && !parsed.IsZero() {
				item.CreatedAt = parsed
				break
			}
		}
	}

	// parse update time
	if updatedAt != "" {
		for _, format := range timeFormats {
			parsed, err := time.Parse(format, updatedAt)
			if err == nil && !parsed.IsZero() {
				item.UpdatedAt = parsed
				break
			}
		}
	}

	// if the update time is empty, use the creation time
	if item.UpdatedAt.IsZero() && !item.CreatedAt.IsZero() {
		item.UpdatedAt = item.CreatedAt
	}

	return item, nil
}

// CreateItem creates a knowledge item
func (m *Manager) CreateItem(category, title, content string) (*KnowledgeItem, error) {
	id := uuid.New().String()
	now := time.Now()

	// build file path
	filePath := filepath.Join(m.basePath, category, title+".md")

	// ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// write file
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	// insert into database
	_, err := m.db.Exec(
		"INSERT INTO knowledge_base_items (id, category, title, file_path, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, category, title, filePath, content, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert knowledge item: %w", err)
	}

	return &KnowledgeItem{
		ID:        id,
		Category:  category,
		Title:     title,
		FilePath:  filePath,
		Content:   content,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// UpdateItem updates a knowledge item
func (m *Manager) UpdateItem(id, category, title, content string) (*KnowledgeItem, error) {
	// get the existing item
	item, err := m.GetItem(id)
	if err != nil {
		return nil, err
	}

	// build new file path
	newFilePath := filepath.Join(m.basePath, category, title+".md")

	// if the path changed, the file needs to be moved
	if item.FilePath != newFilePath {
		// ensure the new directory exists
		if err := os.MkdirAll(filepath.Dir(newFilePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}

		// move file
		if err := os.Rename(item.FilePath, newFilePath); err != nil {
			return nil, fmt.Errorf("failed to move file: %w", err)
		}

		// delete the old directory (if empty)
		oldDir := filepath.Dir(item.FilePath)
		if isEmpty, _ := isEmptyDir(oldDir); isEmpty {
			// only delete when the directory is not the knowledge base root (avoid deleting the root)
			if oldDir != m.basePath {
				if err := os.Remove(oldDir); err != nil {
					m.logger.Warn("failed to delete empty directory", zap.String("dir", oldDir), zap.Error(err))
				}
			}
		}
	}

	// write file
	if err := os.WriteFile(newFilePath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("failed to write file: %w", err)
	}

	// update database
	_, err = m.db.Exec(
		"UPDATE knowledge_base_items SET category = ?, title = ?, file_path = ?, content = ?, updated_at = ? WHERE id = ?",
		category, title, newFilePath, content, time.Now(), id,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to update knowledge item: %w", err)
	}

	// delete old vector embeddings (re-indexing needed)
	_, err = m.db.Exec("DELETE FROM knowledge_embeddings WHERE item_id = ?", id)
	if err != nil {
		m.logger.Warn("failed to delete old vector embeddings", zap.Error(err))
	}

	return m.GetItem(id)
}

// DeleteItem deletes a knowledge item
func (m *Manager) DeleteItem(id string) error {
	// get file path
	var filePath string
	err := m.db.QueryRow("SELECT file_path FROM knowledge_base_items WHERE id = ?", id).Scan(&filePath)
	if err != nil {
		return fmt.Errorf("failed to query knowledge item: %w", err)
	}

	// delete file
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		m.logger.Warn("failed to delete file", zap.String("path", filePath), zap.Error(err))
	}

	// delete database record (vectors are cascade-deleted)
	_, err = m.db.Exec("DELETE FROM knowledge_base_items WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete knowledge item: %w", err)
	}

	// delete empty directory (if empty)
	dir := filepath.Dir(filePath)
	if isEmpty, _ := isEmptyDir(dir); isEmpty {
		// only delete when the directory is not the knowledge base root (avoid deleting the root)
		if dir != m.basePath {
			if err := os.Remove(dir); err != nil {
				m.logger.Warn("failed to delete empty directory", zap.String("dir", dir), zap.Error(err))
			}
		}
	}

	return nil
}

// isEmptyDir checks whether a directory is empty (ignores hidden files and files starting with .)
func isEmptyDir(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		// ignore hidden files (starting with .)
		if !strings.HasPrefix(entry.Name(), ".") {
			return false, nil
		}
	}
	return true, nil
}

// LogRetrieval records a retrieval log
func (m *Manager) LogRetrieval(conversationID, messageID, query, riskType string, retrievedItems []string) error {
	id := uuid.New().String()
	itemsJSON, _ := json.Marshal(retrievedItems)

	_, err := m.db.Exec(
		"INSERT INTO knowledge_retrieval_logs (id, conversation_id, message_id, query, risk_type, retrieved_items, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, conversationID, messageID, query, riskType, string(itemsJSON), time.Now(),
	)
	return err
}

// GetIndexStatus gets index status
func (m *Manager) GetIndexStatus() (map[string]interface{}, error) {
	// get total knowledge item count
	var totalItems int
	err := m.db.QueryRow("SELECT COUNT(*) FROM knowledge_base_items").Scan(&totalItems)
	if err != nil {
		return nil, fmt.Errorf("failed to query total knowledge item count: %w", err)
	}

	// get the number of indexed knowledge items (those with vector embeddings)
	var indexedItems int
	err = m.db.QueryRow(`
		SELECT COUNT(DISTINCT item_id) 
		FROM knowledge_embeddings
	`).Scan(&indexedItems)
	if err != nil {
		return nil, fmt.Errorf("failed to query indexed item count: %w", err)
	}

	// compute progress percentage
	var progressPercent float64
	if totalItems > 0 {
		progressPercent = float64(indexedItems) / float64(totalItems) * 100
	} else {
		progressPercent = 100.0
	}

	// determine whether completed
	isComplete := indexedItems >= totalItems && totalItems > 0

	return map[string]interface{}{
		"total_items":      totalItems,
		"indexed_items":    indexedItems,
		"progress_percent": progressPercent,
		"is_complete":      isComplete,
	}, nil
}

// GetRetrievalLogs gets retrieval logs
func (m *Manager) GetRetrievalLogs(conversationID, messageID string, limit int) ([]*RetrievalLog, error) {
	var rows *sql.Rows
	var err error

	if messageID != "" {
		rows, err = m.db.Query(
			"SELECT id, conversation_id, message_id, query, risk_type, retrieved_items, created_at FROM knowledge_retrieval_logs WHERE message_id = ? ORDER BY created_at DESC LIMIT ?",
			messageID, limit,
		)
	} else if conversationID != "" {
		rows, err = m.db.Query(
			"SELECT id, conversation_id, message_id, query, risk_type, retrieved_items, created_at FROM knowledge_retrieval_logs WHERE conversation_id = ? ORDER BY created_at DESC LIMIT ?",
			conversationID, limit,
		)
	} else {
		rows, err = m.db.Query(
			"SELECT id, conversation_id, message_id, query, risk_type, retrieved_items, created_at FROM knowledge_retrieval_logs ORDER BY created_at DESC LIMIT ?",
			limit,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query retrieval logs: %w", err)
	}
	defer rows.Close()

	var logs []*RetrievalLog
	for rows.Next() {
		log := &RetrievalLog{}
		var createdAt string
		var itemsJSON sql.NullString
		if err := rows.Scan(&log.ID, &log.ConversationID, &log.MessageID, &log.Query, &log.RiskType, &itemsJSON, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan retrieval logs: %w", err)
		}

		// parse time - supports multiple formats
		var err error
		timeFormats := []string{
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
			time.RFC3339,
			time.RFC3339Nano,
		}

		for _, format := range timeFormats {
			log.CreatedAt, err = time.Parse(format, createdAt)
			if err == nil && !log.CreatedAt.IsZero() {
				break
			}
		}

		// if all formats fail, log a warning and continue
		if log.CreatedAt.IsZero() {
			m.logger.Warn("failed to parse retrieval log time",
				zap.String("timeStr", createdAt),
				zap.Error(err),
			)
			// use the current time as fallback
			log.CreatedAt = time.Now()
		}

		// parse retrieval item
		if itemsJSON.Valid {
			json.Unmarshal([]byte(itemsJSON.String), &log.RetrievedItems)
		}

		logs = append(logs, log)
	}

	return logs, nil
}

// DeleteRetrievalLog deletes a retrieval log
func (m *Manager) DeleteRetrievalLog(id string) error {
	result, err := m.db.Exec("DELETE FROM knowledge_retrieval_logs WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete retrieval log: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get deleted row count: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("retrieval log does not exist")
	}

	return nil
}
