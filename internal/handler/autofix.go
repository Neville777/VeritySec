package handler

import (
	"net/http"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AutofixHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewAutofixHandler(db *database.DB, logger *zap.Logger) *AutofixHandler {
	return &AutofixHandler{db: db, logger: logger}
}

func (h *AutofixHandler) ListByVuln(c *gin.Context) {
	vulnID := c.Param("id")
	rows, err := h.db.Query(`SELECT id, file_path, language, original_code, fixed_code, explanation,
		status, generated_by, COALESCE(reviewed_by,''), created_at
		FROM autofix_suggestions WHERE vulnerability_id = ? ORDER BY created_at DESC`, vulnID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, fp, lang, orig, fixed, expl, status, genBy, revBy, created string
		if err := rows.Scan(&id, &fp, &lang, &orig, &fixed, &expl, &status, &genBy, &revBy, &created); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "file_path": fp, "language": lang, "original_code": orig,
			"fixed_code": fixed, "explanation": expl, "status": status,
			"generated_by": genBy, "reviewed_by": revBy, "created_at": created,
		})
	}
	c.JSON(http.StatusOK, gin.H{"suggestions": out})
}

func (h *AutofixHandler) Create(c *gin.Context) {
	vulnID := c.Param("id")
	var req struct {
		FilePath     string `json:"file_path"`
		Language     string `json:"language"`
		OriginalCode string `json:"original_code"`
		FixedCode    string `json:"fixed_code"`
		Explanation  string `json:"explanation"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	id := uuid.NewString()
	now := time.Now()
	_, err := h.db.Exec(`INSERT INTO autofix_suggestions (id, vulnerability_id, file_path, language, original_code, fixed_code, explanation, status, generated_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', 'manual', ?, ?)`,
		id, vulnID, req.FilePath, req.Language, req.OriginalCode, req.FixedCode, req.Explanation, now, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *AutofixHandler) UpdateStatus(c *gin.Context) {
	fixID := c.Param("fix_id")
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status required"})
		return
	}
	userID, _ := c.Get("user_id")
	reviewer, _ := userID.(string)
	_, err := h.db.Exec("UPDATE autofix_suggestions SET status = ?, reviewed_by = ?, updated_at = ? WHERE id = ?",
		req.Status, reviewer, time.Now(), fixID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
