package handler

import (
	"net/http"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type PoCValidationHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewPoCValidationHandler(db *database.DB, logger *zap.Logger) *PoCValidationHandler {
	return &PoCValidationHandler{db: db, logger: logger}
}

func (h *PoCValidationHandler) ListByVuln(c *gin.Context) {
	vulnID := c.Param("id")
	rows, err := h.db.Query(`SELECT id, status, exploit_type, result_summary, confirmed_at, executed_by, created_at
		FROM poc_validations WHERE vulnerability_id = ? ORDER BY created_at DESC`, vulnID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, status, eType, summary, confirmed, execBy, created string
		if err := rows.Scan(&id, &status, &eType, &summary, &confirmed, &execBy, &created); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "status": status, "exploit_type": eType, "result_summary": summary,
			"confirmed_at": confirmed, "executed_by": execBy, "created_at": created,
		})
	}
	c.JSON(http.StatusOK, gin.H{"validations": out})
}

func (h *PoCValidationHandler) Create(c *gin.Context) {
	vulnID := c.Param("id")
	var req struct {
		EngagementID string `json:"engagement_id"`
		ExploitCode  string `json:"exploit_code"`
		ExploitType  string `json:"exploit_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	id := uuid.NewString()
	now := time.Now()
	_, err := h.db.Exec(`INSERT INTO poc_validations (id, vulnerability_id, engagement_id, status, exploit_code, exploit_type, executed_by, created_at, updated_at)
		VALUES (?, ?, ?, 'pending', ?, ?, 'manual', ?, ?)`,
		id, vulnID, req.EngagementID, req.ExploitCode, req.ExploitType, now, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *PoCValidationHandler) UpdateStatus(c *gin.Context) {
	pocID := c.Param("poc_id")
	var req struct {
		Status        string `json:"status"`
		ResultSummary string `json:"result_summary"`
		SandboxLog    string `json:"sandbox_log"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	now := time.Now()
	var confirmed *time.Time
	if req.Status == "confirmed" {
		confirmed = &now
	}
	_, err := h.db.Exec(`UPDATE poc_validations SET status = ?, result_summary = ?, sandbox_log = ?, confirmed_at = ?, updated_at = ?
		WHERE id = ?`, req.Status, req.ResultSummary, req.SandboxLog, confirmed, now, pocID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *PoCValidationHandler) GetDetail(c *gin.Context) {
	pocID := c.Param("poc_id")
	row := h.db.QueryRow(`SELECT id, vulnerability_id, COALESCE(engagement_id,''), status, exploit_code, exploit_type,
		sandbox_log, result_summary, COALESCE(confirmed_at,''), executed_by, created_at, updated_at
		FROM poc_validations WHERE id = ?`, pocID)
	var id, vulnID, engID, status, code, eType, log, summary, confirmed, execBy, created, updated string
	if err := row.Scan(&id, &vulnID, &engID, &status, &code, &eType, &log, &summary, &confirmed, &execBy, &created, &updated); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": id, "vulnerability_id": vulnID, "engagement_id": engID, "status": status,
		"exploit_code": code, "exploit_type": eType, "sandbox_log": log, "result_summary": summary,
		"confirmed_at": confirmed, "executed_by": execBy, "created_at": created, "updated_at": updated,
	})
}
