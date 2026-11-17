package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type CICDHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewCICDHandler(db *database.DB, logger *zap.Logger) *CICDHandler {
	return &CICDHandler{db: db, logger: logger}
}

func generateToken() (plain, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	plain = "vs_" + hex.EncodeToString(b)
	h := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(h[:])
	return
}

func (h *CICDHandler) ListTokens(c *gin.Context) {
	rows, err := h.db.Query(`SELECT id, name, COALESCE(engagement_id,''), COALESCE(project_id,''),
		permissions_json, COALESCE(last_used_at,''), COALESCE(expires_at,''), created_by, created_at
		FROM cicd_tokens ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, name, engID, projID, perms, lastUsed, expires, createdBy, created string
		if err := rows.Scan(&id, &name, &engID, &projID, &perms, &lastUsed, &expires, &createdBy, &created); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "name": name, "engagement_id": engID, "project_id": projID,
			"permissions": perms, "last_used_at": lastUsed, "expires_at": expires,
			"created_by": createdBy, "created_at": created,
		})
	}
	c.JSON(http.StatusOK, gin.H{"tokens": out})
}

func (h *CICDHandler) CreateToken(c *gin.Context) {
	var req struct {
		Name         string `json:"name"`
		EngagementID string `json:"engagement_id"`
		ProjectID    string `json:"project_id"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	plain, hash := generateToken()
	id := uuid.NewString()
	userID, _ := c.Get("user_id")
	createdBy, _ := userID.(string)
	_, err := h.db.Exec(`INSERT INTO cicd_tokens (id, name, token_hash, engagement_id, project_id, created_by, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, req.Name, hash, req.EngagementID, req.ProjectID, createdBy, req.ExpiresAt, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "token": plain})
}

func (h *CICDHandler) DeleteToken(c *gin.Context) {
	tokenID := c.Param("token_id")
	_, err := h.db.Exec("DELETE FROM cicd_tokens WHERE id = ?", tokenID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CICDHandler) ListRuns(c *gin.Context) {
	tokenID := c.Query("token_id")
	query := `SELECT id, token_id, trigger_type, repo_url, branch, commit_sha, status,
		findings_count, critical_count, COALESCE(started_at,''), COALESCE(completed_at,''), created_at
		FROM cicd_runs`
	args := []interface{}{}
	if tokenID != "" {
		query += " WHERE token_id = ?"
		args = append(args, tokenID)
	}
	query += " ORDER BY created_at DESC LIMIT 100"
	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, tokID, trigger, repo, branch, sha, status, started, completed, created string
		var findings, critical int
		if err := rows.Scan(&id, &tokID, &trigger, &repo, &branch, &sha, &status, &findings, &critical, &started, &completed, &created); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "token_id": tokID, "trigger_type": trigger, "repo_url": repo,
			"branch": branch, "commit_sha": sha, "status": status,
			"findings_count": findings, "critical_count": critical,
			"started_at": started, "completed_at": completed, "created_at": created,
		})
	}
	c.JSON(http.StatusOK, gin.H{"runs": out})
}

func (h *CICDHandler) TriggerRun(c *gin.Context) {
	var req struct {
		TokenID   string `json:"token_id"`
		RepoURL   string `json:"repo_url"`
		Branch    string `json:"branch"`
		CommitSHA string `json:"commit_sha"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.TokenID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token_id required"})
		return
	}
	id := uuid.NewString()
	_, err := h.db.Exec(`INSERT INTO cicd_runs (id, token_id, trigger_type, repo_url, branch, commit_sha, status, created_at)
		VALUES (?, ?, 'api', ?, ?, ?, 'queued', ?)`, id, req.TokenID, req.RepoURL, req.Branch, req.CommitSHA, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"run_id": id, "status": "queued"})
}
