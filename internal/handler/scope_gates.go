package handler

import (
	"net/http"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type ScopeGateHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewScopeGateHandler(db *database.DB, logger *zap.Logger) *ScopeGateHandler {
	return &ScopeGateHandler{db: db, logger: logger}
}

func (h *ScopeGateHandler) ListScopeRules(c *gin.Context) {
	engID := c.Param("id")
	rows, err := h.db.Query(`SELECT id, rule_type, target_type, target_value, note, created_at
		FROM engagement_scope_rules WHERE engagement_id = ? ORDER BY rule_type, target_type`, engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, rt, tt, tv, note, created string
		if err := rows.Scan(&id, &rt, &tt, &tv, &note, &created); err != nil {
			continue
		}
		out = append(out, gin.H{"id": id, "rule_type": rt, "target_type": tt, "target_value": tv, "note": note, "created_at": created})
	}
	c.JSON(http.StatusOK, gin.H{"rules": out})
}

func (h *ScopeGateHandler) AddScopeRule(c *gin.Context) {
	engID := c.Param("id")
	var req struct {
		RuleType    string `json:"rule_type"`
		TargetType  string `json:"target_type"`
		TargetValue string `json:"target_value"`
		Note        string `json:"note"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.TargetValue == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_value required"})
		return
	}
	if req.RuleType != "allow" && req.RuleType != "deny" {
		req.RuleType = "allow"
	}
	validTypes := map[string]bool{"ip": true, "cidr": true, "domain": true, "url_prefix": true, "port_range": true}
	if !validTypes[req.TargetType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target_type"})
		return
	}
	id := uuid.NewString()
	_, err := h.db.Exec(`INSERT INTO engagement_scope_rules (id, engagement_id, rule_type, target_type, target_value, note, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, id, engID, req.RuleType, req.TargetType, req.TargetValue, req.Note, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *ScopeGateHandler) DeleteScopeRule(c *gin.Context) {
	engID := c.Param("id")
	ruleID := c.Param("rule_id")
	_, err := h.db.Exec("DELETE FROM engagement_scope_rules WHERE id = ? AND engagement_id = ?", ruleID, engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *ScopeGateHandler) GetNoiseConfig(c *gin.Context) {
	engID := c.Param("id")
	row := h.db.QueryRow(`SELECT max_requests_per_minute, max_concurrent_tools, max_agent_turns, max_tokens_budget,
		COALESCE(quiet_hours_start,''), COALESCE(quiet_hours_end,''), updated_at
		FROM engagement_noise_config WHERE engagement_id = ?`, engID)
	var rpm, concurrent, turns, tokens int
	var qStart, qEnd, updated string
	if err := row.Scan(&rpm, &concurrent, &turns, &tokens, &qStart, &qEnd, &updated); err != nil {
		c.JSON(http.StatusOK, gin.H{"config": gin.H{
			"max_requests_per_minute": 60, "max_concurrent_tools": 3,
			"max_agent_turns": 500, "max_tokens_budget": 1000000,
		}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"config": gin.H{
		"max_requests_per_minute": rpm, "max_concurrent_tools": concurrent,
		"max_agent_turns": turns, "max_tokens_budget": tokens,
		"quiet_hours_start": qStart, "quiet_hours_end": qEnd, "updated_at": updated,
	}})
}

func (h *ScopeGateHandler) UpdateNoiseConfig(c *gin.Context) {
	engID := c.Param("id")
	var req struct {
		MaxRequestsPerMinute int    `json:"max_requests_per_minute"`
		MaxConcurrentTools   int    `json:"max_concurrent_tools"`
		MaxAgentTurns        int    `json:"max_agent_turns"`
		MaxTokensBudget      int    `json:"max_tokens_budget"`
		QuietHoursStart      string `json:"quiet_hours_start"`
		QuietHoursEnd        string `json:"quiet_hours_end"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if req.MaxRequestsPerMinute <= 0 {
		req.MaxRequestsPerMinute = 60
	}
	if req.MaxConcurrentTools <= 0 {
		req.MaxConcurrentTools = 3
	}
	if req.MaxAgentTurns <= 0 {
		req.MaxAgentTurns = 500
	}
	if req.MaxTokensBudget <= 0 {
		req.MaxTokensBudget = 1000000
	}
	_, err := h.db.Exec(`INSERT INTO engagement_noise_config (engagement_id, max_requests_per_minute, max_concurrent_tools, max_agent_turns, max_tokens_budget, quiet_hours_start, quiet_hours_end, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(engagement_id) DO UPDATE SET
			max_requests_per_minute = excluded.max_requests_per_minute,
			max_concurrent_tools = excluded.max_concurrent_tools,
			max_agent_turns = excluded.max_agent_turns,
			max_tokens_budget = excluded.max_tokens_budget,
			quiet_hours_start = excluded.quiet_hours_start,
			quiet_hours_end = excluded.quiet_hours_end,
			updated_at = excluded.updated_at`,
		engID, req.MaxRequestsPerMinute, req.MaxConcurrentTools, req.MaxAgentTurns, req.MaxTokensBudget,
		req.QuietHoursStart, req.QuietHoursEnd, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
