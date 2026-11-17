package handler

import (
	"net/http"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AutonomousGoalHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewAutonomousGoalHandler(db *database.DB, logger *zap.Logger) *AutonomousGoalHandler {
	return &AutonomousGoalHandler{db: db, logger: logger}
}

func (h *AutonomousGoalHandler) ListGoals(c *gin.Context) {
	engID := c.Param("id")
	status := c.Query("status")
	query := `SELECT id, COALESCE(parent_goal_id,''), goal_text, goal_type, status, priority,
		decomposed_by, result_summary, COALESCE(conversation_id,''), created_at, updated_at
		FROM autonomous_goals WHERE engagement_id = ?`
	args := []interface{}{engID}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	query += " ORDER BY priority DESC, created_at"
	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, parent, text, gType, st, decomp, summary, convID, created, updated string
		var priority int
		if err := rows.Scan(&id, &parent, &text, &gType, &st, &priority, &decomp, &summary, &convID, &created, &updated); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "parent_goal_id": parent, "goal_text": text, "goal_type": gType,
			"status": st, "priority": priority, "decomposed_by": decomp,
			"result_summary": summary, "conversation_id": convID,
			"created_at": created, "updated_at": updated,
		})
	}
	c.JSON(http.StatusOK, gin.H{"goals": out})
}

func (h *AutonomousGoalHandler) CreateGoal(c *gin.Context) {
	engID := c.Param("id")
	var req struct {
		ParentGoalID string `json:"parent_goal_id"`
		GoalText     string `json:"goal_text"`
		GoalType     string `json:"goal_type"`
		Priority     int    `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.GoalText == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "goal_text required"})
		return
	}
	if req.GoalType == "" {
		req.GoalType = "custom"
	}
	id := uuid.NewString()
	now := time.Now()
	_, err := h.db.Exec(`INSERT INTO autonomous_goals (id, engagement_id, parent_goal_id, goal_text, goal_type, status, priority, decomposed_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 'pending', ?, 'manual', ?, ?)`,
		id, engID, req.ParentGoalID, req.GoalText, req.GoalType, req.Priority, now, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *AutonomousGoalHandler) UpdateGoal(c *gin.Context) {
	goalID := c.Param("goal_id")
	var req struct {
		Status         string `json:"status"`
		ResultSummary  string `json:"result_summary"`
		ConversationID string `json:"conversation_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	_, err := h.db.Exec(`UPDATE autonomous_goals SET status = ?, result_summary = ?, conversation_id = ?, updated_at = ?
		WHERE id = ?`, req.Status, req.ResultSummary, req.ConversationID, time.Now(), goalID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AutonomousGoalHandler) DecomposeGoal(c *gin.Context) {
	goalID := c.Param("goal_id")
	engID := c.Param("id")
	var req struct {
		SubGoals []struct {
			GoalText string `json:"goal_text"`
			GoalType string `json:"goal_type"`
			Priority int    `json:"priority"`
		} `json:"sub_goals"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.SubGoals) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sub_goals required"})
		return
	}
	var ids []string
	now := time.Now()
	for _, sg := range req.SubGoals {
		id := uuid.NewString()
		gt := sg.GoalType
		if gt == "" {
			gt = "custom"
		}
		_, err := h.db.Exec(`INSERT INTO autonomous_goals (id, engagement_id, parent_goal_id, goal_text, goal_type, status, priority, decomposed_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'pending', ?, 'planner', ?, ?)`,
			id, engID, goalID, sg.GoalText, gt, sg.Priority, now, now)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		ids = append(ids, id)
	}
	_, _ = h.db.Exec("UPDATE autonomous_goals SET status = 'active', updated_at = ? WHERE id = ?", now, goalID)
	c.JSON(http.StatusCreated, gin.H{"sub_goal_ids": ids})
}

func (h *AutonomousGoalHandler) GetGoalTree(c *gin.Context) {
	engID := c.Param("id")
	rows, err := h.db.Query(`SELECT id, COALESCE(parent_goal_id,''), goal_text, goal_type, status, priority
		FROM autonomous_goals WHERE engagement_id = ? ORDER BY priority DESC, created_at`, engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type goal struct {
		ID       string `json:"id"`
		Parent   string `json:"parent_goal_id"`
		Text     string `json:"goal_text"`
		Type     string `json:"goal_type"`
		Status   string `json:"status"`
		Priority int    `json:"priority"`
	}
	var flat []goal
	for rows.Next() {
		var g goal
		if err := rows.Scan(&g.ID, &g.Parent, &g.Text, &g.Type, &g.Status, &g.Priority); err != nil {
			continue
		}
		flat = append(flat, g)
	}
	c.JSON(http.StatusOK, gin.H{"goals": flat})
}
