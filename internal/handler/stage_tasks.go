package handler

import (
	"errors"
	"net/http"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
)

func (h *EngagementHandler) writeStageTaskErr(c *gin.Context, err error) {
	if errors.Is(err, database.ErrStageTaskNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if status, ok := StageErrorStatus(err); ok {
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	h.writeErr(c, err)
}

// ListStageTasks GET /api/engagements/:id/stages/:stage/tasks
func (h *EngagementHandler) ListStageTasks(c *gin.Context) {
	tasks, err := h.db.ListStageTasks(c.Param("id"), c.Param("stage"))
	if err != nil {
		h.writeStageTaskErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

type stageTaskRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Required    *bool  `json:"required"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
}

// CreateStageTask POST /api/engagements/:id/stages/:stage/tasks (a human adds a task).
func (h *EngagementHandler) CreateStageTask(c *gin.Context) {
	var req stageTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	t, err := h.db.CreateStageTask(c.Param("id"), c.Param("stage"), database.StageTaskInput{
		Title: req.Title, Description: req.Description, Required: req.Required, ProposedBy: database.StageTaskByHuman,
	})
	if err != nil {
		h.writeStageTaskErr(c, err)
		return
	}
	h.record(c, "stage_task_create", "Create stage task", "stage_task", t.ID, map[string]interface{}{
		"engagement_id": t.EngagementID, "stage": t.Stage, "required": t.Required,
	})
	c.JSON(http.StatusOK, t)
}

// UpdateStageTask PUT /api/stage-tasks/:id (a human sets open, done or skipped).
func (h *EngagementHandler) UpdateStageTask(c *gin.Context) {
	var req stageTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	t, err := h.db.SetStageTaskStatus(c.Param("id"), req.Status, req.Reason, database.StageTaskByHuman)
	if err != nil {
		h.writeStageTaskErr(c, err)
		return
	}
	h.record(c, "stage_task_update", "Change stage task status", "stage_task", t.ID, map[string]interface{}{
		"engagement_id": t.EngagementID, "stage": t.Stage, "status": t.Status,
	})
	c.JSON(http.StatusOK, t)
}
