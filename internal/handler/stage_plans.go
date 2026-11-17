package handler

import (
	"errors"
	"net/http"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
)

func (h *EngagementHandler) writeStagePlanErr(c *gin.Context, err error) {
	if errors.Is(err, database.ErrStagePlanNotFound) || errors.Is(err, database.ErrStagePlanTaskNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	h.writeStageTaskErr(c, err)
}

// ListStagePlans GET /api/engagements/:id/stages/:stage/plans
func (h *EngagementHandler) ListStagePlans(c *gin.Context) {
	plans, err := h.db.ListStagePlans(c.Param("id"), c.Param("stage"))
	if err != nil {
		h.writeStagePlanErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"plans": plans})
}

// ActivateStagePlan POST /api/stage-plans/:id/activate (the human approval of a draft plan).
func (h *EngagementHandler) ActivateStagePlan(c *gin.Context) {
	p, err := h.db.ActivateStagePlan(c.Param("id"))
	if err != nil {
		h.writeStagePlanErr(c, err)
		return
	}
	h.record(c, "stage_plan_activate", "Activate stage plan", "stage_plan", p.ID, map[string]interface{}{
		"engagement_id": p.EngagementID, "stage": p.Stage, "tasks": len(p.Tasks),
	})
	c.JSON(http.StatusOK, p)
}

// UpdateStagePlanTask PUT /api/stage-plan-tasks/:id (a human sets the task status).
func (h *EngagementHandler) UpdateStagePlanTask(c *gin.Context) {
	var req stageTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	t, err := h.db.SetPlanTaskStatus(c.Param("id"), req.Status, req.Reason, database.StageTaskByHuman)
	if err != nil {
		h.writeStagePlanErr(c, err)
		return
	}
	h.record(c, "stage_plan_task_update", "Change stage plan task status", "stage_plan_task", t.ID, map[string]interface{}{
		"plan_id": t.PlanID, "status": t.Status,
	})
	c.JSON(http.StatusOK, t)
}

// NextStagePlanTask GET /api/engagements/:id/stages/:stage/next-task
func (h *EngagementHandler) NextStagePlanTask(c *gin.Context) {
	t, err := database.NextPlanTask(h.db, c.Param("id"), c.Param("stage"))
	if err != nil {
		h.writeStagePlanErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"task": t})
}

// ResultStagePlanTask POST /api/stage-plan-tasks/:id/result
func (h *EngagementHandler) ResultStagePlanTask(c *gin.Context) {
	var req stageTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	t, err := database.MarkPlanTaskResult(h.db, c.Param("id"), req.Status, req.Reason)
	if err != nil {
		h.writeStagePlanErr(c, err)
		return
	}
	h.record(c, "stage_plan_task_result", "Record stage plan task result", "stage_plan_task", t.ID, map[string]interface{}{
		"plan_id": t.PlanID, "status": t.Status,
	})
	c.JSON(http.StatusOK, t)
}
