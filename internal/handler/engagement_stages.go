package handler

import (
	"errors"
	"net/http"

	"veritysec/internal/audit"
	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
)

// ApplyStageTransition runs one stage transition and writes the audit entry. It is shared by the
// HTTP handlers and the agent tool. c may be nil (agent). The audit detail carries the stage,
// action, actor and evidence count only, never evidence content.
func ApplyStageTransition(db *database.DB, svc *audit.Service, c *gin.Context, engagementID, stage string, in database.StageTransition) (*database.AssessmentStage, error) {
	st, err := db.TransitionAssessmentStage(engagementID, stage, in)
	if err != nil {
		return nil, err
	}
	if svc != nil {
		entry := audit.Entry{
			Category: "engagement", Action: "stage_" + in.Action, Result: "success",
			Message:      "Assessment stage " + st.Stage + ": " + in.Action,
			ResourceType: "engagement", ResourceID: engagementID,
			Detail: map[string]interface{}{
				"stage": st.Stage, "action": in.Action, "actor": in.Actor, "status": st.Status, "evidence_count": len(st.EvidenceIDs),
			},
		}
		if in.Actor == "agent" {
			entry.Actor = "agent"
		}
		svc.Record(c, entry)
	}
	return st, nil
}

// StageErrorStatus maps a stage error to an HTTP status and message; ok is false for internal errors.
func StageErrorStatus(err error) (status int, ok bool) {
	var conflict *database.ErrStageConflict
	var invalid *database.ErrStageInvalid
	switch {
	case errors.Is(err, database.ErrEngagementNotFound), errors.Is(err, database.ErrStageUnknown):
		return http.StatusNotFound, true
	case errors.As(err, &conflict):
		return http.StatusConflict, true
	case errors.As(err, &invalid):
		return http.StatusBadRequest, true
	}
	return http.StatusInternalServerError, false
}

// ListStages GET /api/engagements/:id/stages
func (h *EngagementHandler) ListStages(c *gin.Context) {
	stages, err := h.db.ListAssessmentStages(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"stages": stages})
}

type stageRequest struct {
	EvidenceIDs []string `json:"evidence_ids"`
	Note        string   `json:"note"`
	Reason      string   `json:"reason"`
}

func (h *EngagementHandler) transitionStage(c *gin.Context, action string) {
	var req stageRequest
	if action != database.StageActionStart {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
			return
		}
	}
	if len(req.Note) > 5000 || len(req.Reason) > 5000 || len(req.EvidenceIDs) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a field exceeds its length limit"})
		return
	}
	actor := "unknown"
	if s, ok := security.CurrentSession(c); ok && s.UserID != "" {
		actor = s.UserID
	}
	st, err := ApplyStageTransition(h.db, h.audit, c, c.Param("id"), c.Param("stage"), database.StageTransition{
		Action: action, EvidenceIDs: req.EvidenceIDs, Note: req.Note, Reason: req.Reason, Actor: actor,
	})
	if err != nil {
		if status, ok := StageErrorStatus(err); ok {
			c.JSON(status, gin.H{"error": err.Error()})
			return
		}
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"stage": st})
}

// StartStage POST /api/engagements/:id/stages/:stage/start
func (h *EngagementHandler) StartStage(c *gin.Context) {
	h.transitionStage(c, database.StageActionStart)
}

// CompleteStage POST /api/engagements/:id/stages/:stage/complete
func (h *EngagementHandler) CompleteStage(c *gin.Context) {
	h.transitionStage(c, database.StageActionComplete)
}

// SkipStage POST /api/engagements/:id/stages/:stage/skip
func (h *EngagementHandler) SkipStage(c *gin.Context) { h.transitionStage(c, database.StageActionSkip) }
