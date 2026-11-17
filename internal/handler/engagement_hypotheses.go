package handler

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
)

func (h *EngagementHandler) writeHypothesisErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, database.ErrHypothesisRule):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	case errors.Is(err, database.ErrHypothesisNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	default:
		h.writeErr(c, err)
	}
}

// loadHypothesisFor loads the hypothesis and checks project:write access to its engagement.
func (h *EngagementHandler) loadHypothesisFor(c *gin.Context, permission string) (*database.Hypothesis, bool) {
	hyp, err := h.db.GetHypothesis(c.Param("id"))
	if err != nil {
		h.writeHypothesisErr(c, err)
		return nil, false
	}
	if !h.canAccess(c, permission, hyp.EngagementID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return nil, false
	}
	return hyp, true
}

// ListHypotheses GET /api/engagements/:id/hypotheses
func (h *EngagementHandler) ListHypotheses(c *gin.Context) {
	if _, err := h.db.GetEngagement(c.Param("id")); err != nil {
		h.writeErr(c, err)
		return
	}
	if !h.canAccess(c, "project:read", c.Param("id")) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	rows, err := h.db.ListHypotheses(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"hypotheses": rows, "total": len(rows)})
}

// CreateHypothesis POST /api/engagements/:id/hypotheses (created_by is always "human" here).
func (h *EngagementHandler) CreateHypothesis(c *gin.Context) {
	var req struct {
		Title          string `json:"title"`
		Description    string `json:"description"`
		ConversationID string `json:"conversation_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	if utf8.RuneCountInString(req.Title) > 300 || utf8.RuneCountInString(req.Description) > 20000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title or description too long"})
		return
	}
	if _, err := h.db.GetEngagement(c.Param("id")); err != nil {
		h.writeErr(c, err)
		return
	}
	if !h.canAccess(c, "project:write", c.Param("id")) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	hyp, err := h.db.CreateHypothesis(&database.Hypothesis{EngagementID: c.Param("id"), ConversationID: strings.TrimSpace(req.ConversationID),
		Title: req.Title, Description: req.Description, CreatedBy: "human"})
	if err != nil {
		h.writeHypothesisErr(c, err)
		return
	}
	h.record(c, "hypothesis_create", "Create hypothesis", "hypothesis", hyp.ID, map[string]interface{}{"engagement_id": hyp.EngagementID})
	c.JSON(http.StatusOK, hyp)
}

// LinkHypothesisEvidence POST /api/hypotheses/:id/evidence {evidence_id, stance}
func (h *EngagementHandler) LinkHypothesisEvidence(c *gin.Context) {
	var req struct {
		EvidenceID string `json:"evidence_id"`
		Stance     string `json:"stance"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	hyp, ok := h.loadHypothesisFor(c, "project:write")
	if !ok {
		return
	}
	if err := h.db.LinkHypothesisEvidence(hyp.ID, strings.TrimSpace(req.EvidenceID), strings.TrimSpace(req.Stance)); err != nil {
		h.writeHypothesisErr(c, err)
		return
	}
	h.record(c, "hypothesis_evidence", "Link hypothesis evidence", "hypothesis", hyp.ID, map[string]interface{}{"evidence_id": req.EvidenceID, "stance": req.Stance})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// AddHypothesisApplicability POST /api/hypotheses/:id/applicability
func (h *EngagementHandler) AddHypothesisApplicability(c *gin.Context) {
	var req struct {
		CheckKind           string `json:"check_kind"`
		TargetObservationID string `json:"target_observation_id"`
		Result              string `json:"result"`
		Reason              string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	if utf8.RuneCountInString(req.Reason) > 4000 || utf8.RuneCountInString(req.CheckKind) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "check_kind or reason too long"})
		return
	}
	hyp, ok := h.loadHypothesisFor(c, "project:write")
	if !ok {
		return
	}
	chk, err := h.db.AddApplicabilityCheck(&database.ApplicabilityCheck{HypothesisID: hyp.ID, CheckKind: req.CheckKind,
		TargetObservationID: strings.TrimSpace(req.TargetObservationID), Result: strings.TrimSpace(req.Result), Reason: req.Reason})
	if err != nil {
		h.writeHypothesisErr(c, err)
		return
	}
	h.record(c, "hypothesis_applicability", "Add applicability check", "hypothesis", hyp.ID, map[string]interface{}{"result": chk.Result})
	c.JSON(http.StatusOK, chk)
}

// PromoteHypothesis POST /api/hypotheses/:id/promote {severity}
func (h *EngagementHandler) PromoteHypothesis(c *gin.Context) {
	var req struct {
		Severity string `json:"severity"`
	}
	_ = c.ShouldBindJSON(&req) // body optional
	sev := strings.ToLower(strings.TrimSpace(req.Severity))
	switch sev {
	case "", "critical", "high", "medium", "low", "info":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity"})
		return
	}
	hyp, ok := h.loadHypothesisFor(c, "project:write")
	if !ok {
		return
	}
	v, err := h.db.PromoteHypothesis(hyp.ID, sev)
	if err != nil {
		h.writeHypothesisErr(c, err)
		return
	}
	h.record(c, "hypothesis_promote", "Promote hypothesis to finding", "hypothesis", hyp.ID, map[string]interface{}{"vulnerability_id": v.ID})
	c.JSON(http.StatusOK, gin.H{"vulnerability": v, "hypothesis_id": hyp.ID})
}

// GetReviewQueue GET /api/engagements/:id/review-queue (project:read).
func (h *EngagementHandler) GetReviewQueue(c *gin.Context) {
	if _, err := h.db.GetEngagement(c.Param("id")); err != nil {
		h.writeErr(c, err)
		return
	}
	if !h.canAccess(c, "project:read", c.Param("id")) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	items, err := database.ListReviewQueue(h.db, c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}
