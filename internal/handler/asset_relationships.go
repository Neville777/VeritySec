package handler

import (
	"errors"
	"net/http"
	"strings"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
)

type assetRelationshipRequest struct {
	FromAssetID     string `json:"from_asset_id"`
	ToAssetID       string `json:"to_asset_id"`
	RelationType    string `json:"relation_type"`
	Confidence      string `json:"confidence"`
	EvidenceID      string `json:"evidence_id"`
	ToolExecutionID string `json:"tool_execution_id"`
	Reason          string `json:"reason"`
}

func (h *EngagementHandler) writeRelationshipErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, database.ErrRelationshipRule):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, database.ErrRelationshipNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	default:
		h.writeErr(c, err)
	}
}

// relationshipInput builds the input for a request made by a person. Every HTTP caller is
// human; only a session holding project:write may set "verified".
func relationshipInput(c *gin.Context, req assetRelationshipRequest) database.AssetRelationshipInput {
	s, _ := security.CurrentSession(c)
	return database.AssetRelationshipInput{
		FromAssetID: strings.TrimSpace(req.FromAssetID), ToAssetID: strings.TrimSpace(req.ToAssetID),
		RelationType: strings.TrimSpace(req.RelationType), Confidence: strings.TrimSpace(req.Confidence),
		EvidenceID: req.EvidenceID, ToolExecutionID: req.ToolExecutionID, Reason: req.Reason,
		CreatedBy: s.UserID, Human: true, CanVerify: s.Permissions["project:write"],
	}
}

// GetAssetGraph GET /api/engagements/:id/asset-graph.
func (h *EngagementHandler) GetAssetGraph(c *gin.Context) {
	id := c.Param("id")
	if _, err := h.db.GetEngagement(id); err != nil {
		h.writeErr(c, err)
		return
	}
	g, err := h.db.ListAssetGraph(id)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, g)
}

// CreateAssetRelationship POST /api/engagements/:id/asset-relationships (manual edge). The
// confidence defaults to "manual".
func (h *EngagementHandler) CreateAssetRelationship(c *gin.Context) {
	var req assetRelationshipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Confidence) == "" {
		req.Confidence = database.ConfManual
	}
	in := relationshipInput(c, req)
	in.EngagementID = c.Param("id")
	rel, err := h.db.UpsertAssetRelationship(in)
	if err != nil {
		h.writeRelationshipErr(c, err)
		return
	}
	h.record(c, "asset_relationship_upsert", "Record asset relationship", "asset_relationship", rel.ID, map[string]interface{}{
		"engagement_id": rel.EngagementID, "relation_type": rel.RelationType, "confidence": rel.Confidence, "reason": rel.Reason,
	})
	c.JSON(http.StatusOK, rel)
}

// UpdateAssetRelationship PUT /api/asset-relationships/:id (confidence change).
func (h *EngagementHandler) UpdateAssetRelationship(c *gin.Context) {
	var req assetRelationshipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rel, err := h.db.UpdateAssetRelationshipConfidence(c.Param("id"), relationshipInput(c, req))
	if err != nil {
		h.writeRelationshipErr(c, err)
		return
	}
	h.record(c, "asset_relationship_update", "Change asset relationship confidence", "asset_relationship", rel.ID, map[string]interface{}{
		"engagement_id": rel.EngagementID, "confidence": rel.Confidence, "reason": rel.Reason,
	})
	c.JSON(http.StatusOK, rel)
}
