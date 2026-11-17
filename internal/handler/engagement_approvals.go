package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
)

// SetApprovalTTL overrides the approval lifetime (default 30 minutes).
func (h *EngagementHandler) SetApprovalTTL(ttl time.Duration) {
	if ttl > 0 {
		h.approvalTTL = ttl
	}
}

func (h *EngagementHandler) approvalLifetime() time.Duration {
	if h.approvalTTL > 0 {
		return h.approvalTTL
	}
	return 30 * time.Minute
}

// ListApprovals GET /api/engagements/:id/approvals (pending first). Rows carry the tool, target
// and argument hash only, never the arguments.
func (h *EngagementHandler) ListApprovals(c *gin.Context) {
	id := c.Param("id")
	if !h.canAccess(c, "project:read", id) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	list, err := h.db.ListApprovalRequests(id)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"approvals": list})
}

type approvalDecisionRequest struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// DecideApproval POST /api/approval-requests/:id/decision {decision: approve|deny, reason}.
// Requires project:write (route permission) and access to the request's engagement. A denial
// needs a reason. The model cannot reach this endpoint: it is session-authenticated HTTP only.
func (h *EngagementHandler) DecideApproval(c *gin.Context) {
	var req approvalDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}
	req.Decision = strings.ToLower(strings.TrimSpace(req.Decision))
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Decision != "approve" && req.Decision != "deny" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision must be approve or deny"})
		return
	}
	if req.Decision == "deny" && req.Reason == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a reason is required to deny"})
		return
	}
	if utf8.RuneCountInString(req.Reason) > 2000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason exceeds its length limit"})
		return
	}
	existing, err := h.db.GetApprovalRequest(c.Param("id"))
	if err != nil {
		h.writeApprovalErr(c, err)
		return
	}
	if !h.canAccess(c, "project:write", existing.EngagementID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	by := ""
	if s, ok := security.CurrentSession(c); ok {
		by = s.UserID
	}
	a, err := h.db.DecideApproval(existing.ID, req.Decision == "approve", by, req.Reason, h.now(), h.approvalLifetime())
	if err != nil {
		h.writeApprovalErr(c, err)
		return
	}
	h.record(c, "approval_"+a.Status, "Approval request "+a.Status, "engagement", a.EngagementID, map[string]interface{}{
		"approval_id": a.ID, "tool": a.ToolName, "target": a.Target, "status": a.Status, "decided_by": by,
	})
	c.JSON(http.StatusOK, gin.H{"approval": a})
}

func (h *EngagementHandler) writeApprovalErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, database.ErrApprovalNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, database.ErrApprovalDecided), errors.Is(err, database.ErrApprovalExpired):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		h.writeErr(c, err)
	}
}
