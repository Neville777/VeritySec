package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ListToolObservations GET /api/tool-executions/:id/observations. Access is project:read on the
// engagement the execution's evidence belongs to.
func (h *EngagementHandler) ListToolObservations(c *gin.Context) {
	execID := c.Param("id")
	engagementID, err := h.db.ToolExecutionEngagementID(execID)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	if engagementID == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no engagement-linked observations for this tool execution"})
		return
	}
	if !h.canAccess(c, "project:read", engagementID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	obs, err := h.db.ListToolObservations(execID)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"observations": obs, "total": len(obs)})
}
