package handler

import (
	"net/http"

	"veritysec/internal/registry"

	"github.com/gin-gonic/gin"
)

// ListToolRegistry returns read-only metadata for every tool recipe, sorted by name.
func (h *ConfigHandler) ListToolRegistry(c *gin.Context) {
	opts := registry.Options{
		TimeoutSeconds:   h.config.Agent.ToolTimeoutMinutes * 60,
		OutputLimitBytes: h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective(),
	}
	c.JSON(http.StatusOK, gin.H{"tools": registry.BuildRegistry(h.config.Security.Tools, opts)})
}
