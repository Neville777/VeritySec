package app

import (
	"veritysec/internal/config"
	"veritysec/internal/mcp"
	"veritysec/internal/vision"

	"go.uber.org/zap"
)

func registerVisionTools(mcpServer *mcp.Server, cfg *config.Config, logger *zap.Logger) {
	vision.RegisterAnalyzeImageTool(mcpServer, cfg, logger)
}
