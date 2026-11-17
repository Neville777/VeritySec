package main

import (
	"veritysec/internal/config"
	"veritysec/internal/logger"
	"veritysec/internal/mcp"
	"veritysec/internal/security"
	"veritysec/internal/toolguard"
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"
)

func main() {
	var configPath = flag.String("config", "config.yaml", "config file path")
	flag.Parse()

	// load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// initialize logging (stdio mode writes logs to stderr to avoid interfering with JSON-RPC communication)
	log := logger.New(cfg.Log.Level, "stderr", logger.DiagnosticOptions{
		Dir:           cfg.Log.DiagnosticDir,
		Disabled:      cfg.Log.DiagnosticDisabled,
		RetentionDays: cfg.Log.DiagnosticRetentionDays,
	})
	defer log.Sync()

	// create MCP server
	mcpServer := mcp.NewServer(log.Logger)
	guard, err := toolguard.NewManager(cfg.EffectiveToolGuard())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize call interception: %v\n", err)
		os.Exit(1)
	}
	mcpServer.SetToolGuard(guard)

	// create security tool executor
	executor := security.NewExecutor(&cfg.Security, mcpServer, log.Logger)

	// register tools
	executor.RegisterTools(mcpServer)
	mcp.RegisterExecutionControlTools(mcpServer, nil)

	log.Logger.Info("MCP server (stdio mode) started, waiting for messages...")

	// run stdio loop
	if err := mcpServer.HandleStdio(); err != nil {
		log.Logger.Error("MCP server failed to run", zap.Error(err))
		os.Exit(1)
	}
}
