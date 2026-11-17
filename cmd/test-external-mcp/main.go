package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"veritysec/internal/config"
	"veritysec/internal/logger"
	"veritysec/internal/mcp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/test-external-mcp/main.go <config.yaml>")
		os.Exit(1)
	}

	configPath := os.Args[1]
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	if cfg.ExternalMCP.Servers == nil || len(cfg.ExternalMCP.Servers) == 0 {
		fmt.Println("No external MCP servers configured")
		os.Exit(0)
	}

	fmt.Printf("Found %d external MCP server(s)\n\n", len(cfg.ExternalMCP.Servers))

	// create logger
	log := logger.New("info", "stdout")

	// create external MCP manager
	manager := mcp.NewExternalMCPManager(log.Logger)
	manager.LoadConfigs(&cfg.ExternalMCP)

	// show config
	fmt.Println("=== Config info ===")
	for name, srv := range cfg.ExternalMCP.Servers {
		fmt.Printf("\n%s:\n", name)
		fmt.Printf("  Transport: %s\n", getTransport(srv))
		if srv.Command != "" {
			fmt.Printf("  Command: %s\n", srv.Command)
			fmt.Printf("  Args: %v\n", srv.Args)
		}
		if srv.URL != "" {
			fmt.Printf("  URL: %s\n", srv.URL)
		}
		fmt.Printf("  Description: %s\n", srv.Description)
		fmt.Printf("  Timeout: %d seconds\n", srv.Timeout)
		fmt.Printf("  ExternalMCPEnable: %v\n", srv.ExternalMCPEnable)
	}

	// get statistics
	fmt.Println("\n=== Statistics ===")
	stats := manager.GetStats()
	fmt.Printf("total: %d\n", stats["total"])
	fmt.Printf("enabled: %d\n", stats["enabled"])
	fmt.Printf("disabled: %d\n", stats["disabled"])
	fmt.Printf("connected: %d\n", stats["connected"])

	// test start (enabled servers only)
	fmt.Println("\n=== Test start ===")
	for name, srv := range cfg.ExternalMCP.Servers {
		if srv.ExternalMCPEnable {
			fmt.Printf("\ntrying to start %s...\n", name)
			// note: the actual start may fail because a real MCP server is required
			err := manager.StartClient(name)
			if err != nil {
				fmt.Printf("  start failed (expected if no real MCP server is available): %v\n", err)
			} else {
				fmt.Printf("  started successfully\n")
				// get client status
				if client, exists := manager.GetClient(name); exists {
					fmt.Printf("  status: %s\n", client.GetStatus())
					fmt.Printf("  connected: %v\n", client.IsConnected())
				}
			}
		}
	}

	// wait a moment
	time.Sleep(2 * time.Second)

	// test listing tools
	fmt.Println("\n=== Test listing tools ===")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools, err := manager.GetAllTools(ctx)
	if err != nil {
		fmt.Printf("failed to get tool list: %v\n", err)
	} else {
		fmt.Printf("got %d tools\n", len(tools))
		for i, tool := range tools {
			if i < 5 { // only show the first 5
				fmt.Printf("  - %s: %s\n", tool.Name, tool.Description)
			}
		}
		if len(tools) > 5 {
			fmt.Printf("  ... and %d more tools\n", len(tools)-5)
		}
	}

	// test stop
	fmt.Println("\n=== Test stop ===")
	for name := range cfg.ExternalMCP.Servers {
		fmt.Printf("\nstopping %s...\n", name)
		err := manager.StopClient(name)
		if err != nil {
			fmt.Printf("  stop failed: %v\n", err)
		} else {
			fmt.Printf("  stopped successfully\n")
		}
	}

	// final statistics
	fmt.Println("\n=== Final statistics ===")
	stats = manager.GetStats()
	fmt.Printf("total: %d\n", stats["total"])
	fmt.Printf("enabled: %d\n", stats["enabled"])
	fmt.Printf("disabled: %d\n", stats["disabled"])
	fmt.Printf("connected: %d\n", stats["connected"])

	fmt.Println("\n=== Test complete ===")
}

func getTransport(srv config.ExternalMCPServerConfig) string {
	t := srv.GetTransportType()
	if t == "" {
		return "unknown"
	}
	return t
}
