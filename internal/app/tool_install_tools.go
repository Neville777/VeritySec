package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"veritysec/internal/mcp"
	"veritysec/internal/toolinstall"
	"veritysec/internal/toolrisk"
)

// registerToolInstallTools lets the agent see which tools are installed, install or remove
// the ones in the fixed install table, and check the progress of a job.
func registerToolInstallTools(mcpServer *mcp.Server) {
	textResult := func(v interface{}, isErr bool) *mcp.ToolResult {
		b, _ := json.MarshalIndent(v, "", "  ")
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(b)}}, IsError: isErr}
	}

	listTool := mcp.Tool{
		Name:             "list_tool_installs",
		Description:      "List the security tools this app can install, with whether each is installed, its install method, and its path.",
		ShortDescription: "List installable security tools and their install state",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}
	listHandler := func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		return textResult(map[string]interface{}{"tools": toolinstall.Inventory()}, false), nil
	}
	mcpServer.RegisterTool(listTool, listHandler)

	installTool := mcp.Tool{
		Name:             "install_tool",
		Description:      "Install, upgrade, or remove a security tool from the app's install table. Only pipx, go, and gem tools can be installed here; apt tools must be installed by the user in a terminal. Returns a job_id to check with tool_install_status.",
		ShortDescription: "Install or remove a security tool",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"command": map[string]interface{}{
					"type":        "string",
					"description": "Tool command name, as shown by list_tool_installs (e.g. arjun, subfinder).",
				},
				"action": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"install", "uninstall", "upgrade"},
					"description": "install, uninstall, or upgrade (upgrade fetches the latest release, which usually fixes known vulnerabilities).",
				},
			},
			"required": []string{"command", "action"},
		},
	}
	installHandler := func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		command, _ := args["command"].(string)
		action, _ := args["action"].(string)
		command = strings.TrimSpace(command)
		action = strings.TrimSpace(action)
		if command == "" || action == "" {
			return textResult("command and action are required", true), nil
		}
		job, err := toolinstall.Start(command, action)
		if err != nil {
			return textResult(err.Error(), true), nil
		}
		return textResult(job, false), nil
	}
	mcpServer.RegisterTool(installTool, installHandler)

	riskTool := mcp.Tool{
		Name:             "tool_risk_check",
		Description:      "Check installed security tools for known vulnerabilities: OSV advisories, CVSS v3 scores, and CISA KEV (actively exploited) matches. Use before deciding which tools to upgrade.",
		ShortDescription: "Check installed tools for known vulnerabilities",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	}
	riskHandler := func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		var commands []string
		for _, row := range toolinstall.Inventory() {
			if row.Installed {
				commands = append(commands, row.Command)
			}
		}
		return textResult(map[string]interface{}{"reports": toolrisk.AssessAll(ctx, commands)}, false), nil
	}
	mcpServer.RegisterTool(riskTool, riskHandler)

	statusTool := mcp.Tool{
		Name:             "tool_install_status",
		Description:      "Check the status and output of an install or uninstall job started with install_tool.",
		ShortDescription: "Check an install job's status",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"job_id": map[string]interface{}{"type": "string", "description": "Job ID returned by install_tool."},
			},
			"required": []string{"job_id"},
		},
	}
	statusHandler := func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		id, _ := args["job_id"].(string)
		job, ok := toolinstall.GetJob(strings.TrimSpace(id))
		if !ok {
			return textResult(fmt.Sprintf("job not found: %s", id), true), nil
		}
		return textResult(job, job.Status == "failed"), nil
	}
	mcpServer.RegisterTool(statusTool, statusHandler)
}
