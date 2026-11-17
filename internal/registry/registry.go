// Package registry builds one read-only description of every security tool: name, schemas,
// risk category, required permission, target requirement, timeout and output limit.
// It never runs anything.
package registry

import (
	"sort"
	"strings"

	"veritysec/internal/config"
	"veritysec/internal/toolinstall"
)

const (
	PermissionList = "config:read" // listing the registry
	PermissionRun  = "chat:write"  // running a tool through the agent

	RiskVulnChecked = "vuln-checked" // in the install table, so toolrisk can assess it
	RiskUnknown     = "unknown"
)

// ToolSpec describes one tool.
type ToolSpec struct {
	Name               string                 `json:"name"`
	Description        string                 `json:"description"`
	Command            string                 `json:"command"`
	Enabled            bool                   `json:"enabled"`
	InputSchema        map[string]interface{} `json:"input_schema"`
	OutputSchema       map[string]interface{} `json:"output_schema"`
	RiskCategory       string                 `json:"risk_category"`
	RequiredPermission string                 `json:"required_permission"`
	ListPermission     string                 `json:"list_permission"`
	TargetRequired     bool                   `json:"target_required"`
	TimeoutSeconds     int                    `json:"timeout_seconds"`
	OutputLimitBytes   int                    `json:"output_limit_bytes"`
}

// Options carries the limits applied to every tool.
type Options struct {
	TimeoutSeconds   int
	OutputLimitBytes int
}

var targetParams = map[string]bool{"target": true, "host": true, "url": true, "ip": true}

// OutputSchema returns the generic output schema shared by all tools.
func OutputSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"stdout":    map[string]interface{}{"type": "string"},
			"stderr":    map[string]interface{}{"type": "string"},
			"exit_code": map[string]interface{}{"type": "integer"},
			"truncated": map[string]interface{}{"type": "boolean"},
		},
		"required": []string{"stdout", "stderr", "exit_code", "truncated"},
	}
}

func jsonType(t string) string {
	switch strings.ToLower(t) {
	case "int", "integer":
		return "integer"
	case "number", "float":
		return "number"
	case "bool", "boolean":
		return "boolean"
	case "array":
		return "array"
	case "object":
		return "object"
	default:
		return "string"
	}
}

func inputSchema(params []config.ParameterConfig) (map[string]interface{}, bool) {
	props := map[string]interface{}{}
	required := []string{}
	target := false
	for _, p := range params {
		prop := map[string]interface{}{"type": jsonType(p.Type)}
		if p.Description != "" {
			prop["description"] = strings.TrimSpace(p.Description)
		}
		if prop["type"] == "array" {
			item := p.ItemType
			if item == "" {
				item = "string"
			}
			prop["items"] = map[string]interface{}{"type": jsonType(item)}
		}
		if len(p.Options) > 0 {
			prop["enum"] = p.Options
		}
		if p.Default != nil {
			prop["default"] = p.Default
		}
		props[p.Name] = prop
		if p.Required {
			required = append(required, p.Name)
		}
		if targetParams[strings.ToLower(p.Name)] {
			target = true
		}
	}
	schema := map[string]interface{}{"type": "object", "properties": props}
	if len(required) > 0 {
		sort.Strings(required)
		schema["required"] = required
	}
	return schema, target
}

// RiskCategory is "vuln-checked" when the tool's command is in the install table (so the
// toolrisk package can look up its vulnerabilities), otherwise "unknown".
func RiskCategory(command string) string {
	if _, ok := toolinstall.Lookup(command); ok {
		return RiskVulnChecked
	}
	return RiskUnknown
}

// BuildRegistry converts recipes into specs sorted by name. It is pure.
func BuildRegistry(recipes []config.ToolConfig, opts Options) []ToolSpec {
	out := make([]ToolSpec, 0, len(recipes))
	for _, r := range recipes {
		schema, target := inputSchema(r.Parameters)
		desc := strings.TrimSpace(r.Description)
		if desc == "" {
			desc = strings.TrimSpace(r.ShortDescription)
		}
		out = append(out, ToolSpec{
			Name: r.Name, Description: desc, Command: r.Command, Enabled: r.Enabled,
			InputSchema: schema, OutputSchema: OutputSchema(),
			RiskCategory: RiskCategory(r.Command), RequiredPermission: PermissionRun,
			ListPermission: PermissionList, TargetRequired: target,
			TimeoutSeconds: opts.TimeoutSeconds, OutputLimitBytes: opts.OutputLimitBytes,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
