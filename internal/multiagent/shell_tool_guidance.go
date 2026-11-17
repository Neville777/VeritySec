package multiagent

import (
	"strings"

	"veritysec/internal/projectprompt"
)

func shellToolsPresent(toolNames []string) bool {
	for _, n := range toolNames {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "exec", "execute":
			return true
		}
	}
	return false
}

// injectShellToolGuidance appends the exec/execute division of labor to the end of the system prompt (only when the tool list contains exec or execute).
func injectShellToolGuidance(instruction string, toolNames []string) string {
	if !shellToolsPresent(toolNames) {
		return instruction
	}
	block := strings.TrimSpace(projectprompt.ShellExecExecuteGuidanceSection())
	if block == "" {
		return instruction
	}
	s := strings.TrimSpace(instruction)
	if s == "" {
		return block
	}
	return s + "\n\n" + block
}
