package config

import (
	"strings"
	"testing"
)

func TestDefaultHitlAuditAgentPromptIncludesPrioritizedRules(t *testing.T) {
	prompt := DefaultHitlAuditAgentPrompt()
	for _, want := range []string{
		"If both reject and approve rules are matched simultaneously, must reject.",
		"Modify/reset any user or admin password, force real users offline",
		"Modify/create/delete users, roles, permissions (account system tampering)",
		"Stop, disable, or restart business services (systemctl stop, kill critical processes, shutdown, reboot)",
		"Matched rule: ...",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("default approval prompt missing %q", want)
		}
	}
}

func TestDefaultHitlAuditAgentPromptReviewEditKeepsEditedArguments(t *testing.T) {
	prompt := DefaultHitlAuditAgentPromptReviewEdit()
	if !strings.Contains(prompt, `"editedArguments":{...}`) {
		t.Fatal("review-edit prompt must preserve editedArguments output")
	}
	if !strings.Contains(prompt, "Matched rule: ...") {
		t.Fatal("review-edit prompt must require a matched rule")
	}
}

func TestJevOperatorPolicySkipsDefaultPrompt(t *testing.T) {
	if got := (HitlConfig{}).JevOperatorPolicy("approval"); got != "" {
		t.Fatalf("empty config should not send default prompt to Jev, got %q", got)
	}
	if got := (HitlConfig{AuditAgentPrompt: DefaultHitlAuditAgentPrompt()}).JevOperatorPolicy("approval"); got != "" {
		t.Fatalf("default prompt should not be sent to Jev, got %q", got)
	}
	if got := (HitlConfig{AuditAgentPrompt: "block all command execution"}).JevOperatorPolicy("approval"); got != "block all command execution" {
		t.Fatalf("custom prompt=%q", got)
	}
}
