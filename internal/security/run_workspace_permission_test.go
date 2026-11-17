package security

import (
	"net/http"
	"testing"
)

// TestRunWorkspacePermissionMapsToChatRead verifies the run workspace route is mapped to
// chat:read, and only for GET as the route is read-only.
func TestRunWorkspacePermissionMapsToChatRead(t *testing.T) {
	if got := permissionForRequest(http.MethodGet, "/api/runs/msg-1/workspace"); got != "chat:read" {
		t.Fatalf("permission = %q, want chat:read", got)
	}
}

// TestResumePlanPermissionMapsToChatRead verifies the read-only resume-plan route is mapped to
// chat:read, same as the run workspace route it sits next to.
func TestResumePlanPermissionMapsToChatRead(t *testing.T) {
	if got := permissionForRequest(http.MethodGet, "/api/runs/msg-1/resume-plan"); got != "chat:read" {
		t.Fatalf("permission = %q, want chat:read", got)
	}
}

func TestRunEventsRequiresChatRead(t *testing.T) {
	if got := permissionForRequest(http.MethodGet, "/api/runs/msg-1/events"); got != "chat:read" {
		t.Fatalf("runs events permission = %q, want chat:read", got)
	}
}
