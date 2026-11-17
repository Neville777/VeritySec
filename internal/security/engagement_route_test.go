package security

import (
	"net/http"
	"testing"
)

func TestEngagementAndEvidenceRoutesMapToProjectPermissions(t *testing.T) {
	cases := []struct{ method, path, want string }{
		{http.MethodGet, "/api/engagements", "project:read"},
		{http.MethodPost, "/api/engagements", "project:write"},
		{http.MethodGet, "/api/engagements/:id", "project:read"},
		{http.MethodPut, "/api/engagements/:id", "project:write"},
		{http.MethodDelete, "/api/engagements/:id", "project:delete"},
		{http.MethodPost, "/api/engagements/:id/conversations", "project:write"},
		{http.MethodPost, "/api/engagements/:id/findings", "project:write"},
		{http.MethodPost, "/api/engagements/:id/assets", "project:write"},
		{http.MethodPost, "/api/engagements/:id/evidence", "project:write"},
		{http.MethodGet, "/api/engagements/:id/evidence", "project:read"},
		{http.MethodGet, "/api/engagements/:id/report", "project:read"},
		{http.MethodGet, "/api/engagements/:id/report-snapshots", "project:read"},
		{http.MethodGet, "/api/report-snapshots/:id", "project:read"},
		{http.MethodGet, "/api/engagements/:id/stages", "project:read"},
		{http.MethodPost, "/api/engagements/:id/stages/:stage/start", "project:write"},
		{http.MethodPost, "/api/engagements/:id/stages/:stage/complete", "project:write"},
		{http.MethodPost, "/api/engagements/:id/stages/:stage/skip", "project:write"},
		{http.MethodGet, "/api/engagements/:id/stages/:stage/tasks", "project:read"},
		{http.MethodPost, "/api/engagements/:id/stages/:stage/tasks", "project:write"},
		{http.MethodPut, "/api/stage-tasks/:id", "project:write"},
		{http.MethodGet, "/api/engagements/:id/approvals", "project:read"},
		{http.MethodPost, "/api/approval-requests/:id/decision", "project:write"},
		{http.MethodGet, "/api/engagements/:id/approvals", "project:read"},
		{http.MethodPost, "/api/approval-requests/:id/decision", "project:write"},
		{http.MethodGet, "/api/evidence/:id", "project:read"},
		{http.MethodGet, "/api/engagements/:id/asset-graph", "project:read"},
		{http.MethodPost, "/api/engagements/:id/asset-relationships", "project:write"},
		{http.MethodPut, "/api/asset-relationships/:id", "project:write"},
		{http.MethodPost, "/api/evidence/purge", "config:write"},
	}
	for _, tc := range cases {
		got := permissionForRequest(tc.method, tc.path)
		if got != tc.want {
			t.Errorf("%s %s = %q, want %q", tc.method, tc.path, got, tc.want)
		}
		if _, ok := PermissionCatalog[got]; !ok {
			t.Errorf("%q not in catalog", got)
		}
	}
}
