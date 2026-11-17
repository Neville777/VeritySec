package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newSessionRouter(t *testing.T, sess security.Session) (*gin.Engine, *database.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "j.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := NewEngagementHandler(db, filepath.Join(t.TempDir(), "evidence"), zap.NewNop())
	h.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(security.ContextSessionKey, sess); c.Next() })
	r.GET("/engagements/:id/report", h.GetReport)
	r.POST("/engagements/:id/findings", h.AttachFinding)
	r.POST("/engagements/:id/assets", h.AttachAsset)
	return r, db
}

func doReq(r *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestReportAudienceInferenceAndAttachmentHeaders(t *testing.T) {
	cases := []struct {
		name     string
		roles    []string
		userID   string
		query    string
		audience string
		reason   string
	}{
		{"explicit wins over admin role", []string{"admin"}, "u9", "?audience=developer", "developer", "query parameter"},
		{"admin role is technical", []string{"admin"}, "u9", "", "technical", "role admin"},
		{"owner role is technical", []string{"Owner"}, "u9", "", "technical", "role owner"},
		{"other role is executive", []string{"viewer"}, "u9", "", "executive", "default"},
		{"no role is executive", nil, "u9", "", "executive", "default"},
		{"engagement owner is technical", []string{"viewer"}, "u1", "", "technical", "engagement owner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, db := newSessionRouter(t, security.Session{UserID: tc.userID, Roles: tc.roles, Scope: database.RBACScopeAll})
			e, err := db.CreateEngagement(&database.Engagement{Name: "Acme", OwnerUserID: "u1"})
			if err != nil {
				t.Fatal(err)
			}
			w := doReq(r, "GET", "/engagements/"+e.ID+"/report"+tc.query, nil)
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("X-Report-Audience"); got != tc.audience {
				t.Errorf("audience = %q, want %q", got, tc.audience)
			}
			if got := w.Header().Get("X-Report-Audience-Reason"); got != tc.reason {
				t.Errorf("reason = %q, want %q", got, tc.reason)
			}
			cd := w.Header().Get("Content-Disposition")
			if !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, e.ID) || !strings.Contains(cd, tc.audience) || !strings.HasSuffix(cd, `.md"`) {
				t.Errorf("Content-Disposition = %q", cd)
			}
		})
	}
}

func TestReportFormatsAndInlineFlag(t *testing.T) {
	r, db := newSessionRouter(t, security.Session{UserID: "u1", Scope: database.RBACScopeAll})
	e, _ := db.CreateEngagement(&database.Engagement{Name: "Acme"})
	w := doReq(r, "GET", "/engagements/"+e.ID+"/report?format=html", nil)
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.HasSuffix(cd, `.html"`) || !strings.Contains(cd, "executive") {
		t.Errorf("html disposition = %q", cd)
	}
	w = doReq(r, "GET", "/engagements/"+e.ID+"/report?format=html&inline=1", nil)
	if cd := w.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("inline=1 should not set a disposition, got %q", cd)
	}
	if w.Header().Get("X-Report-Audience") != "executive" {
		t.Errorf("inline audience header missing")
	}
	w = doReq(r, "GET", "/engagements/"+e.ID+"/report?format=docx&inline=1", nil)
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("docx must stay an attachment, got %q", cd)
	}
}

func TestAudienceDoesNotChangeDataset(t *testing.T) {
	r, db := newSessionRouter(t, security.Session{UserID: "u1", Roles: []string{"admin"}, Scope: database.RBACScopeAll})
	e, _ := db.CreateEngagement(&database.Engagement{Name: "Acme"})
	if _, err := db.CreateVulnerability(&database.Vulnerability{Title: "SQLi", Severity: "high", Target: "a.example"}); err != nil {
		t.Fatal(err)
	}
	a := doReq(r, "GET", "/engagements/"+e.ID+"/report", nil).Header().Get("X-Report-Dataset-Hash")
	b := doReq(r, "GET", "/engagements/"+e.ID+"/report?audience=executive", nil).Header().Get("X-Report-Dataset-Hash")
	if a == "" || a != b {
		t.Fatalf("dataset hash differs by audience: %q vs %q", a, b)
	}
}

func joinSession() security.Session {
	return security.Session{UserID: "u1", Scope: database.RBACScopeAll, Permissions: map[string]bool{
		"project:write": true, "vulnerability:write": true, "asset:write": true,
	}}
}

func TestStandaloneFindingJoinRejectsRecordOwnedByAnotherEngagement(t *testing.T) {
	r, db := newSessionRouter(t, joinSession())
	e1, _ := db.CreateEngagement(&database.Engagement{Name: "one"})
	e2, _ := db.CreateEngagement(&database.Engagement{Name: "two"})
	v, err := db.CreateVulnerability(&database.Vulnerability{Title: "XSS", Severity: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	owner := func() string {
		var s string
		db.QueryRow(`SELECT COALESCE(engagement_id,'') FROM vulnerabilities WHERE id = ?`, v.ID).Scan(&s)
		return s
	}
	if w := doReq(r, "POST", "/engagements/"+e1.ID+"/findings", map[string]interface{}{"vulnerability_id": v.ID}); w.Code != 200 || owner() != e1.ID {
		t.Fatalf("first join: %d %s owner=%s", w.Code, w.Body.String(), owner())
	}
	if w := doReq(r, "POST", "/engagements/"+e1.ID+"/findings", map[string]interface{}{"vulnerability_id": v.ID}); w.Code != 200 {
		t.Fatalf("rejoin same engagement should be a no-op: %d", w.Code)
	}
	if w := doReq(r, "POST", "/engagements/"+e2.ID+"/findings", map[string]interface{}{"vulnerability_id": v.ID}); w.Code != 409 || owner() != e1.ID {
		t.Fatalf("join to other engagement: %d %s owner=%s", w.Code, w.Body.String(), owner())
	}
	if w := doReq(r, "POST", "/engagements/"+e2.ID+"/findings", map[string]interface{}{"vulnerability_id": v.ID, "force": true}); w.Code != 200 || owner() != e2.ID {
		t.Fatalf("forced move: %d %s owner=%s", w.Code, w.Body.String(), owner())
	}
	if w := doReq(r, "POST", "/engagements/"+e2.ID+"/findings", map[string]interface{}{"vulnerability_id": "nope"}); w.Code != 404 {
		t.Fatalf("missing finding: %d", w.Code)
	}
	if w := doReq(r, "POST", "/engagements/nope/findings", map[string]interface{}{"vulnerability_id": v.ID}); w.Code != 403 && w.Code != 404 {
		t.Fatalf("missing engagement: %d", w.Code)
	}
}

func TestStandaloneAssetJoinAndPermissionChecks(t *testing.T) {
	r, db := newSessionRouter(t, joinSession())
	e1, _ := db.CreateEngagement(&database.Engagement{Name: "one"})
	e2, _ := db.CreateEngagement(&database.Engagement{Name: "two"})
	if _, err := db.UpsertAssets([]*database.Asset{{Host: "a.example", Port: 443, Protocol: "https"}}, "u1", true); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := db.QueryRow(`SELECT id FROM assets LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if w := doReq(r, "POST", "/engagements/"+e1.ID+"/assets", map[string]interface{}{"asset_id": id}); w.Code != 200 {
		t.Fatalf("join asset: %d %s", w.Code, w.Body.String())
	}
	if w := doReq(r, "POST", "/engagements/"+e2.ID+"/assets", map[string]interface{}{"asset_id": id}); w.Code != 409 {
		t.Fatalf("asset owned by other engagement: %d", w.Code)
	}
	if w := doReq(r, "POST", "/engagements/"+e1.ID+"/assets", map[string]interface{}{}); w.Code != 400 {
		t.Fatalf("missing id: %d", w.Code)
	}
	// Without asset:write the join is refused even with project:write.
	r2, db2 := newSessionRouter(t, security.Session{UserID: "u1", Scope: database.RBACScopeAll, Permissions: map[string]bool{"project:write": true}})
	e, _ := db2.CreateEngagement(&database.Engagement{Name: "x"})
	if w := doReq(r2, "POST", "/engagements/"+e.ID+"/assets", map[string]interface{}{"asset_id": "a"}); w.Code != 403 {
		t.Fatalf("missing permission: %d", w.Code)
	}
}
