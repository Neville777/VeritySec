package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newProjectWorkspaceRouter(t *testing.T, sess security.Session) (*gin.Engine, *database.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "w.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ph := NewProjectHandler(db, zap.NewNop())
	eh := NewEngagementHandler(db, filepath.Join(t.TempDir(), "evidence"), zap.NewNop())
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(security.ContextSessionKey, sess); c.Next() })
	r.GET("/projects/:id/workspace", ph.GetProjectWorkspace)
	r.POST("/engagements", eh.CreateEngagement)
	r.PUT("/engagements/:id", eh.UpdateEngagement)
	return r, db
}

// seedProjectFixture creates one project with one conversation, one finding (via the
// conversation), one asset, one engagement (with its own finding, asset and evidence) and one
// chat upload artifact, all tagged so a test can tell two projects' rows apart.
func seedProjectFixture(t *testing.T, db *database.DB, tag string) (projectID string) {
	t.Helper()
	p, err := db.CreateProject(&database.Project{Name: "Project " + tag})
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("conv-"+tag, database.ConversationCreateMeta{ProjectID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateVulnerability(&database.Vulnerability{
		ConversationID: conv.ID, Title: "finding-" + tag, Severity: "high",
	}); err != nil {
		t.Fatal(err)
	}
	eng, err := db.CreateEngagement(&database.Engagement{Name: "engagement-" + tag, ProjectID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assets (id, dedup_key, project_id, host, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "asset-"+tag, "dedup-"+tag, p.ID, "host-"+tag, time.Now(), time.Now(), time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	ev := database.NewEvidenceRecord(eng.ID)
	ev.Kind = database.EvidenceNote
	ev.Title = "evidence-" + tag
	ev.StoragePath = "x"
	ev.SHA256 = "deadbeef"
	if err := db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertChatUploadArtifact("uploads/"+tag+"/file.txt", conv.ID, "owner-"+tag); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO batch_task_queues (id, title, status, created_at, project_id)
		VALUES (?, ?, ?, ?, ?)`, "queue-"+tag, "queue-"+tag, "idle", time.Now(), p.ID); err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func TestProjectWorkspaceScopesRowsPerProject(t *testing.T) {
	r, db := newProjectWorkspaceRouter(t, security.Session{UserID: "admin", Scope: database.RBACScopeAll})
	projectA := seedProjectFixture(t, db, "a")
	_ = seedProjectFixture(t, db, "b")

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/projects/"+projectA+"/workspace", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	counts := body["counts"].(map[string]interface{})
	for _, key := range []string{"conversations", "findings", "assets", "engagements", "evidence", "files", "batch_queues", "reports"} {
		if got := counts[key].(float64); got != 1 {
			t.Errorf("counts.%s = %v, want 1", key, got)
		}
	}
	if got := counts["facts"].(float64); got != 0 {
		t.Errorf("counts.facts = %v, want 0", got)
	}

	findings := body["findings"].([]interface{})
	if len(findings) != 1 {
		t.Fatalf("findings leaked across projects: %v", findings)
	}
	title := findings[0].(map[string]interface{})["title"].(string)
	if title != "finding-a" {
		t.Errorf("finding title = %q, want finding-a (project B's rows must not leak in)", title)
	}

	assets := body["assets"].([]interface{})
	if len(assets) != 1 || assets[0].(map[string]interface{})["host"].(string) != "host-a" {
		t.Fatalf("assets leaked across projects: %v", assets)
	}

	engagements := body["engagements"].([]interface{})
	if len(engagements) != 1 || engagements[0].(map[string]interface{})["name"].(string) != "engagement-a" {
		t.Fatalf("engagements leaked across projects: %v", engagements)
	}
	engID := engagements[0].(map[string]interface{})["id"].(string)

	evidence := body["evidence"].([]interface{})
	if len(evidence) != 1 || evidence[0].(map[string]interface{})["title"].(string) != "evidence-a" {
		t.Fatalf("evidence leaked across projects: %v", evidence)
	}

	files := body["files"].([]interface{})
	if len(files) != 1 {
		t.Fatalf("files leaked across projects: %v", files)
	}
	file := files[0].(map[string]interface{})
	if file["path"].(string) != "uploads/a/file.txt" || file["id"].(string) != "uploads/a/file.txt" {
		t.Errorf("file path/id = %v, want relative_path \"uploads/a/file.txt\"", file)
	}
	if file["name"].(string) != "file.txt" {
		t.Errorf("file name = %v, want file.txt", file["name"])
	}

	batchQueues := body["batch_queues"].([]interface{})
	if len(batchQueues) != 1 || batchQueues[0].(map[string]interface{})["id"].(string) != "queue-a" {
		t.Fatalf("batch_queues leaked across projects: %v", batchQueues)
	}

	reports := body["reports"].([]interface{})
	if len(reports) != 1 {
		t.Fatalf("reports = %v, want one entry", reports)
	}
	report := reports[0].(map[string]interface{})
	if report["engagement_id"].(string) != engID || report["engagement_name"].(string) != "engagement-a" {
		t.Fatalf("report entry = %v", report)
	}
	downloads := report["downloads"].([]interface{})
	if len(downloads) != 9 {
		t.Fatalf("downloads = %d, want 9 (3 audiences x 3 formats)", len(downloads))
	}
	wantPath := "/api/engagements/" + engID + "/report?audience=executive&format=md"
	found := false
	for _, d := range downloads {
		dm := d.(map[string]interface{})
		if dm["audience"] == "executive" && dm["format"] == "md" {
			found = true
			if dm["path"].(string) != wantPath {
				t.Errorf("download path = %q, want %q", dm["path"], wantPath)
			}
		}
	}
	if !found {
		t.Fatalf("missing executive/md download entry: %v", downloads)
	}
}

func TestProjectWorkspaceAccessDeniedReturns404(t *testing.T) {
	r, db := newProjectWorkspaceRouter(t, security.Session{UserID: "outsider", Scope: database.RBACScopeAssigned})
	p, err := db.CreateProject(&database.Project{Name: "private"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("project", p.ID, "owner"); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/projects/"+p.ID+"/workspace", nil)
	r.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("status %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestProjectWorkspaceUnknownProject404(t *testing.T) {
	r, _ := newProjectWorkspaceRouter(t, security.Session{UserID: "admin", Scope: database.RBACScopeAll})
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/projects/does-not-exist/workspace", nil)
	r.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("status %d, want 404: %s", w.Code, w.Body.String())
	}
}

// createRBACUser inserts a minimal rbac_users row so AssignResourceToUser's foreign key check
// passes for id.
func createRBACUser(t *testing.T, db *database.DB, id string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO rbac_users (id, username, display_name, password_hash, enabled, created_at, updated_at)
		VALUES (?, ?, '', 'x', 1, ?, ?)`, id, id, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestCreateEngagementAcceptsAndValidatesProjectID(t *testing.T) {
	r, db := newProjectWorkspaceRouter(t, security.Session{
		UserID: "u1", Scope: database.RBACScopeAssigned,
		Permissions: map[string]bool{"project:read": true, "project:write": true},
	})
	createRBACUser(t, db, "u1")
	allowed, err := db.CreateProject(&database.Project{Name: "allowed"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser("u1", "project", allowed.ID); err != nil {
		t.Fatal(err)
	}
	denied, err := db.CreateProject(&database.Project{Name: "denied"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetResourceOwner("project", denied.ID, "someone-else"); err != nil {
		t.Fatal(err)
	}

	// Accepted: the caller can read the project it names.
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/engagements", jsonBody(t, map[string]string{"name": "eng1", "project_id": allowed.ID}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
	}
	var created database.Engagement
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ProjectID != allowed.ID {
		t.Errorf("project_id = %q, want %q", created.ProjectID, allowed.ID)
	}

	// Rejected: the caller cannot read the project it names.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/engagements", jsonBody(t, map[string]string{"name": "eng2", "project_id": denied.ID}))
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)
	if w2.Code != 403 {
		t.Fatalf("status %d, want 403: %s", w2.Code, w2.Body.String())
	}
}

func TestUpdateEngagementProjectChangeRequiresWriteOnBothProjects(t *testing.T) {
	r, db := newProjectWorkspaceRouter(t, security.Session{
		UserID: "u1", Scope: database.RBACScopeAssigned,
		Permissions: map[string]bool{"project:read": true, "project:write": true},
	})
	createRBACUser(t, db, "u1")
	source, err := db.CreateProject(&database.Project{Name: "source"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := db.CreateProject(&database.Project{Name: "target"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser("u1", "project", source.ID); err != nil {
		t.Fatal(err)
	}
	// Deliberately no assignment for target: u1 can read/write source only.
	eng, err := db.CreateEngagement(&database.Engagement{Name: "eng", ProjectID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AssignResourceToUser("u1", "engagement", eng.ID); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/engagements/"+eng.ID, jsonBody(t, map[string]string{"name": "eng", "project_id": target.ID}))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("status %d, want 403 (no write access to target project): %s", w.Code, w.Body.String())
	}

	// Now grant access to target too; the move must succeed.
	if err := db.AssignResourceToUser("u1", "project", target.ID); err != nil {
		t.Fatal(err)
	}
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("PUT", "/engagements/"+eng.ID, jsonBody(t, map[string]string{"name": "eng", "project_id": target.ID}))
	req2.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("status %d, want 200: %s", w2.Code, w2.Body.String())
	}
	var updated database.Engagement
	if err := json.Unmarshal(w2.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.ProjectID != target.ID {
		t.Errorf("project_id = %q, want %q", updated.ProjectID, target.ID)
	}
}

func jsonBody(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}
