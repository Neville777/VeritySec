package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veritysec/internal/audit"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type engFixture struct {
	t      *testing.T
	db     *database.DB
	router *gin.Engine
	root   string
}

func newEngFixture(t *testing.T, scope string) *engFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "eng.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	root := filepath.Join(t.TempDir(), "evidence")
	h := NewEngagementHandler(db, root, zap.NewNop())
	h.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{UserID: "u1", Scope: scope, Permissions: map[string]bool{"project:read": true, "project:write": true, "project:delete": true}})
		c.Next()
	})
	r.GET("/engagements", h.ListEngagements)
	r.POST("/engagements", h.CreateEngagement)
	r.GET("/engagements/:id", h.GetEngagement)
	r.PUT("/engagements/:id", h.UpdateEngagement)
	r.DELETE("/engagements/:id", h.DeleteEngagement)
	r.POST("/engagements/:id/conversations", h.AttachConversation)
	r.POST("/engagements/:id/evidence", h.CreateEvidence)
	r.GET("/engagements/:id/evidence", h.ListEvidence)
	r.GET("/engagements/:id/report", h.GetReport)
	r.GET("/evidence/:id", h.GetEvidence)
	r.GET("/engagements/:id/export", h.ExportEngagementCSV)
	r.GET("/engagements/:id/stages", h.ListStages)
	r.POST("/engagements/:id/stages/:stage/start", h.StartStage)
	r.POST("/engagements/:id/stages/:stage/complete", h.CompleteStage)
	r.POST("/engagements/:id/stages/:stage/skip", h.SkipStage)
	r.GET("/engagements/:id/stages/:stage/tasks", h.ListStageTasks)
	r.POST("/engagements/:id/stages/:stage/tasks", h.CreateStageTask)
	r.PUT("/stage-tasks/:id", h.UpdateStageTask)
	return &engFixture{t: t, db: db, router: r, root: root}
}

func (f *engFixture) do(method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *engFixture) json(method, path string, v interface{}, out interface{}) int {
	b, _ := json.Marshal(v)
	w := f.do(method, path, "application/json", b)
	if out != nil {
		_ = json.Unmarshal(w.Body.Bytes(), out)
	}
	return w.Code
}

func TestEngagementCRUD(t *testing.T) {
	f := newEngFixture(t, database.RBACScopeAll)
	var e database.Engagement
	if code := f.json("POST", "/engagements", map[string]interface{}{"name": "  "}, nil); code != 400 {
		t.Fatalf("blank name: %d", code)
	}
	if code := f.json("POST", "/engagements", map[string]interface{}{"name": "n", "status": "bogus"}, nil); code != 400 {
		t.Fatalf("bad status: %d", code)
	}
	if code := f.json("POST", "/engagements", map[string]interface{}{"name": "n", "scope_json": []string{"x"}}, nil); code != 400 {
		t.Fatalf("scope array accepted: %d", code)
	}
	if code := f.json("POST", "/engagements", map[string]interface{}{"name": "Acme", "target": "acme.example", "scope_json": map[string]interface{}{"included": []string{"acme.example"}}, "authorization_note": "SOW-1"}, &e); code != 200 || e.ID == "" || e.Status != "draft" || e.OwnerUserID != "u1" {
		t.Fatalf("create: %d %+v", code, e)
	}
	var got database.Engagement
	if code := f.json("GET", "/engagements/"+e.ID, nil, &got); code != 200 || got.Name != "Acme" || !strings.Contains(string(got.ScopeJSON), "acme.example") {
		t.Fatalf("get: %d %+v", code, got)
	}
	if code := f.json("PUT", "/engagements/"+e.ID, map[string]interface{}{"name": "Acme 2", "status": "active"}, &got); code != 200 || got.Name != "Acme 2" || got.Status != "active" {
		t.Fatalf("put: %d %+v", code, got)
	}
	var list struct {
		Engagements []database.Engagement `json:"engagements"`
	}
	if code := f.json("GET", "/engagements?status=active", nil, &list); code != 200 || len(list.Engagements) != 1 {
		t.Fatalf("list: %d %+v", code, list)
	}
	if code := f.json("GET", "/engagements?status=archived", nil, &list); code != 200 || len(list.Engagements) != 0 {
		t.Fatalf("filtered list: %d %+v", code, list)
	}
	if code := f.json("PUT", "/engagements/nope", map[string]interface{}{"name": "x"}, nil); code != 404 {
		t.Fatalf("put missing: %d", code)
	}
	if code := f.json("DELETE", "/engagements/"+e.ID, nil, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if code := f.json("GET", "/engagements/"+e.ID, nil, nil); code != 404 {
		t.Fatalf("get after delete: %d", code)
	}
}

func TestScopedUserDoesNotSeeUnassignedEngagements(t *testing.T) {
	f := newEngFixture(t, database.RBACScopeAssigned)
	if _, err := f.db.CreateEngagement(&database.Engagement{Name: "other team", OwnerUserID: "someone-else"}); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Engagements []database.Engagement `json:"engagements"`
	}
	f.json("GET", "/engagements", nil, &list)
	if len(list.Engagements) != 0 {
		t.Fatalf("assigned-scope user saw %d engagements", len(list.Engagements))
	}
}

func TestEvidenceLifecycleAndHashVerification(t *testing.T) {
	f := newEngFixture(t, database.RBACScopeAll)
	var e database.Engagement
	f.json("POST", "/engagements", map[string]interface{}{"name": "Acme", "status": "active"}, &e)

	conv, err := f.db.CreateConversation("scan", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.db.CreateVulnerability(&database.Vulnerability{ConversationID: conv.ID, Title: "SQLi", Severity: "high", Status: "open", Type: "sql injection", Target: "acme.example"})
	if err != nil {
		t.Fatal(err)
	}
	if code := f.json("POST", "/engagements/"+e.ID+"/conversations", map[string]string{"conversation_id": "missing"}, nil); code != 404 {
		t.Fatalf("attach missing conv: %d", code)
	}
	if code := f.json("POST", "/engagements/"+e.ID+"/conversations", map[string]string{"conversation_id": conv.ID}, nil); code != 200 {
		t.Fatalf("attach: %d", code)
	}

	// JSON text evidence linked to the finding that came in through the attached conversation.
	var ev database.Evidence
	secret := "GET /login HTTP/1.1\nAuthorization: Bearer SECRET-TOKEN\n"
	if code := f.json("POST", "/engagements/"+e.ID+"/evidence", map[string]string{"kind": "http_exchange", "title": "login", "content": secret, "finding_id": v.ID, "source_tool": "curl"}, &ev); code != 200 || ev.SHA256 == "" || ev.SizeBytes != int64(len(secret)) {
		t.Fatalf("create evidence: %d %+v", code, ev)
	}
	if strings.Contains(ev.StoragePath, "..") || !strings.HasPrefix(ev.StoragePath, e.ID+"/") {
		t.Fatalf("storage path = %q", ev.StoragePath)
	}
	info, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(ev.StoragePath)))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence file perms = %v err=%v", info, err)
	}
	// A finding outside the engagement and an unknown kind are rejected.
	other, _ := f.db.CreateVulnerability(&database.Vulnerability{Title: "x", Severity: "low", Status: "open"})
	if code := f.json("POST", "/engagements/"+e.ID+"/evidence", map[string]string{"kind": "note", "content": "c", "finding_id": other.ID}, nil); code != 400 {
		t.Fatalf("foreign finding accepted: %d", code)
	}
	if code := f.json("POST", "/engagements/"+e.ID+"/evidence", map[string]string{"kind": "weird", "content": "c"}, nil); code != 400 {
		t.Fatalf("bad kind accepted: %d", code)
	}
	if code := f.json("POST", "/engagements/"+e.ID+"/evidence", map[string]string{"kind": "note", "content": ""}, nil); code != 400 {
		t.Fatalf("empty content accepted: %d", code)
	}

	// Multipart binary evidence: metadata only on read.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("kind", "screenshot")
	fw, _ := mw.CreateFormFile("file", "shot.png")
	fw.Write([]byte{0x89, 'P', 'N', 'G', 0, 1, 2})
	mw.Close()
	var shot database.Evidence
	w := f.do("POST", "/engagements/"+e.ID+"/evidence", mw.FormDataContentType(), buf.Bytes())
	json.Unmarshal(w.Body.Bytes(), &shot)
	if w.Code != 200 || shot.Title != "shot.png" || shot.Kind != "screenshot" {
		t.Fatalf("multipart: %d %s", w.Code, w.Body.String())
	}
	var read struct {
		Integrity string `json:"integrity"`
		Content   string `json:"content"`
		Available bool   `json:"content_available"`
	}
	f.json("GET", "/evidence/"+shot.ID, nil, &read)
	if read.Integrity != "verified" || read.Available || read.Content != "" {
		t.Fatalf("screenshot read: %+v", read)
	}

	// Verified read returns text content.
	read.Content = ""
	if code := f.json("GET", "/evidence/"+ev.ID, nil, &read); code != 200 || read.Integrity != "verified" || read.Content != secret {
		t.Fatalf("read: %d %+v", code, read)
	}
	var list struct {
		Total int `json:"total"`
	}
	if f.json("GET", "/engagements/"+e.ID+"/evidence", nil, &list); list.Total != 2 {
		t.Fatalf("evidence list total = %d", list.Total)
	}

	// Report references the evidence hash.
	w = f.do("GET", "/engagements/"+e.ID+"/report?audience=technical&format=md", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), ev.SHA256) || !strings.Contains(w.Body.String(), "Audience: technical") || strings.Contains(w.Body.String(), "SECRET-TOKEN") {
		t.Fatalf("report: %d\n%s", w.Code, w.Body.String())
	}
	for _, q := range []string{"audience=executive&format=html", "audience=developer&format=docx"} {
		if w := f.do("GET", "/engagements/"+e.ID+"/report?"+q, "", nil); w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("report %s: %d", q, w.Code)
		}
	}
	if w := f.do("GET", "/engagements/"+e.ID+"/report?audience=ceo", "", nil); w.Code != 400 {
		t.Fatalf("bad audience: %d", w.Code)
	}
	if w := f.do("GET", "/engagements/"+e.ID+"/report?format=pdf", "", nil); w.Code != 400 {
		t.Fatalf("bad format: %d", w.Code)
	}

	// Tamper: hash mismatch is reported and content withheld.
	path := filepath.Join(f.root, filepath.FromSlash(ev.StoragePath))
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	w = f.do("GET", "/evidence/"+ev.ID, "", nil)
	if w.Code != 409 || !strings.Contains(w.Body.String(), `"integrity":"mismatch"`) || strings.Contains(w.Body.String(), "tampered") {
		t.Fatalf("tamper not detected: %d %s", w.Code, w.Body.String())
	}
	// Missing file is reported too.
	os.Remove(path)
	if w = f.do("GET", "/evidence/"+ev.ID, "", nil); w.Code != 409 || !strings.Contains(w.Body.String(), `"integrity":"missing"`) {
		t.Fatalf("missing not reported: %d %s", w.Code, w.Body.String())
	}

	// Delete removes evidence rows and files, and only unlinks conversation and finding.
	if code := f.json("DELETE", "/engagements/"+e.ID, nil, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if _, err := os.Stat(filepath.Join(f.root, filepath.FromSlash(shot.StoragePath))); !os.IsNotExist(err) {
		t.Fatal("evidence file survived engagement delete")
	}
	if got, err := f.db.GetVulnerability(v.ID); err != nil || got.Title != "SQLi" {
		t.Fatalf("finding lost on engagement delete: %v", err)
	}
}

func TestEvidenceStoreRejectsEscapingPath(t *testing.T) {
	s := &database.EvidenceStore{Root: t.TempDir()}
	if _, err := s.Read(&database.Evidence{StoragePath: "../../etc/passwd"}); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestStageEndpointsAndAudit(t *testing.T) {
	f := newEngFixture(t, "all")
	e, err := f.db.CreateEngagement(&database.Engagement{Name: "e"})
	if err != nil {
		t.Fatal(err)
	}
	base := "/engagements/" + e.ID + "/stages"
	rec := f.do("GET", base, "", nil)
	var list struct {
		Stages []map[string]interface{} `json:"stages"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != 200 || len(list.Stages) != 8 || list.Stages[0]["stage"] != "AUTHORISATION" {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := f.do("POST", base+"/RECONNAISSANCE/start", "", nil); rec.Code != 409 || !strings.Contains(rec.Body.String(), "AUTHORISATION") {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := f.do("POST", base+"/NOPE/start", "", nil); rec.Code != 404 {
		t.Fatal(rec.Code)
	}
	if rec := f.do("POST", base+"/AUTHORISATION/skip", "application/json", []byte(`{"reason":""}`)); rec.Code != 400 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := f.do("POST", base+"/AUTHORISATION/skip", "application/json", []byte(`{"reason":"pre-approved"}`)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"skipped"`) || !strings.Contains(rec.Body.String(), `"u1"`) {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if rec := f.do("POST", base+"/AUTHORISATION/start", "", nil); rec.Code != 409 {
		t.Fatal(rec.Code)
	}
}

func TestStageTransitionWritesAuditWithoutContent(t *testing.T) {
	f := newEngFixture(t, "all")
	svc := audit.NewService(f.db, &config.Config{}, zap.NewNop())
	e, _ := f.db.CreateEngagement(&database.Engagement{Name: "e"})
	if _, err := ApplyStageTransition(f.db, svc, nil, e.ID, "AUTHORISATION", database.StageTransition{Action: "skip", Reason: "secret-reason-text", Actor: "agent"}); err != nil {
		t.Fatal(err)
	}
	rows, err := f.db.ListAuditLogs(database.ListAuditLogsFilter{ResourceID: e.ID, Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatal(err, len(rows))
	}
	r := rows[0]
	if r.Action != "stage_skip" || r.Actor != "agent" || !strings.Contains(fmt.Sprint(r.Detail), "AUTHORISATION") {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(fmt.Sprint(r.Detail), "secret-reason-text") {
		t.Fatal("reason text leaked into audit detail")
	}
	// a refused transition writes nothing
	if _, err := ApplyStageTransition(f.db, svc, nil, e.ID, "AUTHORISATION", database.StageTransition{Action: "start"}); err == nil {
		t.Fatal("terminal stage restarted")
	}
	if rows, _ := f.db.ListAuditLogs(database.ListAuditLogsFilter{ResourceID: e.ID, Limit: 10}); len(rows) != 1 {
		t.Fatal("refused transition was audited")
	}
}

func TestEvidenceUploadProvenance(t *testing.T) {
	f := newEngFixture(t, database.RBACScopeAll)
	e, err := f.db.CreateEngagement(&database.Engagement{Name: "e"})
	if err != nil {
		t.Fatal(err)
	}
	path := "/engagements/" + e.ID + "/evidence"
	// A caller can never set origin or tool_execution_id (JSON or multipart).
	for _, body := range []string{
		`{"kind":"note","content":"c","origin":"tool"}`,
		`{"kind":"note","content":"c","origin":"manual"}`,
		`{"kind":"note","content":"c","tool_execution_id":"exec-1"}`,
	} {
		if rec := f.do("POST", path, "application/json", []byte(body)); rec.Code != 400 {
			t.Fatalf("%s accepted: %d", body, rec.Code)
		}
	}
	for _, field := range []string{"origin", "tool_execution_id"} {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		mw.WriteField(field, "tool")
		fw, _ := mw.CreateFormFile("file", "a.txt")
		fw.Write([]byte("x"))
		mw.Close()
		if rec := f.do("POST", path, mw.FormDataContentType(), buf.Bytes()); rec.Code != 400 {
			t.Fatalf("multipart %s accepted: %d", field, rec.Code)
		}
	}
	if list, _ := f.db.ListEvidence(e.ID); len(list) != 0 {
		t.Fatalf("rejected uploads stored rows: %d", len(list))
	}
	// A normal upload is manual, stamped with the current stage, and the API shows the fields.
	rec := f.do("POST", path, "application/json", []byte(`{"kind":"note","title":"n","content":"hello"}`))
	var got map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &got)
	if rec.Code != 200 || got["origin"] != "manual" || got["stage"] != "AUTHORISATION" {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	if v, present := got["tool_execution_id"]; !present || v != "" {
		t.Fatalf("tool_execution_id missing from JSON: %s", rec.Body.String())
	}
	list := f.do("GET", path, "", nil)
	for _, k := range []string{`"origin":"manual"`, `"tool_execution_id"`, `"stage":"AUTHORISATION"`} {
		if !strings.Contains(list.Body.String(), k) {
			t.Fatalf("list lacks %s: %s", k, list.Body.String())
		}
	}
	// CSV export carries origin and stage.
	csv := f.do("GET", "/engagements/"+e.ID+"/export?kind=evidence", "", nil).Body.String()
	if !strings.Contains(csv, "created_at,origin,stage") || !strings.Contains(csv, ",manual,AUTHORISATION") {
		t.Fatalf("csv: %s", csv)
	}
}

// Manual evidence can be attached and listed but never completes a stage; AUTHORISATION is the
// exception and completes on its note and scope.
func TestStageCompletionOverHTTPNeedsToolEvidence(t *testing.T) {
	f := newEngFixture(t, database.RBACScopeAll)
	e, _ := f.db.CreateEngagement(&database.Engagement{Name: "e", AuthorizationNote: "SOW", ScopeJSON: []byte(`{"included":["a.example"]}`)})
	base := "/engagements/" + e.ID
	var manual database.Evidence
	f.json("POST", base+"/evidence", map[string]string{"kind": "note", "content": "c"}, &manual)
	if rec := f.do("POST", base+"/stages/AUTHORISATION/complete", "application/json", []byte(`{"evidence_ids":["`+manual.ID+`"]}`)); rec.Code != 200 {
		t.Fatalf("AUTHORISATION must complete on note and scope: %d %s", rec.Code, rec.Body.String())
	}
	f.do("POST", base+"/stages/RECONNAISSANCE/start", "", nil)
	var manual2 database.Evidence
	f.json("POST", base+"/evidence", map[string]string{"kind": "note", "content": "c2"}, &manual2)
	rec := f.do("POST", base+"/stages/RECONNAISSANCE/complete", "application/json", []byte(`{"evidence_ids":["`+manual2.ID+`"]}`))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "cite at least one tool evidence row recorded during this stage") {
		t.Fatalf("manual evidence completed a stage: %d %s", rec.Code, rec.Body.String())
	}
	tool := database.NewEvidenceRecord(e.ID)
	tool.Kind, tool.StoragePath, tool.SHA256, tool.Origin = database.EvidenceToolOutput, "x", "y", database.EvidenceOriginTool
	if err := f.db.InsertEvidence(tool); err != nil {
		t.Fatal(err)
	}
	if rec := f.do("POST", base+"/stages/RECONNAISSANCE/complete", "application/json", []byte(`{"evidence_ids":["`+tool.ID+`"]}`)); rec.Code != 200 {
		t.Fatalf("tool evidence did not complete: %d %s", rec.Code, rec.Body.String())
	}
}

func TestStageTaskRoutes(t *testing.T) {
	f := newEngFixture(t, database.RBACScopeAll)
	var e database.Engagement
	if code := f.json("POST", "/engagements", map[string]interface{}{"name": "Acme"}, &e); code != 200 {
		t.Fatalf("create: %d", code)
	}
	base := "/engagements/" + e.ID + "/stages/RECONNAISSANCE/tasks"
	var task database.StageTask
	if code := f.json("POST", base, map[string]interface{}{"title": "  "}, nil); code != 400 {
		t.Fatalf("blank title: %d", code)
	}
	if code := f.json("POST", base, map[string]interface{}{"title": "Run DNS enum"}, &task); code != 200 || task.ProposedBy != "human" || !task.Required {
		t.Fatalf("create task: %d %+v", code, task)
	}
	if code := f.json("POST", "/engagements/"+e.ID+"/stages/BOGUS/tasks", map[string]interface{}{"title": "x"}, nil); code != 404 {
		t.Fatalf("bad stage: %d", code)
	}
	var list struct {
		Tasks []database.StageTask `json:"tasks"`
	}
	if code := f.json("GET", base, nil, &list); code != 200 || len(list.Tasks) != 1 {
		t.Fatalf("list: %d %+v", code, list)
	}
	if code := f.json("PUT", "/stage-tasks/"+task.ID, map[string]interface{}{"status": "skipped"}, nil); code != 400 {
		t.Fatalf("skip without reason: %d", code)
	}
	if code := f.json("PUT", "/stage-tasks/"+task.ID, map[string]interface{}{"status": "skipped", "reason": "out of scope"}, &task); code != 200 || task.Status != "skipped" {
		t.Fatalf("human skip: %d %+v", code, task)
	}
	if code := f.json("PUT", "/stage-tasks/"+task.ID, map[string]interface{}{"status": "done"}, &task); code != 200 || task.Status != "done" || task.Reason != "" {
		t.Fatalf("done: %d %+v", code, task)
	}
	if code := f.json("PUT", "/stage-tasks/missing", map[string]interface{}{"status": "done"}, nil); code != 404 {
		t.Fatalf("missing task: %d", code)
	}
	if code := f.json("GET", "/engagements/missing/stages/RECONNAISSANCE/tasks", nil, nil); code != 404 {
		t.Fatalf("missing engagement: %d", code)
	}
}
