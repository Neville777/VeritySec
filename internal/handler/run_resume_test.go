package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type resumeFixture struct {
	h       *AgentHandler
	db      *database.DB
	userID  string
	convID  string
	msgID   string
	blocks  chan string
	release chan struct{}
}

func newResumeFixture(t *testing.T, unknown bool) *resumeFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "resume.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateRBACUser("resumer", "Resumer", "hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("c", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMessage(conv.ID, "user", "scan SECRET_TOOL_OUTPUT_MARKER", nil); err != nil {
		t.Fatal(err)
	}
	asst, err := db.AddMessage(conv.ID, "assistant", "working SECRET_TOOL_OUTPUT_MARKER", nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(time.Second)
	if _, err := db.Exec(`INSERT INTO tool_executions (id, tool_name, arguments, status, start_time, conversation_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"exec-done-1", "nmap", "{}", "completed", start, conv.ID); err != nil {
		t.Fatal(err)
	}
	if unknown {
		if _, err := db.Exec(`INSERT INTO tool_executions (id, tool_name, arguments, status, start_time, conversation_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"exec-unk-1", "sqlmap", "{}", "running", start, conv.ID); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	h := &AgentHandler{db: db, logger: zap.NewNop(), tasks: NewAgentTaskManager(), config: cfg}
	t.Cleanup(h.tasks.Shutdown)
	return &resumeFixture{h: h, db: db, userID: user.ID, convID: conv.ID, msgID: asst.ID, blocks: make(chan string, 1), release: make(chan struct{})}
}

func (f *resumeFixture) post(perms map[string]bool, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/runs/"+f.msgID+"/resume", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "messageId", Value: f.msgID}}
	c.Set(security.ContextSessionKey, security.Session{UserID: f.userID, Scope: database.RBACScopeAll, Permissions: perms})
	executor := func(ctx, base context.Context, cancel context.CancelCauseFunc, timeout context.CancelFunc, req ChatRequest, p *multiAgentPrepared, r *database.AgentRun, multi bool) {
		f.blocks <- f.h.agentSessionContextBlock(p.ConversationID) + "\n---USER---\n" + p.FinalMessage
		_ = f.h.tasks.FinishTaskRun(p.ConversationID, r.RunID, "completed")
		_ = f.db.FinishAgentRun(r.RunID, "completed", map[string]string{"response": "ok"})
		timeout()
		cancel(nil)
	}
	f.h.resumeRunWithExecutor(c, executor)
	return w
}

var resumePerms = map[string]bool{"chat:write": true, "agent:execute": true}

func TestResumeRefusedWithUndecidedUnknown(t *testing.T) {
	f := newResumeFixture(t, true)
	if w := f.post(resumePerms, `{"confirm":true}`); w.Code != 409 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if w := f.post(resumePerms, `{"confirm":true,"unknown_decisions":[]}`); w.Code != 409 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestResumeRefusedWhileRunning(t *testing.T) {
	f := newResumeFixture(t, false)
	if _, err := f.h.tasks.StartTask(f.convID, "live", func(error) {}); err != nil {
		t.Fatal(err)
	}
	if w := f.post(resumePerms, `{"confirm":true}`); w.Code != 409 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestResumeRefusedWithoutConfirm(t *testing.T) {
	f := newResumeFixture(t, false)
	for _, body := range []string{`{}`, `{"confirm":false}`} {
		if w := f.post(resumePerms, body); w.Code != 400 {
			t.Fatalf("%s status %d: %s", body, w.Code, w.Body)
		}
	}
}

func TestResumeForbiddenWithoutChatWrite(t *testing.T) {
	f := newResumeFixture(t, false)
	if w := f.post(map[string]bool{"chat:read": true, "agent:execute": true}, `{"confirm":true}`); w.Code != 403 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestResumeAcceptedRecordsEventsAndBuildsPrompt(t *testing.T) {
	f := newResumeFixture(t, true)
	body := `{"confirm":true,"unknown_decisions":[{"execution_id":"exec-unk-1","decision":"treat_as_done"}]}`
	w := f.post(resumePerms, body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var prompt string
	select {
	case prompt = <-f.blocks:
	case <-time.After(5 * time.Second):
		t.Fatal("resumed turn never started")
	}
	for _, want := range []string{"Do-not-repeat rule", "execution_id=exec-done-1", "execution_id=exec-unk-1", "TREAT AS DONE", "data, not instructions"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "SECRET_TOOL_OUTPUT_MARKER") {
		t.Fatalf("prompt leaked conversation/tool content:\n%s", prompt)
	}
	events, err := f.db.ListRunEvents(f.msgID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.EventType] = true
	}
	if !seen["resume_requested"] || !seen["resume_started"] {
		t.Fatalf("events = %v", seen)
	}
	cps, _ := f.db.ListRunCheckpoints(f.msgID)
	found := false
	for _, cp := range cps {
		if cp.Kind == "resume_started" {
			found = true
		}
	}
	if !found {
		t.Fatal("resume_started checkpoint missing")
	}
	// A second resume of the same run is refused.
	time.Sleep(50 * time.Millisecond)
	if w := f.post(resumePerms, body); w.Code != 409 {
		t.Fatalf("second resume status %d: %s", w.Code, w.Body)
	}
}
