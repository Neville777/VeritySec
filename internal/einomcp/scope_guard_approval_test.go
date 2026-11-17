package einomcp

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"veritysec/internal/agent"
	"veritysec/internal/audit"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/mcp"

	"go.uber.org/zap"
)

type approvalHarness struct {
	db     *database.DB
	eng    string
	tool   *mcpBridgeTool
	mu     sync.Mutex
	calls  int
	now    time.Time
	events []string
	audits []audit.Entry
}

func newApprovalHarness(t *testing.T, required []string) *approvalHarness {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "a.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e, err := db.CreateEngagement(&database.Engagement{Name: "e", Status: "active", ScopeJSON: []byte(testScope)})
	if err != nil {
		t.Fatal(err)
	}
	conv, err := db.CreateConversation("c", database.ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AttachConversationToEngagement(e.ID, conv.ID); err != nil {
		t.Fatal(err)
	}
	h := &approvalHarness{db: db, eng: e.ID, now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	server := mcp.NewServer(zap.NewNop())
	server.RegisterTool(mcp.Tool{Name: "probe", InputSchema: map[string]interface{}{"type": "object"}},
		func(context.Context, map[string]interface{}) (*mcp.ToolResult, error) {
			h.mu.Lock()
			h.calls++
			h.mu.Unlock()
			return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: "ran"}}}, nil
		})
	ag := agent.NewAgent(&config.OpenAIConfig{}, &config.AgentConfig{}, server, nil, zap.NewNop(), 1)
	holder := &ConversationHolder{}
	holder.Set(conv.ID)
	guard := NewScopeGuard(ScopeGuardConfig{
		Enabled: true, ConversationID: conv.ID, Source: NewDBScopeSource(db),
		Progress:              func(ev, msg string, _ interface{}) { h.events = append(h.events, ev+"|"+msg) },
		Audit:                 func(en audit.Entry) { h.audits = append(h.audits, en) },
		Now:                   func() time.Time { return h.now },
		Resolve:               func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil },
		ApprovalRequiredTools: required, Approvals: NewDBApprovalStore(db), ApprovalTTL: 30 * time.Minute,
	})
	h.tool = &mcpBridgeTool{name: "probe", agent: ag, holder: holder, scopeGuard: guard}
	return h
}

func (h *approvalHarness) run(t *testing.T, args string) string {
	t.Helper()
	out, err := h.tool.InvokableRun(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

func (h *approvalHarness) pendingID(t *testing.T, out string) string {
	t.Helper()
	const p = "approval required: "
	i := strings.Index(out, p)
	if i < 0 {
		t.Fatalf("not an approval refusal: %q", out)
	}
	rest := out[i+len(p):]
	id := rest[:strings.Index(rest, ";")]
	if !strings.Contains(out, "a person must approve it in the engagement page") {
		t.Fatalf("text: %q", out)
	}
	return id
}

const riskyArgs = `{"target":"www.example.com","mode":"x"}`

func TestApprovalRefusedThenApprovedRunsOnce(t *testing.T) {
	h := newApprovalHarness(t, []string{"probe"})
	out := h.run(t, riskyArgs)
	id := h.pendingID(t, out)
	if h.calls != 0 {
		t.Fatal("tool ran without approval")
	}
	if len(h.events) != 1 || !strings.HasPrefix(h.events[0], "approval_requested|") || strings.Contains(h.events[0], "mode") {
		t.Fatalf("events: %v", h.events)
	}
	if len(h.audits) != 1 || h.audits[0].Action != "approval_requested" {
		t.Fatalf("audits: %+v", h.audits)
	}
	// Same call again while pending reuses the request and still does not run.
	if id2 := h.pendingID(t, h.run(t, riskyArgs)); id2 != id || h.calls != 0 {
		t.Fatalf("pending reuse: %s vs %s calls=%d", id2, id, h.calls)
	}
	if _, err := h.db.DecideApproval(id, true, "u1", "ok", h.now, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	// Different arguments do not match the approval.
	h.pendingID(t, h.run(t, `{"target":"www.example.com","mode":"y"}`))
	if h.calls != 0 {
		t.Fatal("different arguments must not use the approval")
	}
	if out := h.run(t, riskyArgs); out != "ran" || h.calls != 1 {
		t.Fatalf("approved call: %q calls=%d", out, h.calls)
	}
	// Second call after use is refused again with a new request.
	id3 := h.pendingID(t, h.run(t, riskyArgs))
	if id3 == id || h.calls != 1 {
		t.Fatalf("approval reused: %s calls=%d", id3, h.calls)
	}
}

func TestApprovalExpiredAndDenied(t *testing.T) {
	h := newApprovalHarness(t, []string{"probe"})
	id := h.pendingID(t, h.run(t, riskyArgs))
	if _, err := h.db.DecideApproval(id, true, "u1", "", h.now, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(31 * time.Minute)
	h.pendingID(t, h.run(t, riskyArgs))
	if h.calls != 0 {
		t.Fatal("expired approval allowed the call")
	}

	h2 := newApprovalHarness(t, []string{"probe"})
	id = h2.pendingID(t, h2.run(t, riskyArgs))
	a, err := h2.db.DecideApproval(id, false, "u1", "too risky", h2.now, 30*time.Minute)
	if err != nil || a.Status != database.ApprovalDenied || a.DecisionReason != "too risky" || a.DecidedBy != "u1" {
		t.Fatalf("deny: %+v %v", a, err)
	}
	h2.pendingID(t, h2.run(t, riskyArgs))
	if h2.calls != 0 {
		t.Fatal("denied request allowed the call")
	}
}

func TestApprovalNotRequiredAndNoArgumentsStored(t *testing.T) {
	h := newApprovalHarness(t, nil)
	if out := h.run(t, riskyArgs); out != "ran" {
		t.Fatalf("empty list must not gate: %q", out)
	}
	h = newApprovalHarness(t, []string{"probe"})
	h.run(t, `{"target":"www.example.com","password":"s3cr3t-value"}`)
	rows, err := h.db.Query(`SELECT * FROM approval_requests`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	for _, c := range cols {
		if strings.HasPrefix(c, "arg") && c != "arguments_hash" {
			t.Fatalf("unexpected column %s", c)
		}
	}
	n := 0
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			if strings.Contains(strings.ToLower(anyString(v)), "s3cr3t") {
				t.Fatalf("argument content stored: %v", v)
			}
		}
		n++
	}
	if n != 1 {
		t.Fatalf("rows=%d", n)
	}
}

func anyString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}
