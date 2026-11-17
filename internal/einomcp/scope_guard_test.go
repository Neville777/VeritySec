package einomcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"veritysec/internal/agent"
	"veritysec/internal/audit"
	"veritysec/internal/config"
	"veritysec/internal/mcp"

	"go.uber.org/zap"
)

type fakeSource struct {
	engagement string
	scope      string
	lookupErr  error
}

func (f fakeSource) ConversationEngagementID(string) (string, error) {
	return f.engagement, f.lookupErr
}
func (f fakeSource) EngagementScopeJSON(string) (json.RawMessage, error) {
	return json.RawMessage(f.scope), nil
}

type scopeHarness struct {
	mu       sync.Mutex
	calls    int
	events   []string
	eventDat []interface{}
	audits   []audit.Entry
	tool     *mcpBridgeTool
}

const testScope = `{"included":["*.example.com","10.0.0.0/24"],"excluded":["admin.example.com"]}`

// fakeResolve answers from a table; unknown names resolve to a public address, "fail.example.com"
// fails. It never touches DNS.
func fakeResolve(table map[string]string) Resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "fail.example.com" {
			return nil, errors.New("no such host")
		}
		if v, ok := table[host]; ok {
			return []netip.Addr{netip.MustParseAddr(v)}, nil
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
}

func newHarness(t *testing.T, src ScopeSource, enabled bool) *scopeHarness {
	return newHarnessR(t, src, enabled, fakeResolve(nil))
}

func newHarnessR(t *testing.T, src ScopeSource, enabled bool, res Resolver) *scopeHarness {
	t.Helper()
	h := &scopeHarness{}
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
	holder.Set("conv-1")
	guard := NewScopeGuard(ScopeGuardConfig{
		Enabled: enabled, ConversationID: "conv-1", Source: src, Resolve: res,
		Progress: func(ev, msg string, data interface{}) {
			h.events = append(h.events, ev+"|"+msg)
			h.eventDat = append(h.eventDat, data)
		},
		Audit: func(e audit.Entry) { h.audits = append(h.audits, e) },
	})
	h.tool = &mcpBridgeTool{name: "probe", agent: ag, holder: holder, scopeGuard: guard}
	return h
}

func (h *scopeHarness) run(t *testing.T, args string) string {
	t.Helper()
	out, err := h.tool.InvokableRun(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

func TestScopeHookRefusesOutOfScopeWithoutInvokingTool(t *testing.T) {
	h := newHarness(t, fakeSource{engagement: "eng-1", scope: testScope}, true)
	for _, args := range []string{
		`{"target":"evil.org"}`, `{"url":"https://admin.example.com/x"}`, `{"host":"10.0.1.1"}`,
		`{"target":"not a target"}`, `{"targets":["a.example.com","evil.org"]}`,
	} {
		out := h.run(t, args)
		if !strings.HasPrefix(out, ToolErrorPrefix+"scope check refused: ") {
			t.Fatalf("%s: expected refusal, got %q", args, out)
		}
	}
	if h.calls != 0 {
		t.Fatalf("tool invoked %d times despite refusal", h.calls)
	}
}

func TestScopeHookRefusalText(t *testing.T) {
	h := newHarness(t, fakeSource{engagement: "eng-1", scope: testScope}, true)
	out := h.run(t, `{"target":"evil.org"}`)
	if out != ToolErrorPrefix+"scope check refused: evil.org: matches no included rule" {
		t.Fatalf("got %q", out)
	}
}

func TestScopeHookAllowsInScopeAndNoTarget(t *testing.T) {
	h := newHarness(t, fakeSource{engagement: "eng-1", scope: testScope}, true)
	if out := h.run(t, `{"target":"www.example.com"}`); out != "ran" {
		t.Fatalf("got %q", out)
	}
	if out := h.run(t, `{"url":"https://a.example.com:8443/p?q=1","other":"10.0.0.9"}`); out != "ran" {
		t.Fatalf("got %q", out)
	}
	if out := h.run(t, `{"count":3,"note":"hello there"}`); out != "ran" {
		t.Fatalf("no-target call must proceed: %q", out)
	}
	if out := h.run(t, ``); out != "ran" {
		t.Fatalf("empty args must proceed: %q", out)
	}
	if h.calls != 4 {
		t.Fatalf("calls = %d", h.calls)
	}
	if len(h.events) != 0 || len(h.audits) != 0 {
		t.Fatal("allowed calls must not be recorded as refusals")
	}
}

func TestScopeHookNoEngagementSkipsCheck(t *testing.T) {
	h := newHarness(t, fakeSource{engagement: "", scope: `{`}, true)
	if out := h.run(t, `{"target":"evil.org"}`); out != "ran" {
		t.Fatalf("got %q", out)
	}
}

func TestScopeHookFlagOffSkipsCheck(t *testing.T) {
	h := newHarness(t, fakeSource{engagement: "eng-1", scope: testScope}, false)
	if h.tool.scopeGuard != nil {
		t.Fatal("guard must be nil when enforcement is off")
	}
	if out := h.run(t, `{"target":"evil.org"}`); out != "ran" {
		t.Fatalf("got %q", out)
	}
	cfg := config.MultiAgentEinoMiddlewareConfig{}
	if !cfg.EngagementScopeEnforcementEffective() {
		t.Fatal("default must be enabled")
	}
	off := false
	cfg.EngagementScopeEnforcement = &off
	if cfg.EngagementScopeEnforcementEffective() {
		t.Fatal("explicit false must disable")
	}
}

func TestScopeHookFailsClosed(t *testing.T) {
	for name, src := range map[string]fakeSource{
		"malformed scope": {engagement: "eng-1", scope: `{"included":[1]}`},
		"empty scope":     {engagement: "eng-1", scope: ``},
		"lookup error":    {lookupErr: errors.New("db down")},
		"expired":         {engagement: "eng-1", scope: `{"included":["*.example.com"],"expires_at":"2000-01-01T00:00:00Z"}`},
	} {
		h := newHarness(t, src, true)
		out := h.run(t, `{"target":"www.example.com"}`)
		if !strings.HasPrefix(out, ToolErrorPrefix+"scope check refused: ") || h.calls != 0 {
			t.Errorf("%s: got %q calls=%d", name, out, h.calls)
		}
	}
}

func TestScopeHookRecordsRefusal(t *testing.T) {
	h := newHarness(t, fakeSource{engagement: "eng-1", scope: testScope}, true)
	h.run(t, `{"target":"evil.org","secret":"do-not-log"}`)
	if len(h.events) != 1 || !strings.HasPrefix(h.events[0], "scope_refused|") {
		t.Fatalf("events = %v", h.events)
	}
	data := h.eventDat[0].(map[string]interface{})
	if data["target"] != "evil.org" || data["reason"] != "matches no included rule" || data["engagementId"] != "eng-1" {
		t.Fatalf("data = %#v", data)
	}
	if len(h.audits) != 1 {
		t.Fatalf("audits = %d", len(h.audits))
	}
	a := h.audits[0]
	if a.Action != "scope_refused" || a.ResourceID != "eng-1" || a.Result != "failure" {
		t.Fatalf("audit = %#v", a)
	}
	blob, _ := json.Marshal([]interface{}{h.events, h.eventDat, h.audits})
	if strings.Contains(string(blob), "do-not-log") {
		t.Fatal("tool arguments other than the target must not be recorded")
	}
}

func TestNewScopeGuardNilCases(t *testing.T) {
	if NewScopeGuard(ScopeGuardConfig{Enabled: true, ConversationID: "", Source: fakeSource{}}) != nil {
		t.Fatal("no conversation => nil")
	}
	if NewScopeGuard(ScopeGuardConfig{Enabled: true, ConversationID: "c"}) != nil {
		t.Fatal("no source => nil")
	}
}

func TestScopeHookFreeText(t *testing.T) {
	h := newHarness(t, fakeSource{engagement: "eng-1", scope: `{"included":["10.1.1.0/24"]}`}, true)
	out := h.run(t, `{"command":"nmap -sV 10.9.9.9 && curl http://evil.example"}`)
	if out != ToolErrorPrefix+"scope check refused: 10.9.9.9: matches no included rule" {
		t.Fatalf("got %q", out)
	}
	if h.calls != 0 {
		t.Fatal("tool ran")
	}
	if out := h.run(t, `{"command":"nmap -sV 10.1.1.7"}`); out != "ran" {
		t.Fatalf("got %q", out)
	}
	if out := h.run(t, `{"command":"nmap 10.1.1.7 ; curl evil.example"}`); !strings.Contains(out, "scope check refused") {
		t.Fatalf("got %q", out)
	}
}

const resolveScope = `{"included":["*.example.com","10.0.0.0/24"],"excluded":["10.0.0.128/25"]}`

func TestScopeHookResolvesToExcludedOrInternal(t *testing.T) {
	res := fakeResolve(map[string]string{"x.example.com": "10.0.0.200", "lo.example.com": "127.0.0.1", "ok.example.com": "10.0.0.5"})
	h := newHarnessR(t, fakeSource{engagement: "eng-1", scope: resolveScope}, true, res)
	for _, host := range []string{"x.example.com", "lo.example.com"} {
		out := h.run(t, `{"target":"`+host+`"}`)
		if !strings.Contains(out, "resolves to out-of-scope address") {
			t.Fatalf("%s: got %q", host, out)
		}
	}
	if out := h.run(t, `{"url":"https://ok.example.com/a","c":"curl www.example.com"}`); out != "ran" {
		t.Fatalf("got %q", out)
	}
	h2 := newHarnessR(t, fakeSource{engagement: "eng-1", scope: `{"included":["lo.example.com","127.0.0.0/8"]}`}, true, res)
	if out := h2.run(t, `{"target":"lo.example.com"}`); out != "ran" {
		t.Fatalf("explicit loopback include: %q", out)
	}
}

func TestScopeHookResolutionFailureRecordsUnresolved(t *testing.T) {
	h := newHarness(t, fakeSource{engagement: "eng-1", scope: resolveScope}, true)
	if out := h.run(t, `{"target":"fail.example.com"}`); out != "ran" {
		t.Fatalf("name decision must stand: %q", out)
	}
	if len(h.audits) != 1 || h.audits[0].Action != "scope_unresolved" {
		t.Fatalf("audits = %#v", h.audits)
	}
	if h.audits[0].Detail["reason"] != "unresolved" {
		t.Fatalf("detail = %#v", h.audits[0].Detail)
	}
}

func TestScopeHookResolverCachedPerCallAndTimeout(t *testing.T) {
	n := 0
	res := func(ctx context.Context, host string) ([]netip.Addr, error) {
		n++
		<-ctx.Done() // honours the deadline
		return nil, ctx.Err()
	}
	h := newHarnessR(t, fakeSource{engagement: "eng-1", scope: resolveScope}, true, res)
	h.tool.scopeGuard = NewScopeGuard(ScopeGuardConfig{Enabled: true, ConversationID: "conv-1",
		Source: fakeSource{engagement: "eng-1", scope: resolveScope}, Resolve: res,
		ResolveTimeout: 20 * time.Millisecond, Audit: func(e audit.Entry) { h.audits = append(h.audits, e) }})
	if out := h.run(t, `{"target":"a.example.com","u":"https://a.example.com/x","c":"curl http://a.example.com:81"}`); out != "ran" {
		t.Fatalf("got %q", out)
	}
	if n != 1 {
		t.Fatalf("resolver called %d times, want 1", n)
	}
}
