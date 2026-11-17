package app

import (
	"path/filepath"
	"testing"

	"veritysec/internal/mcp"
	"veritysec/internal/scope"
	"veritysec/internal/websearch"

	"go.uber.org/zap"
)

func toolNames(s *mcp.Server) map[string]bool {
	out := map[string]bool{}
	for _, t := range s.GetAllTools() {
		out[t.Name] = true
	}
	return out
}

func TestOptionalWebToolsGatedByEnabledFlag(t *testing.T) {
	store, err := websearch.NewStore(filepath.Join(t.TempDir(), "p.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := mcp.NewServer(zap.NewNop())
	registerWebTools(srv, store)
	names := toolNames(srv)
	if names["web_firecrawl_scrape"] || names["web_playwright_fetch"] {
		t.Fatal("optional tools must be absent by default")
	}

	yes := true
	key := "fc-test-key"
	_ = store.Update("firecrawl", nil, &yes, nil) // enabled but no key
	srv = mcp.NewServer(zap.NewNop())
	registerWebTools(srv, store)
	if toolNames(srv)["web_firecrawl_scrape"] {
		t.Fatal("firecrawl must not register without a key")
	}
	_ = store.Update("firecrawl", &key, nil, nil)
	_ = store.Update("playwright", nil, &yes, nil)
	srv = mcp.NewServer(zap.NewNop())
	registerWebTools(srv, store)
	names = toolNames(srv)
	if !names["web_firecrawl_scrape"] || !names["web_playwright_fetch"] {
		t.Fatalf("expected both tools once enabled and configured: %v", names)
	}

	// Turning it off stops the already-registered tool at call time.
	no := false
	_ = store.Update("firecrawl", nil, &no, nil)
	res, _, err := srv.CallTool(t.Context(), "web_firecrawl_scrape", map[string]interface{}{"url": "https://93.184.216.34/"})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("disabled firecrawl tool must return an error result")
	}
}

func TestScopeGuardSeesURLArgumentOfNewTools(t *testing.T) {
	for _, tool := range []string{"web_firecrawl_scrape", "web_playwright_fetch"} {
		got := scope.ExtractTargets(tool, map[string]interface{}{"url": "https://target.example/page"})
		if len(got) != 1 || got[0] != "https://target.example/page" {
			t.Errorf("%s: scope extraction missed url argument: %v", tool, got)
		}
		if scope.NonNetworkTools[tool] {
			t.Errorf("%s must not be exempt from scope checks", tool)
		}
	}
}
