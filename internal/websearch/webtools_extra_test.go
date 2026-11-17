package websearch

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var refusedURLs = []string{
	"http://10.1.2.3/", "file:///etc/passwd",
	"http://user:pw@example.com/", "http://169.254.169.254/latest/meta-data/",
}

func TestFirecrawlAndPlaywrightRefuseBadURLs(t *testing.T) {
	// A fake API that must never be reached.
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	oldBase, oldClient := firecrawlBaseURL, firecrawlClient
	firecrawlBaseURL, firecrawlClient = srv.URL, srv.Client()
	defer func() { firecrawlBaseURL, firecrawlClient = oldBase, oldClient }()
	oldLookup := playwrightLookup
	playwrightLookup = func() (string, error) { t.Fatal("playwright must not be looked up for a refused URL"); return "", nil }
	defer func() { playwrightLookup = oldLookup }()

	for _, u := range refusedURLs {
		if _, err := Firecrawl(context.Background(), "k", u); err == nil {
			t.Errorf("firecrawl accepted %q", u)
		}
		if _, err := PlaywrightFetch(context.Background(), u); err == nil {
			t.Errorf("playwright accepted %q", u)
		}
	}
	if hit {
		t.Fatal("firecrawl API was called for a refused URL")
	}
}

func TestFirecrawlCallsAPIWithKeyAndCapsOutput(t *testing.T) {
	var gotAuth, gotURL string
	var gotFormats []interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(b, &body)
		gotURL, _ = body["url"].(string)
		gotFormats, _ = body["formats"].([]interface{})
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    map[string]interface{}{"markdown": strings.Repeat("a", maxTextChars+500)},
		})
	}))
	defer srv.Close()
	oldBase, oldClient := firecrawlBaseURL, firecrawlClient
	firecrawlBaseURL, firecrawlClient = srv.URL, srv.Client()
	defer func() { firecrawlBaseURL, firecrawlClient = oldBase, oldClient }()

	out, err := Firecrawl(context.Background(), "fc-secret", "https://93.184.216.34/page")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer fc-secret" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if gotURL != "https://93.184.216.34/page" || len(gotFormats) != 1 || gotFormats[0] != "markdown" {
		t.Errorf("request body wrong: url=%q formats=%v", gotURL, gotFormats)
	}
	if !strings.HasSuffix(out, "[truncated]") || len(out) > maxTextChars+20 {
		t.Errorf("output not capped: len=%d", len(out))
	}
}

func TestFirecrawlErrorsHideKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad key fc-secret", http.StatusUnauthorized)
	}))
	defer srv.Close()
	oldBase, oldClient := firecrawlBaseURL, firecrawlClient
	firecrawlBaseURL, firecrawlClient = srv.URL, srv.Client()
	defer func() { firecrawlBaseURL, firecrawlClient = oldBase, oldClient }()
	_, err := Firecrawl(context.Background(), "fc-secret", "https://93.184.216.34/")
	if err == nil || strings.Contains(err.Error(), "fc-secret") {
		t.Fatalf("expected an error without the key, got %v", err)
	}
	if _, err := Firecrawl(context.Background(), "", "https://93.184.216.34/"); err == nil {
		t.Fatal("empty key must be refused")
	}
}

func TestFirecrawlUsesSafeClientByDefault(t *testing.T) {
	// The real client must refuse to dial a link-local/metadata API address (loopback is allowed).
	old := firecrawlBaseURL
	firecrawlBaseURL = "http://169.254.169.254/v1/scrape"
	defer func() { firecrawlBaseURL = old }()
	if _, err := Firecrawl(context.Background(), "k", "https://93.184.216.34/"); err == nil {
		t.Fatal("safe client should refuse a link-local address")
	}
}

func TestPlaywrightRefusesWhenBinaryMissing(t *testing.T) {
	old := playwrightLookup
	playwrightLookup = func() (string, error) { return "", errors.New("playwright is not installed: none") }
	defer func() { playwrightLookup = old }()
	_, err := PlaywrightFetch(context.Background(), "https://93.184.216.34/")
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("expected clear not-installed error, got %v", err)
	}
}

func TestPythonForReadsShebang(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "playwright")
	if err := os.WriteFile(bin, []byte("#!/usr/bin/python3\nprint(1)\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("no /usr/bin/python3")
	}
	got, err := pythonFor(bin)
	if err != nil || got != "/usr/bin/python3" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestPlaywrightScriptIsFixedAndGuarded(t *testing.T) {
	for _, want := range []string{"accept_downloads=False", "ctx.route(", "route.abort()", "timeout=30000", "service_workers=\"block\""} {
		if !strings.Contains(playwrightScript, want) {
			t.Errorf("script missing %q", want)
		}
	}
}

func TestDefaultProvidersOffByDefault(t *testing.T) {
	found := map[string]Provider{}
	for _, p := range DefaultProviders() {
		found[p.ID] = p
	}
	fc, ok := found["firecrawl"]
	if !ok || !fc.NeedKey || fc.Enabled || fc.Hint == "" {
		t.Errorf("firecrawl default wrong: %+v", fc)
	}
	if pw, ok := found["playwright"]; !ok || pw.Enabled || pw.NeedKey {
		t.Errorf("playwright default wrong: %+v", pw)
	}
}
