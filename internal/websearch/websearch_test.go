package websearch

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateURLBlocksInternalTargets(t *testing.T) {
	blocked := []string{
		"http://10.1.2.3/", "http://192.168.8.1/",
		"http://172.16.0.5/", "http://169.254.169.254/latest/meta-data", "http://100.88.19.41/",
		"file:///etc/passwd", "ftp://example.com/", "http://user:pass@example.com/",
	}
	for _, u := range blocked {
		if _, err := ValidateURL(u); err == nil {
			t.Errorf("expected %q to be refused", u)
		}
	}
	for _, u := range []string{"http://127.0.0.1:8080/", "http://localhost:8080/", "http://app.localhost/", "http://[::1]/", "http://127.5.5.5/"} {
		if _, err := ValidateURL(u); err != nil {
			t.Errorf("loopback %q should now be allowed: %v", u, err)
		}
	}
	if _, err := ValidateURL("https://example.com/page"); err != nil {
		t.Errorf("public URL refused: %v", err)
	}
}

func TestIsBlockedIP(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0"} {
		if !isBlockedIP(net.ParseIP(ip)) {
			t.Errorf("%s should be blocked", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "127.9.9.9", "::1"} {
		if isBlockedIP(net.ParseIP(ip)) {
			t.Errorf("loopback %s should be allowed", ip)
		}
	}
	if isBlockedIP(net.ParseIP("93.184.216.34")) {
		t.Error("public address should be allowed")
	}
}

func TestHTMLToTextDropsScriptsAndTags(t *testing.T) {
	page := []byte("<html><head><title>T</title><script>var secret=1</script></head><body><h1>Hello</h1><p>World <b>now</b></p><style>p{}</style></body></html>")
	got := HTMLToText(page)
	if strings.Contains(got, "secret") || strings.Contains(got, "p{}") {
		t.Fatalf("script or style leaked: %q", got)
	}
	if !strings.Contains(got, "Hello") || !strings.Contains(got, "World now") {
		t.Fatalf("visible text missing: %q", got)
	}
}

func TestParseDuckDuckGoResults(t *testing.T) {
	page := `<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa&amp;rut=x">Example <b>A</b></a><a class="result__snippet" href="#">Snippet one</a>`
	res := parseDuckDuckGo(page, 5)
	if len(res) != 1 || res[0].URL != "https://example.com/a" || res[0].Title != "Example A" {
		t.Fatalf("unexpected parse: %+v", res)
	}
}

func TestSearchWithoutProvidersSaysSo(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"brave", "tavily", "serpapi", "duckduckgo"} {
		off := false
		if err := store.Update(id, nil, &off, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := Search(context.Background(), store, "test", 3); err == nil || !strings.Contains(err.Error(), "no search provider") {
		t.Fatalf("expected a clear no-provider error, got %v", err)
	}
}

func TestKeysAreMaskedAndPersistedPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store, _ := NewStore(path)
	key := "secret-key-1234"
	if err := store.Update("tavily", &key, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range store.List() {
		if p.ID == "tavily" && p.MaskedKey() != "••••1234" {
			t.Fatalf("key not masked: %q", p.MaskedKey())
		}
	}
	reloaded, _ := NewStore(path)
	found := false
	for _, p := range reloaded.List() {
		if p.ID == "tavily" && p.Key == key {
			found = true
		}
	}
	if !found {
		t.Fatal("key was not persisted")
	}
}
