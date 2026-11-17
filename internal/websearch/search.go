package websearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Result is one search hit.
type Result struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
	Date    string `json:"date,omitempty"`
}

// Provider is one search API. A provider with no key set is skipped.
type Provider struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	NeedKey bool   `json:"needKey"`
	Enabled bool   `json:"enabled"`
	Order   int    `json:"order"`
	Key     string `json:"-"` // never returned to the UI; see MaskedKey
	Hint    string `json:"hint"`
}

// MaskedKey shows only the last four characters of a key.
func (p Provider) MaskedKey() string {
	if p.Key == "" {
		return ""
	}
	if len(p.Key) <= 4 {
		return "••••"
	}
	return "••••" + p.Key[len(p.Key)-4:]
}

// Configured reports whether the provider can be called.
func (p Provider) Configured() bool {
	return p.Enabled && (!p.NeedKey || p.Key != "")
}

// searcher runs one query against one provider.
type searcher func(ctx context.Context, key, query string, n int) ([]Result, error)

var searchers = map[string]searcher{
	"brave":      searchBrave,
	"tavily":     searchTavily,
	"serpapi":    searchSerpAPI,
	"duckduckgo": searchDuckDuckGo,
}

// Attempt records how one provider did during a search.
type Attempt struct {
	Provider string `json:"provider"`
	Error    string `json:"error,omitempty"`
}

// Search runs the query through the configured providers in order and returns the first
// provider that answers. Providers that fail are recorded and the next one is tried, so one
// broken or rate-limited API does not stop the search.
func Search(ctx context.Context, store *Store, query string, n int) ([]Result, string, []Attempt, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, "", nil, errors.New("query is empty")
	}
	if n <= 0 || n > 20 {
		n = 8
	}
	var attempts []Attempt
	for _, p := range store.Ordered() {
		if !p.Configured() {
			continue
		}
		fn, ok := searchers[p.ID]
		if !ok {
			continue
		}
		results, err := fn(ctx, p.Key, query, n)
		if err == nil && len(results) > 0 {
			return results, p.ID, attempts, nil
		}
		msg := "no results"
		if err != nil {
			msg = err.Error()
		}
		attempts = append(attempts, Attempt{Provider: p.ID, Error: msg})
		if ctx.Err() != nil {
			break
		}
	}
	if len(attempts) == 0 {
		return nil, "", nil, errors.New("no search provider is configured; add an API key in Settings → Web search")
	}
	return nil, "", attempts, errors.New("every search provider failed or returned no results")
}

func getJSON(ctx context.Context, method, endpoint string, headers map[string]string, body []byte, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := defaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
	}
	return json.Unmarshal(raw, out)
}

func searchBrave(ctx context.Context, key, query string, n int) ([]Result, error) {
	var out struct {
		Web struct {
			Results []struct {
				Title       string `json:"title"`
				URL         string `json:"url"`
				Description string `json:"description"`
				PageAge     string `json:"page_age"`
			} `json:"results"`
		} `json:"web"`
	}
	endpoint := "https://api.search.brave.com/res/v1/web/search?q=" + url.QueryEscape(query) + fmt.Sprintf("&count=%d", n)
	if err := getJSON(ctx, http.MethodGet, endpoint, map[string]string{"X-Subscription-Token": key}, nil, &out); err != nil {
		return nil, err
	}
	res := make([]Result, 0, len(out.Web.Results))
	for _, r := range out.Web.Results {
		res = append(res, Result{Title: r.Title, URL: r.URL, Snippet: r.Description, Date: r.PageAge})
	}
	return res, nil
}

func searchTavily(ctx context.Context, key, query string, n int) ([]Result, error) {
	var out struct {
		Results []struct {
			Title         string `json:"title"`
			URL           string `json:"url"`
			Content       string `json:"content"`
			PublishedDate string `json:"published_date"`
		} `json:"results"`
	}
	body, _ := json.Marshal(map[string]interface{}{"api_key": key, "query": query, "max_results": n})
	if err := getJSON(ctx, http.MethodPost, "https://api.tavily.com/search", nil, body, &out); err != nil {
		return nil, err
	}
	res := make([]Result, 0, len(out.Results))
	for _, r := range out.Results {
		res = append(res, Result{Title: r.Title, URL: r.URL, Snippet: r.Content, Date: r.PublishedDate})
	}
	return res, nil
}

func searchSerpAPI(ctx context.Context, key, query string, n int) ([]Result, error) {
	var out struct {
		Organic []struct {
			Title   string `json:"title"`
			Link    string `json:"link"`
			Snippet string `json:"snippet"`
			Date    string `json:"date"`
		} `json:"organic_results"`
	}
	endpoint := "https://serpapi.com/search.json?engine=google&q=" + url.QueryEscape(query) +
		fmt.Sprintf("&num=%d&api_key=%s", n, url.QueryEscape(key))
	if err := getJSON(ctx, http.MethodGet, endpoint, nil, nil, &out); err != nil {
		return nil, err
	}
	res := make([]Result, 0, len(out.Organic))
	for _, r := range out.Organic {
		res = append(res, Result{Title: r.Title, URL: r.Link, Snippet: r.Snippet, Date: r.Date})
	}
	return res, nil
}

// searchDuckDuckGo is the keyless fallback. It reads the HTML results page.
func searchDuckDuckGo(ctx context.Context, _ string, query string, n int) ([]Result, error) {
	endpoint := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) VeritySec/1.0")
	resp, err := defaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return parseDuckDuckGo(string(raw), n), nil
}

// parseDuckDuckGo pulls title, link and snippet out of the DuckDuckGo HTML results.
func parseDuckDuckGo(page string, n int) []Result {
	var out []Result
	parts := strings.Split(page, `class="result__a"`)
	for i := 1; i < len(parts) && len(out) < n; i++ {
		seg := parts[i]
		href := attr(seg, "href=\"")
		title := textBetween(seg, ">", "</a>")
		snippet := textBetween(seg[strings.Index(seg, "result__snippet"):], ">", "</a>")
		if href == "" {
			continue
		}
		if u, err := url.Parse(href); err == nil {
			if real := u.Query().Get("uddg"); real != "" {
				href = real
			}
		}
		out = append(out, Result{Title: stripTags(title), URL: href, Snippet: stripTags(snippet)})
	}
	return out
}

func attr(s, prefix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	s = s[i+len(prefix):]
	j := strings.Index(s, `"`)
	if j < 0 {
		return ""
	}
	return strings.ReplaceAll(s[:j], "&amp;", "&")
}

func textBetween(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	s = s[i+len(start):]
	j := strings.Index(s, end)
	if j < 0 {
		return ""
	}
	return s[:j]
}

func stripTags(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(html.UnescapeString(b.String()))
}

// ---- provider store ---------------------------------------------------------

// Store keeps provider settings (order, enabled flag, API keys). Keys stay on this machine.
type Store struct {
	mu    sync.RWMutex
	path  string
	items []Provider
}

// DefaultProviders are the built-in providers, in their default order.
func DefaultProviders() []Provider {
	return []Provider{
		{ID: "brave", Name: "Brave Search", NeedKey: true, Enabled: true, Order: 1, Hint: "https://brave.com/search/api/"},
		{ID: "tavily", Name: "Tavily", NeedKey: true, Enabled: true, Order: 2, Hint: "https://tavily.com"},
		{ID: "serpapi", Name: "SerpAPI (Google results)", NeedKey: true, Enabled: true, Order: 3, Hint: "https://serpapi.com"},
		{ID: "duckduckgo", Name: "DuckDuckGo (no key)", NeedKey: false, Enabled: true, Order: 4, Hint: "Keyless fallback; may rate-limit"},
		{ID: "browser", Name: "Headless browser (Chrome)", NeedKey: false, Enabled: false, Order: 99, Hint: "Off by default. Loads pages with JavaScript; a page can still make its own requests."},
		{ID: "firecrawl", Name: "Firecrawl (page scrape)", NeedKey: true, Enabled: false, Order: 90, Hint: "Off by default. Needs an API key (https://firecrawl.dev). Sends the URL to Firecrawl's servers; returns markdown."},
		{ID: "playwright", Name: "Playwright (headless Chromium)", NeedKey: false, Enabled: false, Order: 98, Hint: "Off by default. Uses the installed playwright CLI; every request is checked and internal addresses are blocked."},
	}
}

// Ordered returns the providers sorted by their order value.
func (s *Store) Ordered() []Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Provider(nil), s.items...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Order < out[j-1].Order; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// List returns providers for display; keys are masked.
func (s *Store) List() []Provider {
	return s.Ordered()
}

// Update changes one provider's key, enabled flag or order. An empty key keeps the stored key.
func (s *Store) Update(id string, key *string, enabled *bool, order *int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.items {
		if s.items[i].ID != id {
			continue
		}
		if key != nil && strings.TrimSpace(*key) != "" {
			s.items[i].Key = strings.TrimSpace(*key)
		}
		if enabled != nil {
			s.items[i].Enabled = *enabled
		}
		if order != nil {
			s.items[i].Order = *order
		}
		return s.saveLocked()
	}
	return fmt.Errorf("unknown provider %q", id)
}

// Test runs a small query through one provider and reports whether it works.
func (s *Store) Test(ctx context.Context, id string) error {
	s.mu.RLock()
	var p *Provider
	for i := range s.items {
		if s.items[i].ID == id {
			cp := s.items[i]
			p = &cp
		}
	}
	s.mu.RUnlock()
	if p == nil {
		return fmt.Errorf("unknown provider %q", id)
	}
	if id == "firecrawl" {
		if p.Key == "" {
			return errors.New("no API key set")
		}
		_, err := Firecrawl(ctx, p.Key, "https://example.com/")
		return err
	}
	fn, ok := searchers[id]
	if !ok {
		return fmt.Errorf("no test available for %q", id)
	}
	if p.NeedKey && p.Key == "" {
		return errors.New("no API key set")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res, err := fn(ctx, p.Key, "cybersecurity news", 1)
	if err != nil {
		return err
	}
	if len(res) == 0 {
		return errors.New("provider answered but returned no results")
	}
	return nil
}
