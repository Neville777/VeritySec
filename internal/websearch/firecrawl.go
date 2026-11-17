package websearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// firecrawlBaseURL and firecrawlClient are variables only so tests can point at an httptest
// server. Production code always uses the real API and the safe HTTP client.
var (
	firecrawlBaseURL = "https://api.firecrawl.dev/v1/scrape"
	firecrawlClient  = NewHTTPClient()
)

// resolveCheck refuses hosts that resolve to an internal address. It fails closed: if the host
// cannot be resolved, it cannot be checked, so it is refused. Overridable in tests.
var resolveCheck = func(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return ErrBlockedAddress
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("cannot verify host %q: %v", host, err)
	}
	for _, a := range addrs {
		if isBlockedIP(a.IP) {
			return ErrBlockedAddress
		}
	}
	return nil
}

// Firecrawl scrapes one already-public URL through the Firecrawl API and returns markdown.
// The target URL is validated first (same rules as Fetch plus a resolve check); the API call
// itself goes through the safe HTTP client. The key travels only in the Authorization header.
func Firecrawl(ctx context.Context, key, raw string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", errors.New("Firecrawl API key is not set")
	}
	u, err := ValidateURL(raw)
	if err != nil {
		return "", err
	}
	if err := resolveCheck(ctx, u.Hostname()); err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]interface{}{
		"url":             u.String(),
		"formats":         []string{"markdown"},
		"onlyMainContent": true,
	})
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, firecrawlBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := firecrawlClient.Do(req)
	if err != nil {
		return "", errors.New(strings.ReplaceAll(err.Error(), key, "[key]"))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return "", fmt.Errorf("firecrawl HTTP %d: %s", resp.StatusCode, strings.ReplaceAll(msg, key, "[key]"))
	}
	var out struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
		Data    struct {
			Markdown string `json:"markdown"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("firecrawl returned unreadable JSON: %w", err)
	}
	if !out.Success {
		if out.Error == "" {
			out.Error = "request was not successful"
		}
		return "", fmt.Errorf("firecrawl: %s", out.Error)
	}
	text := strings.TrimSpace(out.Data.Markdown)
	if len(text) > maxTextChars {
		text = text[:maxTextChars] + "\n[truncated]"
	}
	return text, nil
}
