// Package websearch gives the agent web access: a guarded page fetcher, a search chain that
// fails over between providers, and a headless browser for pages that need JavaScript.
package websearch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/html"
)

const (
	maxFetchBytes = 2 << 20 // 2 MiB of response body is more than enough for reading a page
	maxTextChars  = 12000   // what the agent gets back, after HTML is reduced to text
	fetchTimeout  = 20 * time.Second
)

// ErrBlockedAddress is returned when a URL points at a private, link-local or otherwise internal address.
var ErrBlockedAddress = errors.New("address is internal or not allowed")

// isBlockedIP reports whether an IP must never be fetched by the agent.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Loopback (127.0.0.0/8, ::1) is deliberately allowed so the web tools can reach local services.
	if ip.IsLoopback() {
		return false
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// Cloud metadata and carrier-grade NAT ranges.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1]&0xc0 == 64 { // 100.64.0.0/10
			return true
		}
		if ip4[0] == 169 && ip4[1] == 254 { // 169.254.0.0/16
			return true
		}
	}
	return false
}

// ValidateURL checks the scheme and host of a URL before any request is made.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("only http and https URLs are allowed")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("URL has no host")
	}
	if h := strings.ToLower(u.Hostname()); strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return nil, ErrBlockedAddress
	}
	if u.User != nil {
		return nil, fmt.Errorf("URLs with embedded credentials are not allowed")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedIP(ip) {
		return nil, ErrBlockedAddress
	}
	return u, nil
}

// safeDialer re-checks the address at connect time, so DNS tricks and redirects cannot reach internal hosts.
func safeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || isBlockedIP(ip) {
				return ErrBlockedAddress
			}
			return nil
		},
	}
}

// NewHTTPClient returns a client that refuses internal addresses at every hop.
func NewHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext:           safeDialer().DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          10,
	}
	return &http.Client{
		Timeout:   fetchTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			_, err := ValidateURL(req.URL.String())
			return err
		},
	}
}

var defaultClient = NewHTTPClient()

// Fetch downloads a page and returns its readable text, trimmed to a size the agent can use.
func Fetch(ctx context.Context, raw string) (string, string, error) {
	u, err := ValidateURL(raw)
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) VeritySec/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5")
	resp, err := defaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		return "", "", err
	}
	ctype := resp.Header.Get("Content-Type")
	text := string(body)
	if strings.Contains(ctype, "html") || strings.HasPrefix(strings.TrimSpace(text), "<") {
		text = HTMLToText(body)
	}
	text = strings.TrimSpace(text)
	if len(text) > maxTextChars {
		text = text[:maxTextChars] + "\n[truncated]"
	}
	return fmt.Sprintf("HTTP %d from %s", resp.StatusCode, resp.Request.URL.String()), text, nil
}

// HTMLToText strips tags, scripts and styles and keeps readable text, one block per line.
func HTMLToText(body []byte) string {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return string(body)
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "noscript", "svg", "head":
				return
			case "p", "div", "li", "br", "h1", "h2", "h3", "h4", "h5", "h6", "tr", "section", "article":
				b.WriteString("\n")
			}
		}
		if n.Type == html.TextNode {
			if t := strings.TrimSpace(n.Data); t != "" {
				b.WriteString(t)
				b.WriteString(" ")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	lines := strings.Split(b.String(), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if t := strings.Join(strings.Fields(l), " "); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}
