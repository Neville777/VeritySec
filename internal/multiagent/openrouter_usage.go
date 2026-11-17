package multiagent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// OpenRouter reports the real billed cost of a completion in usage.cost when the request carries
// usage: {"include": true}. This file adds that field to chat completion requests for openrouter.ai
// channels and hands the reported cost to the current run. Request and response bodies are never logged.

type runCostCtxKey struct{}

// runCostSlot collects provider-reported costs for the calls of one run until the usage accumulator
// takes them with the next recorded usage.
type runCostSlot struct {
	mu  sync.Mutex
	sum float64
	has bool
}

func withRunCostSlot(ctx context.Context) (context.Context, *runCostSlot) {
	if s := runCostSlotFrom(ctx); s != nil {
		return ctx, s
	}
	s := &runCostSlot{}
	return context.WithValue(ctx, runCostCtxKey{}, s), s
}

func runCostSlotFrom(ctx context.Context) *runCostSlot {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(runCostCtxKey{}).(*runCostSlot)
	return s
}

func (s *runCostSlot) add(cost float64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.sum += cost
	s.has = true
	s.mu.Unlock()
}

// take returns the cost collected since the last take, or nil when the provider reported none.
func (s *runCostSlot) take() *float64 {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.has {
		return nil
	}
	v := s.sum
	s.sum, s.has = 0, false
	return &v
}

// IsOpenRouterBaseURL reports whether the base URL host is openrouter.ai.
func IsOpenRouterBaseURL(baseURL string) bool {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Host == "" {
		u, err = url.Parse("https://" + strings.TrimSpace(baseURL))
		if err != nil {
			return false
		}
	}
	return strings.EqualFold(u.Hostname(), "openrouter.ai")
}

// wrapOpenRouterUsage returns a client whose transport requests and extracts OpenRouter usage cost.
// Clients for other hosts are returned unchanged.
func wrapOpenRouterUsage(client *http.Client, baseURL string) *http.Client {
	if client == nil || !IsOpenRouterBaseURL(baseURL) {
		return client
	}
	cloned := *client
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	cloned.Transport = &openRouterUsageRoundTripper{base: base}
	return &cloned
}

type openRouterUsageRoundTripper struct{ base http.RoundTripper }

func (rt *openRouterUsageRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || !strings.EqualFold(req.URL.Hostname(), "openrouter.ai") ||
		!strings.HasSuffix(strings.TrimSuffix(req.URL.Path, "/"), "/chat/completions") {
		return rt.base.RoundTrip(req)
	}
	out := req
	if req.Body != nil {
		raw, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		patched := raw
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) == nil && fields != nil {
			fields["usage"] = json.RawMessage(`{"include":true}`)
			if b, err := json.Marshal(fields); err == nil {
				patched = b
			}
		}
		out = req.Clone(req.Context())
		out.Body = io.NopCloser(bytes.NewReader(patched))
		out.ContentLength = int64(len(patched))
		out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(patched)), nil }
		out.Header.Del("Content-Length")
	}
	resp, err := rt.base.RoundTrip(out)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	slot := runCostSlotFrom(req.Context())
	if slot == nil || resp.StatusCode < 200 || resp.StatusCode > 299 || resp.Header.Get("Content-Encoding") != "" {
		return resp, nil
	}
	resp.Body = &openRouterCostBody{
		upstream: resp.Body,
		slot:     slot,
		sse:      strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream"),
	}
	return resp, nil
}

const openRouterCostMaxBuffer = 8 << 20

// openRouterCostBody passes the body through unchanged while looking for usage.cost.
type openRouterCostBody struct {
	upstream io.ReadCloser
	slot     *runCostSlot
	sse      bool
	line     []byte // partial SSE line
	buf      []byte // whole JSON body (non-streaming), capped
	over     bool
	cost     *float64
	done     bool
}

func (b *openRouterCostBody) Read(p []byte) (int, error) {
	n, err := b.upstream.Read(p)
	if n > 0 {
		b.feed(p[:n])
	}
	if err != nil {
		b.finish()
	}
	return n, err
}

func (b *openRouterCostBody) Close() error {
	b.finish()
	return b.upstream.Close()
}

func (b *openRouterCostBody) feed(chunk []byte) {
	if !b.sse {
		if b.over {
			return
		}
		if len(b.buf)+len(chunk) > openRouterCostMaxBuffer {
			b.over, b.buf = true, nil
			return
		}
		b.buf = append(b.buf, chunk...)
		return
	}
	for len(chunk) > 0 {
		i := bytes.IndexByte(chunk, '\n')
		if i < 0 {
			if len(b.line)+len(chunk) <= openRouterCostMaxBuffer {
				b.line = append(b.line, chunk...)
			}
			return
		}
		if len(b.line)+i <= openRouterCostMaxBuffer {
			b.line = append(b.line, chunk[:i]...)
			b.scanLine(b.line)
		}
		b.line = b.line[:0]
		chunk = chunk[i+1:]
	}
}

func (b *openRouterCostBody) scanLine(line []byte) {
	line = bytes.TrimSpace(line)
	if !bytes.HasPrefix(line, []byte("data:")) {
		return
	}
	payload := bytes.TrimSpace(line[5:])
	if len(payload) == 0 || payload[0] != '{' || !bytes.Contains(payload, []byte(`"cost"`)) {
		return
	}
	if c := parseOpenRouterCost(payload); c != nil {
		b.cost = c
	}
}

func parseOpenRouterCost(payload []byte) *float64 {
	var v struct {
		Usage *struct {
			Cost *float64 `json:"cost"`
		} `json:"usage"`
	}
	if json.Unmarshal(payload, &v) != nil || v.Usage == nil {
		return nil
	}
	return v.Usage.Cost
}

func (b *openRouterCostBody) finish() {
	if b.done {
		return
	}
	b.done = true
	if b.sse {
		if len(b.line) > 0 {
			b.scanLine(b.line)
		}
	} else if !b.over && len(b.buf) > 0 {
		b.cost = parseOpenRouterCost(b.buf)
	}
	b.line, b.buf = nil, nil
	if b.cost != nil {
		b.slot.add(*b.cost)
	}
}
