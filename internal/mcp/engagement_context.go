package mcp

import (
	"context"
	"strings"
)

type engagementIDKey struct{}

// WithEngagementID attaches the engagement a direct MCP call acts for. The HTTP handler sets it
// from the X-Engagement-ID request header; it is used by the scope authorizer.
func WithEngagementID(ctx context.Context, engagementID string) context.Context {
	return context.WithValue(ctx, engagementIDKey{}, strings.TrimSpace(engagementID))
}

// EngagementIDFromContext returns the engagement attached by WithEngagementID, or "".
func EngagementIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(engagementIDKey{}).(string); ok {
		return v
	}
	return ""
}

type directHTTPKey struct{}

// WithDirectHTTP marks a call that arrived over the direct /api/mcp HTTP route.
func WithDirectHTTP(ctx context.Context) context.Context {
	return context.WithValue(ctx, directHTTPKey{}, true)
}

// WithAgentExecution marks a call as originating from an agent execution.
// This clears the directHTTP flag so agent tool invocations are not confused with direct MCP HTTP calls.
func WithAgentExecution(ctx context.Context) context.Context {
	return context.WithValue(ctx, directHTTPKey{}, false)
}

// IsDirectHTTP reports whether the call arrived over the direct /api/mcp HTTP route.
func IsDirectHTTP(ctx context.Context) bool {
	v, _ := ctx.Value(directHTTPKey{}).(bool)
	return v
}
