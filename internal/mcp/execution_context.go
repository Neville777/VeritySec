// Package mcp provides execution context types and helpers for MCP tool invocations.
package mcp

import (
	"context"
	"fmt"
	"strings"
)

// ExecutionOrigin describes how a tool invocation is initiated.
type ExecutionOrigin string

const (
	OriginDirectMCPHTTP ExecutionOrigin = "direct_mcp_http"
	OriginAgent         ExecutionOrigin = "agent"
	OriginBackground    ExecutionOrigin = "background"
	OriginExternalMCP   ExecutionOrigin = "external_mcp"
)

// ExecutionContext carries trusted execution metadata for tool invocations.
// All fields must be populated from trusted application state, not tool arguments.
type ExecutionContext struct {
	Origin         ExecutionOrigin
	UserID         string
	EngagementID   string
	RunID          string
	ConversationID string
}

// executionContextKey is the context key for ExecutionContext.
type executionContextKey struct{}

// WithExecutionContext attaches a trusted execution context to ctx.
// Use the dedicated constructors (NewDirectMCPExecution, NewAgentExecution, etc.)
// to create ExecutionContext values.
func WithExecutionContext(ctx context.Context, exec ExecutionContext) context.Context {
	return context.WithValue(ctx, executionContextKey{}, exec)
}

// ExecutionContextFromContext returns the execution context attached to ctx.
// Returns ok=false if no context is attached.
func ExecutionContextFromContext(ctx context.Context) (ExecutionContext, bool) {
	v, ok := ctx.Value(executionContextKey{}).(ExecutionContext)
	return v, ok
}

// MustExecutionContextFromContext returns the execution context or panics if not present.
// Use when the execution context is guaranteed to be set.
func MustExecutionContextFromContext(ctx context.Context) ExecutionContext {
	exec, ok := ExecutionContextFromContext(ctx)
	if !ok {
		panic("mcp: execution context not set")
	}
	return exec
}

// NewDirectMCPExecution creates an execution context for direct MCP HTTP calls.
// userID and engagementID must come from the authenticated HTTP request.
func NewDirectMCPExecution(userID, engagementID string) ExecutionContext {
	return ExecutionContext{
		Origin:       OriginDirectMCPHTTP,
		UserID:       strings.TrimSpace(userID),
		EngagementID: strings.TrimSpace(engagementID),
	}
}

// NewAgentExecution creates an execution context for agent-initiated tool calls.
// All fields must come from the agent's trusted run state.
func NewAgentExecution(userID, engagementID, runID, conversationID string) ExecutionContext {
	return ExecutionContext{
		Origin:         OriginAgent,
		UserID:         strings.TrimSpace(userID),
		EngagementID:   strings.TrimSpace(engagementID),
		RunID:          strings.TrimSpace(runID),
		ConversationID: strings.TrimSpace(conversationID),
	}
}

// NewBackgroundExecution creates an execution context for background job tool calls.
// All fields must come from the persisted job record.
func NewBackgroundExecution(userID, engagementID, runID string) ExecutionContext {
	return ExecutionContext{
		Origin:       OriginBackground,
		UserID:       strings.TrimSpace(userID),
		EngagementID: strings.TrimSpace(engagementID),
		RunID:        strings.TrimSpace(runID),
	}
}

// NewExternalMCPExecution creates an execution context for external MCP tool calls.
// userID and engagementID must come from the authenticated MCP session.
func NewExternalMCPExecution(userID, engagementID string) ExecutionContext {
	return ExecutionContext{
		Origin:       OriginExternalMCP,
		UserID:       strings.TrimSpace(userID),
		EngagementID: strings.TrimSpace(engagementID),
	}
}

// IsDirectMCPHTTP returns true if the execution origin is direct MCP HTTP.
// This is the typed equivalent of IsDirectHTTP.
func IsDirectMCPHTTP(ctx context.Context) bool {
	exec, ok := ExecutionContextFromContext(ctx)
	if !ok {
		// Fall back to legacy boolean for backward compatibility
		return IsDirectHTTP(ctx)
	}
	return exec.Origin == OriginDirectMCPHTTP
}

// IsAgentExecution returns true if the execution origin is an agent.
func IsAgentExecution(ctx context.Context) bool {
	exec, ok := ExecutionContextFromContext(ctx)
	if !ok {
		return false
	}
	return exec.Origin == OriginAgent
}

// Validate returns an error if the execution context is invalid for the given origin.
func (e ExecutionContext) Validate() error {
	if e.Origin == "" {
		return fmt.Errorf("execution origin is empty")
	}
	switch e.Origin {
	case OriginDirectMCPHTTP:
		// Direct MCP HTTP requires user ID
		if e.UserID == "" {
			return fmt.Errorf("direct MCP HTTP requires user ID")
		}
		// Engagement ID is optional (checked later if needed)
	case OriginAgent:
		// Agent execution requires user ID, engagement ID, and conversation ID
		if e.UserID == "" {
			return fmt.Errorf("agent execution requires user ID")
		}
		if e.ConversationID == "" {
			return fmt.Errorf("agent execution requires conversation ID")
		}
		// Engagement ID is optional (may be unbound conversation)
	case OriginBackground:
		// Background execution requires user ID and run ID
		if e.UserID == "" {
			return fmt.Errorf("background execution requires user ID")
		}
		if e.RunID == "" {
			return fmt.Errorf("background execution requires run ID")
		}
	case OriginExternalMCP:
		// External MCP requires user ID
		if e.UserID == "" {
			return fmt.Errorf("external MCP requires user ID")
		}
	default:
		return fmt.Errorf("unknown execution origin: %s", e.Origin)
	}
	return nil
}
