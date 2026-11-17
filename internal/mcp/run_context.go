package mcp

import (
	"context"
	"strings"
)

// ToolRunRegistry registers the current executionId when a tool starts/ends, so the conversation page's "terminate only the current tool" and the monitor page share the cancel logic.
type ToolRunRegistry interface {
	RegisterRunningTool(conversationID, executionID string)
	UnregisterRunningTool(conversationID, executionID string)
}

// EinoExecuteRunRegistry registers in-flight Eino filesystem executes so "interrupt and continue" can terminate long-running commands such as amass.
type EinoExecuteRunRegistry interface {
	RegisterActiveEinoExecute(conversationID string, cancel context.CancelFunc)
	UnregisterActiveEinoExecute(conversationID string)
	AbortActiveEinoExecute(conversationID, note string) bool
	TakeEinoExecuteAbortNote(conversationID string) string
}

type toolRunRegistryCtxKey struct{}
type einoExecuteRunRegistryCtxKey struct{}
type mcpConversationIDCtxKey struct{}
type mcpExecutionIDCtxKey struct{}
type mcpProjectIDCtxKey struct{}

// WithToolRunRegistry injects the registry into ctx (Eino / native Agent task ctx).
func WithToolRunRegistry(ctx context.Context, reg ToolRunRegistry) context.Context {
	if ctx == nil || reg == nil {
		return ctx
	}
	return context.WithValue(ctx, toolRunRegistryCtxKey{}, reg)
}

// ToolRunRegistryFromContext retrieves the registry (nil if absent).
func ToolRunRegistryFromContext(ctx context.Context) ToolRunRegistry {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(toolRunRegistryCtxKey{}).(ToolRunRegistry)
	return v
}

// WithEinoExecuteRunRegistry injects the Eino execute cancel registry into ctx.
func WithEinoExecuteRunRegistry(ctx context.Context, reg EinoExecuteRunRegistry) context.Context {
	if ctx == nil || reg == nil {
		return ctx
	}
	return context.WithValue(ctx, einoExecuteRunRegistryCtxKey{}, reg)
}

// EinoExecuteRunRegistryFromContext retrieves the Eino execute registry (nil if absent).
func EinoExecuteRunRegistryFromContext(ctx context.Context) EinoExecuteRunRegistry {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(einoExecuteRunRegistryCtxKey{}).(EinoExecuteRunRegistry)
	return v
}

// WithMCPConversationID injects the conversation ID into ctx so it can be associated with executionId inside CallTool.
func WithMCPConversationID(ctx context.Context, conversationID string) context.Context {
	if ctx == nil {
		return nil
	}
	id := strings.TrimSpace(conversationID)
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, mcpConversationIDCtxKey{}, id)
}

// MCPConversationIDFromContext reads the conversation ID.
func MCPConversationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(mcpConversationIDCtxKey{}).(string)
	return v
}

// WithMCPExecutionID injects the current tool executionId into ctx, so the file name of oversized output saved to disk aligns with it.
func WithMCPExecutionID(ctx context.Context, executionID string) context.Context {
	if ctx == nil {
		return nil
	}
	id := strings.TrimSpace(executionID)
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, mcpExecutionIDCtxKey{}, id)
}

// MCPExecutionIDFromContext reads the current tool executionId.
func MCPExecutionIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(mcpExecutionIDCtxKey{}).(string)
	return v
}

// WithMCPProjectID injects the project ID into ctx, so the reduction/trunc disk paths align with project isolation.
func WithMCPProjectID(ctx context.Context, projectID string) context.Context {
	if ctx == nil {
		return nil
	}
	id := strings.TrimSpace(projectID)
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, mcpProjectIDCtxKey{}, id)
}

// MCPProjectIDFromContext reads the project ID.
func MCPProjectIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(mcpProjectIDCtxKey{}).(string)
	return v
}

func notifyToolRunBegin(ctx context.Context, executionID string) {
	reg := ToolRunRegistryFromContext(ctx)
	if reg == nil {
		return
	}
	conv := MCPConversationIDFromContext(ctx)
	if conv == "" || strings.TrimSpace(executionID) == "" {
		return
	}
	reg.RegisterRunningTool(conv, executionID)
}

func notifyToolRunEnd(ctx context.Context, executionID string) {
	reg := ToolRunRegistryFromContext(ctx)
	if reg == nil {
		return
	}
	conv := MCPConversationIDFromContext(ctx)
	if conv == "" || strings.TrimSpace(executionID) == "" {
		return
	}
	reg.UnregisterRunningTool(conv, executionID)
}
