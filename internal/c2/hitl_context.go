package c2

import "context"

type hitlRunCtxKey struct{}

// WithHITLRunContext attaches runCtx (typically the entire Agent / SSE request lifecycle) to the given ctx.
// The ctx received by MCP tool handlers may be a child context with a per-tool timeout that is cancelled on tool return;
// dangerous-task HITL should use HITLUserContext to obtain runCtx for waiting on human approval.
func WithHITLRunContext(ctx, runCtx context.Context) context.Context {
	if ctx == nil || runCtx == nil {
		return ctx
	}
	return context.WithValue(ctx, hitlRunCtxKey{}, runCtx)
}

// HITLUserContext returns the context used for C2 dangerous-task HITL waiting:
// if a longer-lived runCtx was previously injected via WithHITLRunContext, it returns that; otherwise returns ctx.
func HITLUserContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	if v := ctx.Value(hitlRunCtxKey{}); v != nil {
		if run, ok := v.(context.Context); ok && run != nil {
			return run
		}
	}
	return ctx
}
