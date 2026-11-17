package handler

import (
	"context"
	"fmt"
	"time"

	"veritysec/internal/agent"
	"veritysec/internal/config"
	"veritysec/internal/multiagent"

	"go.uber.org/zap"
)

// rebindEinoRunningTask handles interrupt-and-continue and empty-body continuation: rebuilds the cancel chain and timeout ctx, keeping the task running.
func (h *AgentHandler) rebindEinoRunningTask(parent context.Context, conversationID string, timeoutCancel context.CancelFunc) (context.Context, context.CancelCauseFunc, context.Context, context.CancelFunc) {
	if timeoutCancel != nil {
		timeoutCancel()
	}
	baseCtx, cancelWithCause := context.WithCancelCause(detachedAgentContext(parent))
	h.tasks.BindTaskCancel(conversationID, cancelWithCause)
	taskCtx, newTimeoutCancel := h.newTaskContext(baseCtx)
	h.tasks.UpdateTaskStatus(conversationID, "running")
	return baseCtx, cancelWithCause, taskCtx, newTimeoutCancel
}

// tryContinueOnEinoEmptyResponse backs off and continues when Run succeeds but Response is emptyHint; true means the next Run segment has been prepared.
func (h *AgentHandler) tryContinueOnEinoEmptyResponse(
	taskCtx context.Context,
	mw *config.MultiAgentEinoMiddlewareConfig,
	conversationID string,
	result *multiagent.RunResult,
	attempt *int,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	if result == nil || !multiagent.IsEinoEmptyResponseResult(result) || !multiagent.HasEinoResumeTrace(result) {
		return false
	}
	maxAttempts := multiagent.EmptyResponseContinueMaxAttemptsFromConfig(mw)
	if *attempt >= maxAttempts {
		if h.logger != nil {
			h.logger.Warn("eino empty response continue exhausted",
				zap.String("conversationId", conversationID),
				zap.Int("maxAttempts", maxAttempts))
		}
		return false
	}
	*attempt++
	h.persistEinoAgentTraceForResume(conversationID, result)

	backoff := multiagent.EmptyResponseContinueBackoff(*attempt-1, mw)
	waitMsg := fmt.Sprintf("session ended but no assistant text was captured; auto-continuing in %d seconds (attempt %d/%d)…",
		int(backoff.Seconds()), *attempt, maxAttempts)
	if progressCallback != nil {
		progressCallback("eino_empty_response_continue", waitMsg, map[string]interface{}{
			"conversationId": conversationID,
			"source":         "eino",
			"attempt":        *attempt,
			"maxAttempts":    maxAttempts,
			"backoffSec":     int(backoff.Seconds()),
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(backoff):
	}

	h.applyEinoTraceResumeSegment(conversationID, result, curHistory, curFinalMessage, "")
	if progressCallback != nil {
		progressCallback("eino_empty_response_continue", "context restored; continuing…", map[string]interface{}{
			"conversationId":   conversationID,
			"source":           "eino",
			"attempt":          *attempt,
			"maxAttempts":      maxAttempts,
			"contextSource":    "empty_response_continue",
			"contextInjection": false,
		})
	}
	return true
}
