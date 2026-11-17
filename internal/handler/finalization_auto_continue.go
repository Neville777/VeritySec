package handler

import (
	"context"
	"strings"
	"time"

	"veritysec/internal/agent"
	"veritysec/internal/agentfinalizer"
	"veritysec/internal/mcp"
	"veritysec/internal/multiagent"

	"go.uber.org/zap"
)

const finalizationAutoContinueMaxAttempts = 2
const finalizationPendingToolCancelWait = 2 * time.Second
const finalizationPendingToolCancelPoll = 50 * time.Millisecond
const finalizationPendingToolCancelNote = "Agent iteration ended; unfinished tool executions were automatically terminated before the final reply"

func shouldAutoContinueAfterFinalization(d agentfinalizer.Decision, attempt int) bool {
	if d.Finalizable || d.Finalized {
		return false
	}
	if attempt >= finalizationAutoContinueMaxAttempts {
		return false
	}
	return d.CompletionReason == agentfinalizer.ReasonMissingEvidence
}

func (h *AgentHandler) tryAutoContinueAfterFinalization(
	taskCtx context.Context,
	conversationID string,
	result *multiagent.RunResult,
	decision agentfinalizer.Decision,
	attempt *int,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	if !shouldAutoContinueAfterFinalization(decision, *attempt) || result == nil || !multiagent.HasEinoResumeTrace(result) {
		return false
	}
	*attempt++
	h.persistEinoAgentTraceForResume(conversationID, result)
	if hist, err := h.loadHistoryFromAgentTrace(conversationID); err == nil && len(hist) > 0 {
		*curHistory = hist
	} else if h.logger != nil {
		h.logger.Warn("finalization auto-continue could not restore trace",
			zap.String("conversationId", conversationID),
			zap.Error(err))
		return false
	}
	// Agent silent continuation: does not append new user/system text; continues the Runner using only the previous model-visible trace.
	*curFinalMessage = ""
	if progressCallback != nil {
		progressCallback("finalization_auto_continue", "final reply check has not converged yet; continuing execution based on the existing trace…", map[string]interface{}{
			"conversationId":      conversationID,
			"source":              "finalizer",
			"attempt":             *attempt,
			"maxAttempts":         finalizationAutoContinueMaxAttempts,
			"status":              decision.Status,
			"completionReason":    decision.CompletionReason,
			"missingChecks":       decision.MissingChecks,
			"pendingExecutionIds": decision.PendingExecutionIDs,
			"contextInjection":    false,
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(finalizationAutoContinueBackoff(*attempt)):
		return true
	}
}

func finalizationAutoContinueBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return 500 * time.Millisecond
	}
	return time.Duration(attempt) * time.Second
}

func (h *AgentHandler) cleanupPendingToolExecutionsAfterIteration(
	taskCtx context.Context,
	conversationID string,
	decision agentfinalizer.Decision,
	progressCallback func(eventType, message string, data interface{}),
) []string {
	if h == nil || h.agent == nil || decision.CompletionReason != agentfinalizer.ReasonPendingTools {
		return nil
	}
	pending := uniqueNonEmptyStrings(decision.PendingExecutionIDs)
	if len(pending) == 0 {
		return nil
	}
	cancelled := make([]string, 0, len(pending))
	for _, executionID := range pending {
		if h.agent.CancelMCPToolExecutionWithNote(executionID, finalizationPendingToolCancelNote) {
			cancelled = append(cancelled, executionID)
		} else if h.logger != nil {
			h.logger.Warn("finalization pending tool cleanup could not cancel execution",
				zap.String("conversationId", conversationID),
				zap.String("executionId", executionID))
		}
	}
	if len(cancelled) == 0 {
		return nil
	}
	if progressCallback != nil {
		progressCallback("finalization_pending_tools_cancelled", "iteration ended; tool executions still running were automatically terminated.", map[string]interface{}{
			"conversationId":                   conversationID,
			"source":                           "finalizer",
			"autoCancelledPendingExecutionIds": cancelled,
			"pendingExecutionIds":              pending,
			"reason":                           agentfinalizer.ReasonPendingTools,
		})
	}
	h.waitForToolExecutionsToLeavePending(taskCtx, cancelled, finalizationPendingToolCancelWait)
	return cancelled
}

func (h *AgentHandler) waitForToolExecutionsToLeavePending(ctx context.Context, executionIDs []string, wait time.Duration) {
	if h == nil || h.db == nil || len(executionIDs) == 0 || wait <= 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(finalizationPendingToolCancelPoll)
	defer ticker.Stop()
	for {
		if !h.hasPendingToolExecutions(executionIDs) {
			return
		}
		select {
		case <-contextDone(ctx):
			return
		case <-timer.C:
			return
		case <-ticker.C:
		}
	}
}

func (h *AgentHandler) hasPendingToolExecutions(executionIDs []string) bool {
	if h == nil || h.db == nil {
		return false
	}
	for _, executionID := range uniqueNonEmptyStrings(executionIDs) {
		exec, err := h.db.GetToolExecution(executionID)
		if err != nil || exec == nil {
			continue
		}
		switch strings.TrimSpace(exec.Status) {
		case mcp.ToolExecutionStatusQueued, mcp.ToolExecutionStatusRunning:
			return true
		}
	}
	return false
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func contextDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

// announcedWorkNudgeMaxAttempts caps how many times one run is sent back to do work its last
// reply only announced.
const announcedWorkNudgeMaxAttempts = 6

const announcedWorkNudgeText = "Your last reply announced more work but did not do it or give a result. Do not write another status message. Either call the next tool now, or write the final answer with the results gathered so far."

// tryAutoContinueForAnnouncedWork starts one more turn in the same conversation when the decision
// was refused with ReasonAnnouncedWork. attempt is the per-run counter; at the limit it returns
// false and the caller finalizes with the existing behaviour.
func (h *AgentHandler) tryAutoContinueForAnnouncedWork(
	taskCtx context.Context,
	conversationID string,
	result *multiagent.RunResult,
	decision agentfinalizer.Decision,
	attempt *int,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	if h == nil || result == nil || decision.Finalizable || decision.CompletionReason != agentfinalizer.ReasonAnnouncedWork {
		return false
	}
	if *attempt >= announcedWorkNudgeMaxAttempts || !multiagent.HasEinoResumeTrace(result) {
		return false
	}
	*attempt++
	h.persistEinoAgentTraceForResume(conversationID, result)
	if hist, err := h.loadHistoryFromAgentTrace(conversationID); err == nil && len(hist) > 0 {
		*curHistory = hist
	} else {
		if h.logger != nil {
			h.logger.Warn("announced-work nudge could not restore trace",
				zap.String("conversationId", conversationID), zap.Error(err))
		}
		return false
	}
	*curFinalMessage = announcedWorkNudgeText
	if progressCallback != nil {
		progressCallback("announced_work_continue", "reply announced more work without doing it; continuing…", map[string]interface{}{
			"conversationId": conversationID,
			"source":         "finalizer",
			"attempt":        *attempt,
			"maxAttempts":    announcedWorkNudgeMaxAttempts,
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(time.Duration(*attempt) * 400 * time.Millisecond):
		return true
	}
}
