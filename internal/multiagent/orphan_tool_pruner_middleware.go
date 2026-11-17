package multiagent

import (
	"context"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// orphanToolPrunerMiddleware removes orphan tool messages that have no corresponding assistant(tool_calls) before each ChatModel call.
//
// Background:
//   - After triggering a summary, Eino's summarization middleware by default replaces all non-system messages with 1 summary message;
//     this project uses a custom Finalize (summarizeFinalizeWithRecentAssistantToolTrail) to backfill the
//     most recent assistant/tool trail after the summary. If Finalize's retention policy truncates by "count" rather than aligning by round, it may keep
//     tool results while the corresponding assistant(tool_calls) falls before the summary, forming orphan tool messages.
//   - Likewise, any logic that rewrites history, such as reduction / tool_search / custom breakpoint recovery, can break
//     the tool_call ↔ tool_result pairing.
//
// Once an orphan tool message enters the ChatModel, OpenAI-compatible APIs (including DashScope and various relays) return
// 400 "No tool call found for function call output with call_id ..." which Eino wraps as
// [NodeRunError] and throws, aborting the whole orchestration round.
//
// Design trade-offs:
//   - The official patchtoolcalls middleware only backfills the reverse case (assistant(tc) missing tool_result) and does not handle orphan tools.
//     This middleware complements it, specializing in the forward-orphan safety net.
//   - It only removes messages and does not inject fabricated assistant(tc) into history: fabricated tool_calls would mislead the model's later reasoning.
//     The summary already covers the semantics of the trimmed segment, so dropping one raw tool result has minimal impact on conversational coherence.
//   - Placement suggestion: after summarization / reduction / skill / plantask / system merge / continuation dedup,
//     tool_search), at the end closest to the ChatModel call.
type orphanToolPrunerMiddleware struct {
	adk.BaseChatModelAgentMiddleware
	logger *zap.Logger
	phase  string
}

// newOrphanToolPrunerMiddleware constructs the middleware. phase is used only for log differentiation among deep / supervisor /
// plan_execute_executor / sub_agent, and does not affect runtime behavior.
func newOrphanToolPrunerMiddleware(logger *zap.Logger, phase string) adk.ChatModelAgentMiddleware {
	return &orphanToolPrunerMiddleware{
		logger: logger,
		phase:  phase,
	}
}

// BeforeModelRewriteState scans the message list, collects the set of call_ids provided by assistant.tool_calls,
// then removes role=tool messages whose ToolCallID is not in that set.
//
// Complexity: O(N). When no orphan is found, no allocation is made and state is returned unchanged for the upstream fast path.
func (m *orphanToolPrunerMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.ChatModelAgentState,
	mc *adk.ModelContext,
) (context.Context, *adk.ChatModelAgentState, error) {
	_ = mc
	if m == nil || state == nil || len(state.Messages) == 0 {
		return ctx, state, nil
	}

	// First pass: collect all provided tool_call_ids; also determine on the fast path whether any orphan actually exists.
	provided := make(map[string]struct{}, 8)
	for _, msg := range state.Messages {
		if msg == nil {
			continue
		}
		if msg.Role == schema.Assistant {
			for _, tc := range msg.ToolCalls {
				if tc.ID != "" {
					provided[tc.ID] = struct{}{}
				}
			}
		}
	}

	hasOrphan := false
	for _, msg := range state.Messages {
		if msg == nil {
			continue
		}
		if msg.Role == schema.Tool && msg.ToolCallID != "" {
			if _, ok := provided[msg.ToolCallID]; !ok {
				hasOrphan = true
				break
			}
		}
	}
	if !hasOrphan {
		return ctx, state, nil
	}

	// Second pass: produce the new message list with orphans removed.
	pruned := make([]adk.Message, 0, len(state.Messages))
	droppedIDs := make([]string, 0, 2)
	droppedNames := make([]string, 0, 2)
	for _, msg := range state.Messages {
		if msg == nil {
			continue
		}
		if msg.Role == schema.Tool && msg.ToolCallID != "" {
			if _, ok := provided[msg.ToolCallID]; !ok {
				droppedIDs = append(droppedIDs, msg.ToolCallID)
				droppedNames = append(droppedNames, msg.ToolName)
				continue
			}
		}
		pruned = append(pruned, msg)
	}

	if m.logger != nil {
		m.logger.Warn("eino orphan tool messages pruned before model call",
			zap.String("phase", m.phase),
			zap.Int("dropped_count", len(droppedIDs)),
			zap.Strings("dropped_tool_call_ids", droppedIDs),
			zap.Strings("dropped_tool_names", droppedNames),
			zap.Int("messages_before", len(state.Messages)),
			zap.Int("messages_after", len(pruned)),
		)
	}

	ns := *state
	ns.Messages = pruned
	return ctx, &ns, nil
}
