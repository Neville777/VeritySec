package multiagent

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"veritysec/internal/agent"
	"veritysec/internal/config"
	"veritysec/internal/einomcp"
	"veritysec/internal/einoobserve"
	"veritysec/internal/security"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// normalizeStreamingDelta normalizes a chunk that may be a "cumulative fragment" into a "pure increment".
// Some models/bridge layers resend already-emitted prefixes during streaming; if the frontend does buffer += chunk directly, duplicated text appears.
//
// Note: keep consistent with internal/openai.normalizeStreamingDelta.
func normalizeStreamingDelta(current, incoming string) (next, delta string) {
	if incoming == "" {
		return current, ""
	}
	if current == "" {
		return incoming, incoming
	}
	if strings.HasPrefix(incoming, current) && len(incoming) > len(current) {
		return incoming, incoming[len(current):]
	}
	if incoming == current && utf8.RuneCountInString(current) > 1 {
		return current, ""
	}
	return current + incoming, incoming
}

func isInterruptContinue(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	return errors.Is(context.Cause(ctx), ErrInterruptContinue)
}

func isEinoStreamCanceled(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, adk.ErrStreamCanceled) {
		return true
	}
	var streamCanceled *adk.StreamCanceledError
	return errors.As(err, &streamCanceled)
}

func isEinoCancelError(err error) bool {
	if err == nil {
		return false
	}
	var cancelErr *adk.CancelError
	return errors.As(err, &cancelErr)
}

// isEinoVoluntaryCancelErr reports cancel signals produced by Agent Cancel /
// TurnLoop preempt (CancelError, ErrStreamCanceled, context.Canceled).
func isEinoVoluntaryCancelErr(err error) bool {
	if err == nil {
		return false
	}
	return isEinoCancelError(err) || isEinoStreamCanceled(err) || errors.Is(err, context.Canceled)
}

// isEinoTurnLoopPreemptErr is true when a cancel/stream-cancel leaked from the
// current agent turn while the host task context is still alive. TurnLoop
// interrupt-continue does not cancel the parent context; treating that leak as
// fatal would abort the whole run instead of starting the queued next turn.
func isEinoTurnLoopPreemptErr(ctx context.Context, err error) bool {
	if err == nil || !isEinoVoluntaryCancelErr(err) {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	return true
}

func isEinoIterationLimitError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "max iteration") ||
		strings.Contains(msg, "maximum iteration") ||
		strings.Contains(msg, "maximum iterations") ||
		strings.Contains(msg, "iteration limit") ||
		strings.Contains(msg, "reached maximum iteration")
}

// einoADKRunLoopArgs extracts the Eino adk.Runner event loop from RunDeepAgent / RunEinoSingleChatModelAgent for reuse.
type einoADKRunLoopArgs struct {
	OrchMode             string
	OrchestratorName     string
	ConversationID       string
	Progress             func(eventType, message string, data interface{})
	Logger               *zap.Logger
	SnapshotMCPIDs       func() []string
	StreamsMainAssistant func(agent string) bool
	EinoRoleTag          func(agent string) string
	CheckpointDir        string
	// RunRetryMaxAttempts / RunRetryMaxBackoffSec: exponential-backoff resume on 429, 5xx, and network jitter (0 = default 4 attempts / 30s cap).
	RunRetryMaxAttempts   int
	RunRetryMaxBackoffSec int

	McpIDsMu *sync.Mutex
	McpIDs   *[]string

	// When FilesystemMonitorAgent / FilesystemMonitorRecord is non-nil, filesystem middleware tools of Eino ADK (ls/read_file/write_file/edit_file/glob/grep)
	// are written to MCP monitoring on completion; execute is still recorded by eino_execute_monitor, so it is skipped here.
	FilesystemMonitorAgent  *agent.Agent
	FilesystemMonitorRecord einomcp.ExecutionRecorder
	MCPExecutionBinder      *MCPExecutionBinder

	// ToolInvokeNotify is shared with einomcp.ToolsFromDefinitions: the run loop Sets it before each iteration, and when execute/MCP bridge Fires it, tool_result is pushed immediately (late ADK events are deduplicated via toolResultEmitter).
	ToolInvokeNotify *einomcp.ToolInvokeNotifyHolder

	DA adk.Agent

	// TokenGuard (optional) enforces agent.run_token_budget; the middleware/gen-input hooks return an error before a model call
	// once the run's cumulative provider-reported tokens exceed the budget, and this loop ends the run with status token_budget_exhausted.
	TokenGuard *runTokenGuard

	// EmptyResponseMessage is the placeholder used when no assistant body was captured (multi-agent and single-agent wording differ).
	EmptyResponseMessage string

	// ModelFacingTrace (optional): a snapshot of the "about to be sent to the model" messages, written by middleware at the end of each ChatModelAgent Handlers chain;
	// when non-empty, it is preferred for serializing LastAgentTraceInput, so that resume matches the context after summarization/reduction.
	ModelFacingTrace *modelFacingTraceHolder

	// EinoCallbacks (optional): injects eino [callbacks] full-chain observability into the ADK Runner (see internal/einoobserve).
	EinoCallbacks *config.MultiAgentEinoCallbacksConfig

	// MaxTotalTokens / ToolMaxBytes / ModelName are used for aggressive-compression resume on context overflow.
	MaxTotalTokens   int
	ToolMaxBytes     int
	ModelName        string
	MiddlewareConfig *config.MultiAgentEinoMiddlewareConfig

	// TurnLoopInterruptTimeout is only for test/special runtime overrides; 0 uses the EinoTurnLoopRuntime default.
	TurnLoopInterruptTimeout time.Duration
}

func runEinoADKAgentLoop(ctx context.Context, args *einoADKRunLoopArgs, baseMsgs []adk.Message) (*RunResult, error) {
	if args == nil || args.DA == nil {
		return nil, fmt.Errorf("eino run loop: args or Agent is empty")
	}
	if args.McpIDs == nil {
		s := []string{}
		args.McpIDs = &s
	}
	if args.McpIDsMu == nil {
		args.McpIDsMu = &sync.Mutex{}
	}

	orchMode := args.OrchMode
	orchestratorName := args.OrchestratorName
	conversationID := args.ConversationID
	progress := args.Progress
	logger := args.Logger
	runID := newEinoRunID()
	progress = withEinoRunIDProgress(runID, progress)
	args.Progress = progress
	if logger != nil {
		logger.Info("eino run session started",
			zap.String("runId", runID),
			zap.String("conversationId", conversationID),
			zap.String("orchestration", orchMode),
			zap.String("orchestratorName", orchestratorName),
		)
	}
	snapshotMCPIDs := args.SnapshotMCPIDs
	if snapshotMCPIDs == nil {
		snapshotMCPIDs = func() []string { return nil }
	}
	streamsMainAssistant := args.StreamsMainAssistant
	if streamsMainAssistant == nil {
		streamsMainAssistant = func(agent string) bool {
			return agent == "" || agent == orchestratorName
		}
	}
	einoRoleTag := args.EinoRoleTag
	if einoRoleTag == nil {
		einoRoleTag = func(agent string) string {
			if streamsMainAssistant(agent) {
				return "orchestrator"
			}
			return "sub"
		}
	}
	// Panic recovery: prevents a panic inside the Eino framework from crashing the whole goroutine and leaving the connection unable to close normally.
	defer func() {
		if r := recover(); r != nil {
			if logger != nil {
				logger.Error("eino runner panic recovered", zap.Any("recover", r), zap.Stack("stack"))
			}
			if progress != nil {
				progress("error", fmt.Sprintf("Internal error: %v", r), map[string]interface{}{
					"conversationId": conversationID,
					"source":         "eino",
				})
			}
		}
	}()

	msgs := append([]adk.Message(nil), baseMsgs...)

	emptyHint := strings.TrimSpace(args.EmptyResponseMessage)
	if emptyHint == "" {
		emptyHint = "(Eino session completed but no assistant text was captured. Check process details or logs.) " +
			"(Eino session completed, but no assistant text output was captured. Check process details or logs.)"
	}

	ctx, _ = withRunCostSlot(ctx)
	if args.EinoCallbacks != nil {
		ctx = einoobserve.AttachAgentRunCallbacks(ctx, args.EinoCallbacks, einoobserve.Params{
			Logger:           logger,
			Progress:         progress,
			ConversationID:   conversationID,
			OrchMode:         orchMode,
			OrchestratorName: orchestratorName,
			RunID:            runID,
		})
	}

	drain := newEinoRunEventDrain(einoRunEventDrainConfig{
		Context:                 ctx,
		ConversationID:          conversationID,
		OrchMode:                orchMode,
		OrchestratorName:        orchestratorName,
		Progress:                progress,
		Logger:                  logger,
		BaseMessages:            msgs,
		SnapshotMCPIDs:          snapshotMCPIDs,
		StreamsMainAssistant:    streamsMainAssistant,
		EinoRoleTag:             einoRoleTag,
		MiddlewareConfig:        args.MiddlewareConfig,
		FilesystemMonitorAgent:  args.FilesystemMonitorAgent,
		FilesystemMonitorRecord: args.FilesystemMonitorRecord,
		MCPExecutionBinder:      args.MCPExecutionBinder,
	})
	session := newEinoRunRuntimeSession(einoRunRuntimeSessionConfig{
		Context:        ctx,
		Args:           args,
		Drain:          drain,
		BaseMessages:   msgs,
		EmptyHint:      emptyHint,
		SnapshotMCPIDs: snapshotMCPIDs,
		EinoRoleTag:    einoRoleTag,
	})
	defer session.Close()

	args.TokenGuard.Bind(drain.Usage())

	// Reset only when data/a step is actually received after a backoff retry, to avoid the first error-free ADK event after restart wrongly resetting the counter to 0.
	drain.BindHandlers(session.ConfirmRecovery)

	for {
		// iter.Next may block for a long time (tool execution, model inference); it must be linked with ctx, otherwise cancel/timeout cannot flush pending in time.
		ev, ok, iterCtxErr := nextAgentEventWithContext(ctx, session.Iterator())
		if iterCtxErr != nil {
			return session.HandleIteratorContextError(iterCtxErr)
		}
		if !ok {
			// iter ending does not always mean "normal completion":
			// if cancel/timeout occurs while iter.Next() is blocked, it may directly return !ok.
			// In that case the checkpoint must be preserved, to avoid a later resume being misjudged as "no breakpoint" and rerunning everything.
			completed, result, err := session.HandleIteratorEnd()
			if result != nil || err != nil {
				return result, err
			}
			if completed {
				break
			}
			continue
		}
		if ev == nil {
			continue
		}
		if ev.Err != nil {
			if used, budget, tripped := args.TokenGuard.Tripped(); tripped {
				return session.FinishTokenBudgetExhausted(used, budget), nil
			}
			handled := session.HandleRunError(ev.Err)
			if handled.Result != nil || handled.Err != nil {
				return handled.Result, handled.Err
			}
			if handled.Restarted {
				continue
			}
		}
		drain.ObserveAgent(ev.AgentName)
		if ev.Output == nil || ev.Output.MessageOutput == nil {
			continue
		}
		mv := ev.Output.MessageOutput

		if drain.HandleToolResultStreaming(mv, ev.AgentName) {
			continue
		}

		if handledStream, streamRecvErr := drain.HandleAssistantStream(mv, ev.AgentName); handledStream {
			if streamRecvErr != nil {
				if used, budget, tripped := args.TokenGuard.Tripped(); tripped {
					return session.FinishTokenBudgetExhausted(used, budget), nil
				}
				handled := session.HandleStreamError(streamRecvErr, ev.AgentName)
				if handled.Result != nil || handled.Err != nil {
					return handled.Result, handled.Err
				}
				if handled.Restarted {
					continue
				}
			} else {
				session.ConfirmRecovery()
			}
			continue
		}

		msg, gerr := mv.GetMessage()
		if gerr != nil || msg == nil {
			continue
		}
		drain.HandleMaterialized(mv, msg, ev.AgentName)
		session.ConfirmRecovery()
	}

	return session.BuildFinalResult(), nil
}

// modelFacingTraceSnapshot returns only the state that actually reached the model boundary.
// Never fall back to event-stream accumulation here: it can contain pre-reduction tool output
// that the model never received (for example when summarization failed before the first call).
func modelFacingTraceSnapshot(args *einoADKRunLoopArgs) []adk.Message {
	if args != nil && args.ModelFacingTrace != nil {
		if snap := args.ModelFacingTrace.Snapshot(); len(snap) > 0 {
			return snap
		}
	}
	return nil
}

// friendlyEinoExecuteInvokeTail turns Eino execute timeouts/interruptions/stream errors into short hints.
// A non-zero command exit (ExecuteExitError) already has exec-aligned body text, so "Execution did not finish normally" is no longer appended.
func friendlyEinoExecuteInvokeTail(invokeErr error) string {
	if invokeErr == nil {
		return ""
	}
	var exitErr *ExecuteExitError
	if errors.As(invokeErr, &exitErr) {
		return ""
	}
	if errors.Is(invokeErr, context.DeadlineExceeded) {
		return einoExecuteTimeoutUserHint()
	}
	if errors.Is(invokeErr, context.Canceled) {
		return ""
	}
	if strings.Contains(invokeErr.Error(), "shell inactivity timeout") {
		return ""
	}
	return "[Execution did not finish normally] " + invokeErr.Error()
}

// einoToolResultIsError uniformly determines whether an Eino tool result should be marked as an error (aligned with the MCP exec IsError).
func einoToolResultIsError(toolName, content string) bool {
	if strings.HasPrefix(content, einomcp.ToolErrorPrefix) {
		return true
	}
	if strings.TrimSpace(toolName) == "execute" && security.IsCommandFailureResult(content) {
		return true
	}
	return false
}

func isMCPBackgroundWaitResult(content string) bool {
	text := strings.ToLower(strings.TrimSpace(content))
	if text == "" {
		return false
	}
	hasExecutionID := strings.Contains(text, "execution_id:") || strings.Contains(text, `"execution_id"`)
	hasRunningStatus := strings.Contains(text, "status: running") || strings.Contains(text, "status: queued") ||
		strings.Contains(text, `"status": "running"`) || strings.Contains(text, `"status":"running"`) ||
		strings.Contains(text, `"status": "queued"`) || strings.Contains(text, `"status":"queued"`)
	hasSoftWaitSignal := strings.Contains(text, "tool has been submitted for background execution") ||
		strings.Contains(text, "this wait has reached") ||
		strings.Contains(text, "wait_timeout:") ||
		strings.Contains(text, "background execution") ||
		strings.Contains(text, "still running") ||
		strings.Contains(text, "still not completed")
	return hasExecutionID && hasRunningStatus && hasSoftWaitSignal
}

func mcpExecutionIDFromWaitResult(content string) string {
	re := regexp.MustCompile(`(?i)"?execution_id"?\s*[:=]\s*"?([0-9a-f]{8}-[0-9a-f-]{12,})"?`)
	if m := re.FindStringSubmatch(content); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "execution_id:") {
			continue
		}
		return strings.Trim(strings.TrimSpace(line[len("execution_id:"):]), `"'`)
	}
	return ""
}

// einoToolResultBody strips the tool error prefix and returns the body for display/persistence.
func einoToolResultBody(content string) string {
	if strings.HasPrefix(content, einomcp.ToolErrorPrefix) {
		return strings.TrimPrefix(content, einomcp.ToolErrorPrefix)
	}
	return content
}

// nextAgentEventWithContext no longer blocks indefinitely on iter.Next() when ctx is cancelled (common during tool execution/model inference).
func nextAgentEventWithContext(ctx context.Context, iter *adk.AsyncIterator[*adk.AgentEvent]) (ev *adk.AgentEvent, ok bool, ctxErr error) {
	if iter == nil {
		return nil, false, nil
	}
	type nextRes struct {
		ev *adk.AgentEvent
		ok bool
	}
	ch := make(chan nextRes, 1)
	go func() {
		e, o := iter.Next()
		ch <- nextRes{e, o}
	}()
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case res := <-ch:
		return res.ev, res.ok, nil
	}
}

// recvSchemaMessageStream consumes the ADK Tool streaming result; it returns immediately on ctx cancel, to avoid permanent blocking when e.g. amass produces no output.
func recvSchemaMessageStream(ctx context.Context, stream *schema.StreamReader[*schema.Message]) (content, toolCallID, toolName string, recvErr error) {
	msgs, recvErr := recvSchemaToolResultMessages(ctx, stream)
	if len(msgs) == 0 {
		return "", "", "", recvErr
	}
	parts := make([]string, 0, len(msgs))
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		parts = append(parts, msg.Content)
		if id := strings.TrimSpace(msg.ToolCallID); id != "" {
			toolCallID = id
		}
		if name := strings.TrimSpace(msg.ToolName); name != "" {
			toolName = name
		}
	}
	return strings.Join(parts, ""), toolCallID, toolName, recvErr
}

// recvSchemaToolResultMessages first collects the whole Tool stream, then merges with Eino ConcatMessages.
// EventSender uses ConcatMessages when there is one stream per call; when parallel results are flattened into the same stream, they are split by CallID and then merged.
func recvSchemaToolResultMessages(ctx context.Context, stream *schema.StreamReader[*schema.Message]) (msgs []*schema.Message, recvErr error) {
	if stream == nil {
		return nil, nil
	}
	var chunks []*schema.Message
	recvErr = recvEinoSchemaMessageStreamWithContext(ctx, stream, 8, func(chunk *schema.Message) {
		chunks = append(chunks, chunk)
	})
	msgs, concatErr := concatToolResultChunks(chunks)
	if concatErr != nil && recvErr == nil {
		return nil, concatErr
	}
	return msgs, recvErr
}

func buildEinoCheckpointID(orchMode string) string {
	mode := sanitizeEinoPathSegment(strings.TrimSpace(orchMode))
	if mode == "" {
		mode = "default"
	}
	return "runner-" + mode
}

func buildEinoTurnLoopCheckpointID(orchMode string) string {
	mode := sanitizeEinoPathSegment(strings.TrimSpace(orchMode))
	if mode == "" {
		mode = "default"
	}
	return "turn-loop-" + mode
}
