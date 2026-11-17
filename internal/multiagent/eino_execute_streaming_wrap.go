package multiagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"veritysec/internal/einomcp"
	"veritysec/internal/mcp"
	"veritysec/internal/security"

	"github.com/cloudwego/eino/adk/filesystem"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// prependPythonUnbufferedEnv injects PYTHONUNBUFFERED=1 for /bin/sh -c.
// eino-ext local pushes streaming stdout line by line via bufio; when python3 writes to a pipe it block-buffers by default, so print output stays in user-space buffers,
// no newlines reach the pipe, and the symptom is no output for a long time until timeout or exit. If PYTHONUNBUFFERED already appears in the command, it is not overwritten.
func prependPythonUnbufferedEnv(shellCommand string) string {
	if strings.TrimSpace(shellCommand) == "" {
		return shellCommand
	}
	if strings.Contains(strings.ToUpper(shellCommand), "PYTHONUNBUFFERED") {
		return shellCommand
	}
	return "export PYTHONUNBUFFERED=1\n" + shellCommand
}

// einoExecuteTimeoutUserHint is consistent with the ADK tool message written (visible to the model) and the SSE tool_result trailing tag.
func einoExecuteTimeoutUserHint() string {
	return "Terminated on timeout · Timed out"
}

// einoExecuteRecvErrIsToolTimeout determines whether a Recv error was triggered by agent.tool_timeout_minutes.
// After WithTimeout expires, the local side often reports canceled / exit -1, but execCtx.Err() is still DeadlineExceeded.
func einoExecuteRecvErrIsToolTimeout(rerr error, tctx context.Context) bool {
	if tctx != nil && errors.Is(tctx.Err(), context.DeadlineExceeded) {
		return true
	}
	return errors.Is(rerr, context.DeadlineExceeded)
}

// einoStreamingShellWrap wraps the StreamingShell used by Eino filesystem (cloudwego eino-ext local.Local).
// The official execute tool defaults to ExecuteStreaming without RunInBackendGround; when the command ends with &, the child process is still connected to the pipe,
// and streamStdout reading line by line can block for a long time when there is no newline output (different from the independent implementation of the MCP tool exec).
// Automatically enables RunInBackendGround for "fully background" commands, aligning with the behavior of local.runCmdInBackground.
//
// Uses a Pipe to forward the inner stream to the caller: after the inner EOF and before closing the Pipe, ToolInvokeNotify.Fire is called synchronously,
// and the run loop pushes tool_result immediately upon Fire (deduplicated by toolResultSent), so the UI does not get stuck in "running" when the ADK Tool event arrives late.
//
// If inner returns an error directly during the validation phase (no reader established), it does not enter the goroutine below, and it must still Fire;
// otherwise the pending tool_call is only force-closed after the whole run ends, out of sync with the displayed assistant/tool soft-error text.
type einoStreamingShellWrap struct {
	inner         filesystem.StreamingShell
	invokeNotify  *einomcp.ToolInvokeNotifyHolder
	einoAgentName string
	// outputChunk is optional; when non-nil, it is pushed when inner ExecuteResponse fragments are received, consistent with the MCP tool's tool_result_delta (requires a valid toolCallId).
	outputChunk func(toolName, toolCallID, chunk string)
	// toolTimeoutMinutes is aligned with agent.tool_timeout_minutes; when >0, a context timeout is applied to each execute (consistent with MCP tools via executeToolViaMCP). 0 means only the upper-layer ctx applies (e.g., the overall 10h task cap).
	toolTimeoutMinutes int
	// toolWaitTimeoutSeconds is aligned with agent.tool_wait_timeout_seconds; when >0, after this round's wait expires it returns execution_id, and the shell keeps running in the background.
	toolWaitTimeoutSeconds int
	// shellNoOutputTimeoutSec: idle seconds with no output at all; 0 = disabled.
	shellNoOutputTimeoutSec int
	// beginMonitor writes the running state when execute starts; finishMonitor updates it to completed/failed after the stream ends.
	beginMonitor            func(toolCallID, command string) string
	appendPartialMonitor    func(executionID, toolCallID, chunk string)
	registerCancelMonitor   func(executionID string, cancel context.CancelFunc)
	unregisterCancelMonitor func(executionID string)
	finishMonitor           func(executionID, toolCallID, command, stdout string, success bool, invokeErr error)
}

func (w *einoStreamingShellWrap) ExecuteStreaming(ctx context.Context, input *filesystem.ExecuteRequest) (*schema.StreamReader[*filesystem.ExecuteResponse], error) {
	if w.inner == nil {
		return nil, fmt.Errorf("einoStreamingShellWrap: inner shell is nil")
	}
	if input == nil {
		return w.inner.ExecuteStreaming(ctx, nil)
	}
	req := *input
	userCmd := strings.TrimSpace(req.Command)
	tid := strings.TrimSpace(compose.GetToolCallID(ctx))
	agentTag := strings.TrimSpace(w.einoAgentName)
	if security.IsBackgroundShellCommand(req.Command) && !req.RunInBackendGround {
		req.RunInBackendGround = true
	}
	req.Command = prependPythonUnbufferedEnv(req.Command)
	convID := mcp.MCPConversationIDFromContext(ctx)
	execReg := mcp.EinoExecuteRunRegistryFromContext(ctx)

	var monitorExecID string
	if w.beginMonitor != nil {
		monitorExecID = w.beginMonitor(tid, userCmd)
	}
	if monitorExecID != "" && convID != "" {
		if toolReg := mcp.ToolRunRegistryFromContext(ctx); toolReg != nil {
			toolReg.RegisterRunningTool(convID, monitorExecID)
		}
	}
	toolRunReg := mcp.ToolRunRegistryFromContext(ctx)

	execCtx, execCancel := context.WithCancel(ctx)
	var timeoutCancel context.CancelFunc
	if w.toolTimeoutMinutes > 0 {
		execCtx, timeoutCancel = context.WithTimeout(execCtx, time.Duration(w.toolTimeoutMinutes)*time.Minute)
	}
	if monitorExecID != "" && w.registerCancelMonitor != nil {
		w.registerCancelMonitor(monitorExecID, execCancel)
	}
	if execReg != nil && convID != "" {
		execReg.RegisterActiveEinoExecute(convID, execCancel)
	}

	sr, err := w.inner.ExecuteStreaming(execCtx, &req)
	if err != nil {
		if timeoutCancel != nil {
			timeoutCancel()
		}
		if execCancel != nil {
			execCancel()
		}
		if monitorExecID != "" && w.unregisterCancelMonitor != nil {
			w.unregisterCancelMonitor(monitorExecID)
		}
		if einoExecuteRecvErrIsToolTimeout(err, execCtx) {
			hint := "\n\n" + einoExecuteTimeoutUserHint() + "\n"
			if w.finishMonitor != nil {
				w.finishMonitor(monitorExecID, tid, userCmd, hint, false, context.DeadlineExceeded)
			}
			if w.invokeNotify != nil && tid != "" {
				w.invokeNotify.Fire(tid, "execute", agentTag, false, hint, context.DeadlineExceeded)
			}
			return schema.StreamReaderFromArray([]*filesystem.ExecuteResponse{{Output: hint}}), nil
		}
		if w.finishMonitor != nil {
			w.finishMonitor(monitorExecID, tid, userCmd, "", false, err)
		}
		if w.invokeNotify != nil && tid != "" {
			w.invokeNotify.Fire(tid, "execute", agentTag, false, "", err)
		}
		return nil, err
	}
	if sr == nil {
		if timeoutCancel != nil {
			timeoutCancel()
		}
		if execCancel != nil {
			execCancel()
		}
		return sr, nil
	}

	outR, outW := schema.Pipe[*filesystem.ExecuteResponse](32)

	go func(inner *schema.StreamReader[*filesystem.ExecuteResponse], command string, cancel context.CancelFunc, timeoutCleanup context.CancelFunc, tctx context.Context, conversationID string, reg mcp.EinoExecuteRunRegistry, toolReg mcp.ToolRunRegistry, execID string, toolCallID string, noOutputSec int, waitTimeoutSec int) {
		var innerCloseOnce sync.Once
		closeInner := func() {
			innerCloseOnce.Do(func() { inner.Close() })
		}
		defer closeInner()
		if timeoutCleanup != nil {
			defer timeoutCleanup()
		}
		if cancel != nil {
			defer cancel()
		}
		if reg != nil && conversationID != "" {
			defer reg.UnregisterActiveEinoExecute(conversationID)
		}
		if toolReg != nil && conversationID != "" && execID != "" {
			defer toolReg.UnregisterRunningTool(conversationID, execID)
		}
		if w.unregisterCancelMonitor != nil && execID != "" {
			defer w.unregisterCancelMonitor(execID)
		}

		// On ctx cancel, close the inner stream, to avoid Recv blocking forever when amass and similar tools produce no newline output for a long time.
		stopWatch := make(chan struct{})
		go func() {
			select {
			case <-tctx.Done():
				closeInner()
			case <-stopWatch:
			}
		}()
		defer close(stopWatch)

		var sb strings.Builder
		success := true
		var invokeErr error
		exitCode := 0
		hasExitCode := false
		softReturned := false
		var outCloseOnce sync.Once
		closeOut := func() {
			outCloseOnce.Do(func() { outW.Close() })
		}
		defer closeOut()
		sendOut := func(resp *filesystem.ExecuteResponse, err error) bool {
			if softReturned {
				return false
			}
			return outW.Send(resp, err)
		}

		idleWatch := security.NewShellInactivityWatch(noOutputSec)
		if idleWatch != nil {
			defer idleWatch.Stop()
		}
		var waitTimeoutCh <-chan time.Time
		var waitTimer *time.Timer
		if waitTimeoutSec > 0 {
			waitTimer = time.NewTimer(time.Duration(waitTimeoutSec) * time.Second)
			waitTimeoutCh = waitTimer.C
			defer waitTimer.Stop()
		}

		type execRecvMsg struct {
			resp *filesystem.ExecuteResponse
			err  error
		}
		recvCh := make(chan execRecvMsg, 1)
		go func() {
			for {
				resp, rerr := inner.Recv()
				recvCh <- execRecvMsg{resp: resp, err: rerr}
				if rerr != nil {
					return
				}
			}
		}()

		fireInactivityTimeout := func() {
			success = false
			invokeErr = fmt.Errorf("shell inactivity timeout (%ds)", idleWatch.Sec)
			msg := security.ShellNoOutputTimeoutMessage(idleWatch.Sec)
			_ = sendOut(&filesystem.ExecuteResponse{Output: msg}, nil)
			sb.WriteString(msg)
			if w.appendPartialMonitor != nil && execID != "" {
				w.appendPartialMonitor(execID, toolCallID, msg)
			}
			if w.outputChunk != nil && toolCallID != "" {
				w.outputChunk("execute", toolCallID, msg)
			}
			if cancel != nil {
				cancel()
			}
			closeInner()
		}

	recvLoop:
		for {
			var idleCh <-chan struct{}
			if idleWatch != nil {
				idleCh = idleWatch.Expired
			}
			select {
			case <-idleCh:
				fireInactivityTimeout()
				break recvLoop
			case <-waitTimeoutCh:
				if execID != "" && !softReturned {
					msg := einoExecuteSoftWaitTimeoutResult(execID, waitTimeoutSec)
					_ = outW.Send(&filesystem.ExecuteResponse{Output: msg}, nil)
					softReturned = true
					closeOut()
				}
				waitTimeoutCh = nil
			case msg := <-recvCh:
				rerr := msg.err
				resp := msg.resp
				if errors.Is(rerr, io.EOF) {
					break recvLoop
				}
				if rerr != nil {
					success = false
					invokeErr = rerr
					if einoExecuteRecvErrIsToolTimeout(rerr, tctx) {
						invokeErr = context.DeadlineExceeded
						break recvLoop
					}
					if errors.Is(rerr, context.Canceled) || (tctx != nil && errors.Is(tctx.Err(), context.Canceled)) {
						invokeErr = context.Canceled
						break recvLoop
					}
					_ = sendOut(nil, rerr)
					break recvLoop
				}
				if resp != nil {
					if resp.ExitCode != nil {
						hasExitCode = true
						exitCode = *resp.ExitCode
						continue
					}
					var appended string
					if resp.Output != "" {
						if security.IsLegacyShellExitNoise(resp.Output) {
							continue
						}
						if idleWatch != nil {
							idleWatch.Bump()
						}
						sb.WriteString(resp.Output)
						appended = resp.Output
						if w.appendPartialMonitor != nil && execID != "" {
							w.appendPartialMonitor(execID, toolCallID, appended)
						}
					}
					if w.outputChunk != nil && strings.TrimSpace(appended) != "" {
						w.outputChunk("execute", toolCallID, appended)
					}
					if sendOut(resp, nil) {
						success = false
						invokeErr = fmt.Errorf("execute stream closed by consumer")
						break recvLoop
					}
				}
			}
		}

		if success && hasExitCode && exitCode != 0 {
			success = false
			invokeErr = &ExecuteExitError{Code: exitCode}
		}
		// After WithTimeout fires, the child process is often ended by a signal, and the local side reports exit -1 / canceled; the error chain does not necessarily include DeadlineExceeded.
		// Normalize using the ctx used for execution, so the UI can show "timeout" instead of an ambiguous -1.
		if tctx != nil && errors.Is(tctx.Err(), context.DeadlineExceeded) {
			success = false
			invokeErr = context.DeadlineExceeded
		}
		// The user "interrupts and continues" to terminate execute: merge the note into the tool result (consistent with MCP CancelToolExecutionWithNote).
		partialStreamed := sb.String()
		var abortNote string
		if reg != nil && conversationID != "" && (invokeErr != nil || errors.Is(tctx.Err(), context.Canceled)) {
			if note := reg.TakeEinoExecuteAbortNote(conversationID); note != "" {
				abortNote = note
				merged := mcp.MergePartialToolOutputAndAbortNote(partialStreamed, note)
				sb.Reset()
				sb.WriteString(merged)
				if invokeErr == nil {
					success = false
					invokeErr = context.Canceled
				}
			}
		}
		// ADK assembles the tool message body from this Pipe; a Notify-only trailing tag does not enter the model context. The timeout sentence is written to the stream, consistent with the UI.
		if invokeErr != nil && errors.Is(invokeErr, context.DeadlineExceeded) {
			hint := "\n\n" + einoExecuteTimeoutUserHint() + "\n"
			_ = sendOut(&filesystem.ExecuteResponse{Output: hint}, nil)
			if w.appendPartialMonitor != nil && execID != "" {
				w.appendPartialMonitor(execID, toolCallID, hint)
			}
			if w.outputChunk != nil && tid != "" {
				w.outputChunk("execute", tid, hint)
			}
			sb.WriteString(hint)
		}
		// On interruption, stdout has already been written line by line inside the loop; here only USER INTERRUPT NOTE is appended, to avoid duplicating the entire output.
		if invokeErr != nil && errors.Is(invokeErr, context.Canceled) && abortNote != "" {
			if partialStreamed != "" {
				_ = sendOut(&filesystem.ExecuteResponse{Output: "\n\n" + mcp.AbortNoteBannerForModel + "\n" + abortNote}, nil)
			} else if text := strings.TrimSpace(sb.String()); text != "" {
				_ = sendOut(&filesystem.ExecuteResponse{Output: text + "\n"}, nil)
			}
		}
		rawOutput := sb.String()
		fireBody := rawOutput
		if !success && hasExitCode && exitCode != 0 {
			statusLine := security.ExecuteFailureStatusLine(exitCode)
			if !strings.Contains(rawOutput, "Command execution failed:") {
				_ = sendOut(&filesystem.ExecuteResponse{Output: statusLine}, nil)
				if w.appendPartialMonitor != nil && execID != "" {
					w.appendPartialMonitor(execID, toolCallID, statusLine)
				}
				sb.WriteString(statusLine)
			}
			fireBody = einomcp.ToolErrorPrefix + security.FormatCommandFailureResult(exitCode, rawOutput)
		}
		if w.finishMonitor != nil {
			w.finishMonitor(execID, toolCallID, command, sb.String(), success, invokeErr)
		}
		if w.invokeNotify != nil {
			if !softReturned {
				w.invokeNotify.Fire(toolCallID, "execute", agentTag, success, fireBody, invokeErr)
			}
		}
	}(sr, userCmd, execCancel, timeoutCancel, execCtx, convID, execReg, toolRunReg, monitorExecID, tid, w.shellNoOutputTimeoutSec, w.toolWaitTimeoutSeconds)

	return outR, nil
}

func einoExecuteSoftWaitTimeoutResult(executionID string, waitTimeoutSec int) string {
	waitText := "configured wait timeout"
	if waitTimeoutSec > 0 {
		waitText = fmt.Sprintf("%ds", waitTimeoutSec)
	}
	return fmt.Sprintf(`Tool has been submitted for background execution and is still running.

execution_id: %s
status: running
wait_timeout: %s

You can keep reasoning, switch to other tools, or call get_tool_execution / wait_tool_execution to read partial_output and keep waiting; you can also call cancel_tool_execution to cancel.`, executionID, waitText)
}
