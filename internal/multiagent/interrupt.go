package multiagent

import "errors"

// ErrInterruptContinue is used as a context.CancelCause: when the user chooses "interrupt and continue" and there is currently no in-progress MCP tool,
// it cancels the current reasoning/streaming output and, within the same conversation task, carries the user's supplementary note to automatically continue the next round (similar to Hermes-style human-in-the-loop turns).
var ErrInterruptContinue = errors.New("agent interrupt: continue with user-supplied context")
