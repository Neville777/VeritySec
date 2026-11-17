package einomcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"veritysec/internal/agent"
	"veritysec/internal/security"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"github.com/eino-contrib/jsonschema"
)

// ExecutionRecorder is optional; it is called back when an MCP tool returns successfully with an execution id (used to aggregate mcpExecutionIds).
// toolCallID comes from Eino compose.GetToolCallID and is used to associate it with the display result after reduction.
type ExecutionRecorder func(executionID, toolCallID string)

// ToolResultEvidenceRecorder is optional; when the current run belongs to an engagement, it stores
// a tool's successful text result as evidence and returns the text to show the model with an
// "[evidence: <id>]" line appended. It is nil-safe: a nil recorder disables the behavior, and the
// recorder itself is expected to no-op (return content unchanged) for conversations without an
// engagement.
type ToolResultEvidenceRecorder func(ctx context.Context, toolName, executionID, content string) string

// ToolErrorPrefix is used to pass the IsError flag from internal MCP execution results up to the multi-agent layer.
// The Eino tool channel currently only supports returning strings, so the flag is conveyed via a prefix, which the multi-agent runner later parses into success/isError.
const ToolErrorPrefix = "__VERITYSEC_AI_TOOL_ERROR__\n"

// ToolsFromDefinitions converts the OpenAI-style tool definitions used by a single Agent into Eino InvokableTools; execution goes through the Agent's MCP path.
// invokeNotify is optional: shared with runEinoADKAgentLoop; when InvokableRun returns it triggers UI updates and pending cleanup (deduplicated against ADK Tool events).
// einoAgentName is the Name of the ChatModelAgent that owns this tool set (main agent or sub-agent id), used for the einoAgent field on SSE.
func ToolsFromDefinitions(
	ag *agent.Agent,
	holder *ConversationHolder,
	defs []agent.Tool,
	rec ExecutionRecorder,
	toolOutputChunk func(toolName, toolCallID, chunk string),
	invokeNotify *ToolInvokeNotifyHolder,
	einoAgentName string,
) ([]tool.BaseTool, error) {
	return ToolsFromDefinitionsWithEvidence(ag, holder, defs, rec, toolOutputChunk, invokeNotify, einoAgentName, nil)
}

// ToolsFromDefinitionsWithEvidence is ToolsFromDefinitions with an optional evidence recorder
// (see ToolResultEvidenceRecorder); pass nil to disable it.
func ToolsFromDefinitionsWithEvidence(
	ag *agent.Agent,
	holder *ConversationHolder,
	defs []agent.Tool,
	rec ExecutionRecorder,
	toolOutputChunk func(toolName, toolCallID, chunk string),
	invokeNotify *ToolInvokeNotifyHolder,
	einoAgentName string,
	evidenceRecord ToolResultEvidenceRecorder,
) ([]tool.BaseTool, error) {
	return ToolsFromDefinitionsWithScope(ag, holder, defs, rec, toolOutputChunk, invokeNotify, einoAgentName, evidenceRecord, nil)
}

// ToolsFromDefinitionsWithScope is ToolsFromDefinitionsWithEvidence with an optional scope guard
// (see ScopeGuard); pass nil to disable it.
func ToolsFromDefinitionsWithScope(
	ag *agent.Agent,
	holder *ConversationHolder,
	defs []agent.Tool,
	rec ExecutionRecorder,
	toolOutputChunk func(toolName, toolCallID, chunk string),
	invokeNotify *ToolInvokeNotifyHolder,
	einoAgentName string,
	evidenceRecord ToolResultEvidenceRecorder,
	scopeGuard ScopeGuard,
) ([]tool.BaseTool, error) {
	out := make([]tool.BaseTool, 0, len(defs))
	for _, d := range defs {
		if d.Type != "function" || d.Function.Name == "" {
			continue
		}
		info, err := toolInfoFromDefinition(d)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", d.Function.Name, err)
		}
		out = append(out, &mcpBridgeTool{
			info:           info,
			name:           d.Function.Name,
			agent:          ag,
			holder:         holder,
			record:         rec,
			chunk:          toolOutputChunk,
			invokeNotify:   invokeNotify,
			einoAgentName:  strings.TrimSpace(einoAgentName),
			evidenceRecord: evidenceRecord,
			scopeGuard:     scopeGuard,
		})
	}
	return out, nil
}

func toolInfoFromDefinition(d agent.Tool) (*schema.ToolInfo, error) {
	fn := d.Function
	raw, err := json.Marshal(fn.Parameters)
	if err != nil {
		return nil, err
	}
	var js jsonschema.Schema
	if len(raw) > 0 && string(raw) != "null" && string(raw) != "{}" {
		if err := json.Unmarshal(raw, &js); err != nil {
			return nil, err
		}
	}
	if js.Type == "" {
		js.Type = string(schema.Object)
	}
	if js.Properties == nil && js.Type == string(schema.Object) {
		// empty argument object
	}
	return &schema.ToolInfo{
		Name:        fn.Name,
		Desc:        fn.Description,
		ParamsOneOf: schema.NewParamsOneOfByJSONSchema(&js),
	}, nil
}

type mcpBridgeTool struct {
	info           *schema.ToolInfo
	name           string
	agent          *agent.Agent
	holder         *ConversationHolder
	record         ExecutionRecorder
	chunk          func(toolName, toolCallID, chunk string)
	invokeNotify   *ToolInvokeNotifyHolder
	einoAgentName  string
	evidenceRecord ToolResultEvidenceRecorder
	scopeGuard     ScopeGuard
}

func (m *mcpBridgeTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	_ = ctx
	return m.info, nil
}

func (m *mcpBridgeTool) InvokableRun(ctx context.Context, argumentsInJSON string, opts ...tool.Option) (out string, err error) {
	_ = opts
	toolCallID := compose.GetToolCallID(ctx)
	// uiOut holds the full (non-compacted) result when the model-facing value was compacted; the UI
	// notification and evidence always see the full text.
	var uiOut string
	defer func() {
		if m.invokeNotify == nil {
			return
		}
		tid := strings.TrimSpace(toolCallID)
		if tid == "" {
			return
		}
		success := err == nil && !strings.HasPrefix(out, ToolErrorPrefix)
		body := out
		if uiOut != "" && success {
			body = uiOut
		}
		if err != nil {
			success = false
		} else if strings.HasPrefix(out, ToolErrorPrefix) {
			success = false
			body = strings.TrimPrefix(out, ToolErrorPrefix)
		}
		m.invokeNotify.Fire(tid, m.name, m.einoAgentName, success, body, err)
	}()
	var execID string
	// Repeated-failure stop (per run, per tool): the same tool with the same normalised arguments
	// failing repeatedFailureLimit times in a row is not executed again; a changed argument set
	// resets the count and other tools are unaffected.
	var argsKey string
	if m.holder != nil {
		argsKey = normalizeToolArgsKey(argumentsInJSON)
		if msg, stop := m.holder.failures.blocked(m.name, argsKey); stop {
			return ToolErrorPrefix + msg, nil
		}
	}
	out, execID, err = runMCPToolInvocation(ctx, m.agent, m.holder, m.name, argumentsInJSON, m.record, m.chunk, m.scopeGuard)
	if m.holder != nil {
		switch {
		case err != nil:
			m.holder.failures.record(m.name, argsKey, err.Error())
		case strings.HasPrefix(out, ToolErrorPrefix):
			m.holder.failures.record(m.name, argsKey, strings.TrimPrefix(out, ToolErrorPrefix))
		default:
			m.holder.failures.record(m.name, argsKey, "")
		}
	}
	if err == nil {
		out = applyToolResultEvidenceRecorder(ctx, m.evidenceRecord, m.name, execID, out)
		if compact, ok := compactRecordedToolResult(m.name, out); ok {
			// Only the model sees the compact block; the UI notification above keeps the full text.
			uiOut = out
			out = compact
		}
	}
	return out, err
}

// ToolResultCompactThreshold is the size (characters) above which a successful, evidence-recorded
// tool result is replaced in the model history by a compact block. Single source of truth.
const ToolResultCompactThreshold = 4000

// toolResultCompactPreviewChars is how much of the output the compact block keeps inline.
const toolResultCompactPreviewChars = 1500

const evidenceLineMarker = "\n[evidence: "

// compactRecordedToolResult builds the compact block for a recorded result (content ending in the
// "[evidence: <id>]" line appended by the recorder). It returns ok=false, leaving the result as is,
// when the result is an error, has no evidence ID (nothing stored, so nothing may be dropped), or is
// not larger than ToolResultCompactThreshold.
func compactRecordedToolResult(toolName, recorded string) (string, bool) {
	if strings.HasPrefix(recorded, ToolErrorPrefix) || !strings.HasSuffix(recorded, "]") {
		return "", false
	}
	i := strings.LastIndex(recorded, evidenceLineMarker)
	if i < 0 {
		return "", false
	}
	id := strings.TrimSpace(recorded[i+len(evidenceLineMarker) : len(recorded)-1])
	body := recorded[:i]
	obsBlock := ""
	if j := strings.Index(body, observationsOpen); j >= 0 {
		if k := strings.Index(body[j:], observationsClose); k >= 0 {
			obsBlock = body[j+len(observationsOpen) : j+k]
			body = body[:j] + body[j+k+len(observationsClose):]
		}
	}
	if id == "" || strings.ContainsAny(id, " \n") || len([]rune(body)) <= ToolResultCompactThreshold {
		return "", false
	}
	runes := []rune(body)
	preview := string(runes[:toolResultCompactPreviewChars])
	lines := strings.Count(body, "\n") + 1
	var b strings.Builder
	fmt.Fprintf(&b, "[tool result compacted] tool: %s\nstatus: ok\nlines: %d\nchars: %d\nevidence: %s\n--- first %d characters ---\n%s\n--- end of preview ---\n",
		toolName, lines, len(runes), id, toolResultCompactPreviewChars, preview)
	if obsBlock != "" {
		b.WriteString(obsBlock)
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Full output saved as evidence %s; ask for a section with read_evidence if you need more", id)
	return b.String(), true
}

// applyToolResultEvidenceRecorder runs the evidence recorder (if any) on a successful tool
// result's body, preserving the ToolErrorPrefix flag used to carry IsError up to the multi-agent
// layer. A nil recorder leaves content unchanged.
func applyToolResultEvidenceRecorder(ctx context.Context, evidenceRecord ToolResultEvidenceRecorder, toolName, executionID, content string) string {
	if evidenceRecord == nil {
		return content
	}
	body := content
	prefix := ""
	if strings.HasPrefix(body, ToolErrorPrefix) {
		prefix = ToolErrorPrefix
		body = strings.TrimPrefix(body, ToolErrorPrefix)
	}
	return prefix + evidenceRecord(ctx, toolName, executionID, body)
}

// runMCPToolInvocation is shared with mcpBridgeTool.InvokableRun.
func runMCPToolInvocation(
	ctx context.Context,
	ag *agent.Agent,
	holder *ConversationHolder,
	toolName string,
	argumentsInJSON string,
	record ExecutionRecorder,
	chunk func(toolName, toolCallID, chunk string),
	scopeGuard ScopeGuard,
) (string, string, error) {
	var args map[string]interface{}
	if argumentsInJSON != "" && argumentsInJSON != "null" {
		if err := json.Unmarshal([]byte(argumentsInJSON), &args); err != nil {
			// Return soft error (nil error) so the eino graph continues and the LLM can self-correct,
			// instead of a hard error that terminates the iteration loop.
			return ToolErrorPrefix + fmt.Sprintf(
				"Invalid tool arguments JSON: %s\n\nPlease ensure the arguments are a valid JSON object "+
					"(double-quoted keys, matched braces, no trailing commas) and retry.\n\n"+
					"(failed to parse tool argument JSON: %s. Make sure arguments is a valid JSON object and retry.)",
				err.Error(), err.Error()), "", nil
		}
	}
	if args == nil {
		args = map[string]interface{}{}
	}

	// Scope hook: the single choke point before any MCP tool is dispatched. The guard only ever
	// refuses (a soft tool error the model can read); a call that names no target is not a network
	// action and a conversation without an engagement has no scope, so both proceed unchanged.
	// A nil guard (scope_enforcement off) performs no check.
	if scopeGuard != nil {
		if refusal := scopeGuard(ctx, toolName, args); refusal != "" {
			return ToolErrorPrefix + refusal, "", nil
		}
	}

	if chunk != nil {
		toolCallID := compose.GetToolCallID(ctx)
		if toolCallID != "" {
			if existing, ok := ctx.Value(security.ToolOutputCallbackCtxKey).(security.ToolOutputCallback); ok && existing != nil {
				ctx = context.WithValue(ctx, security.ToolOutputCallbackCtxKey, security.ToolOutputCallback(func(c string) {
					existing(c)
					if strings.TrimSpace(c) == "" {
						return
					}
					chunk(toolName, toolCallID, c)
				}))
			} else {
				ctx = context.WithValue(ctx, security.ToolOutputCallbackCtxKey, security.ToolOutputCallback(func(c string) {
					if strings.TrimSpace(c) == "" {
						return
					}
					chunk(toolName, toolCallID, c)
				}))
			}
		}
	}

	res, err := ag.ExecuteMCPToolForConversation(ctx, holder.Get(), toolName, args)
	if err != nil {
		return "", "", err
	}
	if res == nil {
		return "", "", nil
	}
	if res.ExecutionID != "" && record != nil {
		record(res.ExecutionID, compose.GetToolCallID(ctx))
	}
	if res.IsError {
		return ToolErrorPrefix + res.Result, res.ExecutionID, nil
	}
	return res.Result, res.ExecutionID, nil
}

// UnknownToolReminderHandler is used by compose.ToolsNodeConfig.UnknownToolsHandler:
// when the model requests an unregistered tool name, it returns a "soft error" tool result (nil error),
// letting the model self-correct within the same turn and avoiding a run-loop-level full rerun.
// No name guessing or mapping is done, to avoid mis-executing.
func UnknownToolReminderHandler() func(ctx context.Context, name, input string) (string, error) {
	return func(ctx context.Context, name, input string) (string, error) {
		_ = ctx
		_ = input
		requested := strings.TrimSpace(name)
		// Return a soft tool-result error so the graph keeps running and the LLM
		// can correct tool name/arguments within the same run.
		return ToolErrorPrefix + unknownToolReminderText(requested), nil
	}
}

func unknownToolReminderText(requested string) string {
	if requested == "" {
		requested = "(empty)"
	}
	return fmt.Sprintf(`The tool name %q is not registered for this agent.

Please retry using only names that appear in the tool definitions for this turn (exact match, case-sensitive). Do not invent or rename tools; adjust your plan and continue.

(tool %q is not registered: use only the tool names given in this turn's context, exactly as written; do not rewrite or guess names, and continue with the remaining steps.)`, requested, requested)
}
