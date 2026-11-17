package multiagent

import (
	"context"
	"encoding/json"
	"sync"
	"unicode/utf8"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

// maxManifestToolNames bounds the per-tool breakdown so a manifest stays small.
const maxManifestToolNames = 40

// maxPendingManifests bounds the per-conversation queue of manifests awaiting their usage record.
const maxPendingManifests = 64

// ModelCallManifest describes the size of what is sent in one model call. It holds counts and
// character lengths only, never message content.
type ModelCallManifest struct {
	SystemChars      int            `json:"system_chars"`
	ToolDefChars     int            `json:"tool_def_chars"`
	ToolDefCount     int            `json:"tool_def_count"`
	UserMessages     int            `json:"user_messages"`
	AssistantMsgs    int            `json:"assistant_messages"`
	ToolMessages     int            `json:"tool_messages"`
	TotalMessages    int            `json:"total_messages"`
	ToolResultChars  map[string]int `json:"tool_result_chars,omitempty"`
	ToolResultsOther int            `json:"tool_result_chars_other,omitempty"`
}

// JSON renders the manifest as compact JSON.
func (m ModelCallManifest) JSON() string {
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

func (m *ModelCallManifest) addToolResult(name string, chars int) {
	if name == "" {
		name = "unknown"
	}
	if m.ToolResultChars == nil {
		m.ToolResultChars = map[string]int{}
	}
	if _, ok := m.ToolResultChars[name]; !ok && len(m.ToolResultChars) >= maxManifestToolNames {
		m.ToolResultsOther += chars
		return
	}
	m.ToolResultChars[name] += chars
}

func toolInfoChars(tools []*schema.ToolInfo) int {
	n := 0
	for _, t := range tools {
		if t == nil {
			continue
		}
		n += utf8.RuneCountInString(t.Name) + utf8.RuneCountInString(t.Desc)
		if t.ParamsOneOf != nil {
			if js, err := t.ParamsOneOf.ToJSONSchema(); err == nil && js != nil {
				if b, err := json.Marshal(js); err == nil {
					n += utf8.RuneCount(b)
				}
			}
		}
	}
	return n
}

// BuildMessageManifest computes the manifest for a classic message list and tool definitions.
func BuildMessageManifest(msgs []*schema.Message, tools []*schema.ToolInfo) ModelCallManifest {
	m := ModelCallManifest{ToolDefChars: toolInfoChars(tools), ToolDefCount: len(tools)}
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		m.TotalMessages++
		switch msg.Role {
		case schema.System:
			m.SystemChars += utf8.RuneCountInString(msg.Content)
		case schema.User:
			m.UserMessages++
		case schema.Assistant:
			m.AssistantMsgs++
		case schema.Tool:
			m.ToolMessages++
			m.addToolResult(msg.ToolName, utf8.RuneCountInString(msg.Content))
		}
	}
	return m
}

// BuildAgenticManifest computes the manifest for an agentic message list.
func BuildAgenticManifest(msgs []*schema.AgenticMessage, tools []*schema.ToolInfo) ModelCallManifest {
	m := ModelCallManifest{ToolDefChars: toolInfoChars(tools), ToolDefCount: len(tools)}
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		m.TotalMessages++
		switch msg.Role {
		case schema.AgenticRoleTypeSystem:
			for _, b := range msg.ContentBlocks {
				if b != nil && b.UserInputText != nil {
					m.SystemChars += utf8.RuneCountInString(b.UserInputText.Text)
				}
			}
		case schema.AgenticRoleTypeAssistant:
			m.AssistantMsgs++
		case schema.AgenticRoleTypeUser:
			hasResult := false
			for _, b := range msg.ContentBlocks {
				if b == nil || b.FunctionToolResult == nil {
					continue
				}
				hasResult = true
				chars := 0
				for _, c := range b.FunctionToolResult.Content {
					if c != nil && c.Text != nil {
						chars += utf8.RuneCountInString(c.Text.Text)
					}
				}
				m.addToolResult(b.FunctionToolResult.Name, chars)
			}
			if hasResult {
				m.ToolMessages++
			} else {
				m.UserMessages++
			}
		}
	}
	return m
}

var pendingManifests sync.Map // conversationID -> *manifestQueue

type manifestQueue struct {
	mu    sync.Mutex
	items []string
}

func queueFor(conversationID string) *manifestQueue {
	v, _ := pendingManifests.LoadOrStore(conversationID, &manifestQueue{})
	return v.(*manifestQueue)
}

func pushPendingManifest(conversationID, manifestJSON string) {
	q := queueFor(conversationID)
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= maxPendingManifests {
		q.items = q.items[1:]
	}
	q.items = append(q.items, manifestJSON)
}

// popPendingManifest returns the oldest manifest awaiting its usage record, or "".
func popPendingManifest(conversationID string) string {
	v, ok := pendingManifests.Load(conversationID)
	if !ok {
		return ""
	}
	q := v.(*manifestQueue)
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return ""
	}
	s := q.items[0]
	q.items = q.items[1:]
	if len(q.items) == 0 {
		pendingManifests.Delete(conversationID)
	}
	return s
}

// manifestMiddleware records a manifest before every model call.
type manifestMiddleware[M adk.MessageType] struct {
	*adk.TypedBaseChatModelAgentMiddleware[M]
	conversationID string
	build          func(msgs []M, tools []*schema.ToolInfo) ModelCallManifest
}

func (w *manifestMiddleware[M]) BeforeModelRewriteState(ctx context.Context, state *adk.TypedChatModelAgentState[M], mc *adk.TypedModelContext[M]) (context.Context, *adk.TypedChatModelAgentState[M], error) {
	if state != nil && ModelCallUsageSink != nil {
		pushPendingManifest(w.conversationID, w.build(state.Messages, state.ToolInfos).JSON())
	}
	return ctx, state, nil
}

func newManifestMiddleware(conversationID string) adk.ChatModelAgentMiddleware {
	return &manifestMiddleware[*schema.Message]{
		TypedBaseChatModelAgentMiddleware: &adk.TypedBaseChatModelAgentMiddleware[*schema.Message]{},
		conversationID:                    conversationID, build: BuildMessageManifest,
	}
}

func newAgenticManifestMiddleware(conversationID string) adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	return &manifestMiddleware[*schema.AgenticMessage]{
		TypedBaseChatModelAgentMiddleware: &adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]{},
		conversationID:                    conversationID, build: BuildAgenticManifest,
	}
}
