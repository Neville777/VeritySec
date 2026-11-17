package multiagent

import (
	"strings"
	"testing"

	"veritysec/internal/database"

	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

func fixedMessages() []*schema.Message {
	return []*schema.Message{
		schema.SystemMessage("sys prompt"), // 10
		schema.UserMessage("hello"),
		{Role: schema.Assistant, Content: "calling", ToolCalls: []schema.ToolCall{{ID: "1"}}},
		{Role: schema.Tool, Content: "12345", ToolName: "nmap", ToolCallID: "1"},
		{Role: schema.Tool, Content: "123", ToolName: "nmap", ToolCallID: "2"},
		{Role: schema.Tool, Content: "ab", ToolName: "curl", ToolCallID: "3"},
		schema.UserMessage("next"),
	}
}

func TestBuildMessageManifestCounts(t *testing.T) {
	tools := []*schema.ToolInfo{{Name: "nmap", Desc: "scan"}, {Name: "curl", Desc: "fetch"}}
	m := BuildMessageManifest(fixedMessages(), tools)
	if m.SystemChars != 10 || m.UserMessages != 2 || m.AssistantMsgs != 1 || m.ToolMessages != 3 || m.TotalMessages != 7 {
		t.Fatalf("counts: %+v", m)
	}
	if m.ToolResultChars["nmap"] != 8 || m.ToolResultChars["curl"] != 2 || len(m.ToolResultChars) != 2 {
		t.Fatalf("tool result chars: %+v", m.ToolResultChars)
	}
	if m.ToolDefCount != 2 || m.ToolDefChars != len("nmapscan")+len("curlfetch") {
		t.Fatalf("tool defs: %+v", m)
	}
	js := m.JSON()
	for _, secret := range []string{"hello", "sys prompt", "12345", "calling"} {
		if strings.Contains(js, secret) {
			t.Fatalf("manifest leaks content %q: %s", secret, js)
		}
	}
}

func TestBuildAgenticManifestCounts(t *testing.T) {
	msgs := []*schema.AgenticMessage{
		schema.SystemAgenticMessage("sys"),
		schema.UserAgenticMessage("hi"),
		{Role: schema.AgenticRoleTypeUser, ContentBlocks: []*schema.ContentBlock{{
			Type: schema.ContentBlockTypeFunctionToolResult,
			FunctionToolResult: &schema.FunctionToolResult{Name: "nmap", Content: []*schema.FunctionToolResultContentBlock{
				{Type: schema.FunctionToolResultContentBlockTypeText, Text: &schema.UserInputText{Text: "abcd"}},
			}},
		}}},
	}
	m := BuildAgenticManifest(msgs, nil)
	if m.SystemChars != 3 || m.UserMessages != 1 || m.ToolMessages != 1 || m.TotalMessages != 3 || m.ToolResultChars["nmap"] != 4 {
		t.Fatalf("agentic manifest: %+v", m)
	}
}

func TestManifestQueueAndStoredColumn(t *testing.T) {
	pushPendingManifest("c1", "a")
	pushPendingManifest("c1", "b")
	if popPendingManifest("c1") != "a" || popPendingManifest("c1") != "b" || popPendingManifest("c1") != "" {
		t.Fatal("queue should be FIFO and drain")
	}

	db, err := database.NewDB(t.TempDir()+"/m.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	man := BuildMessageManifest(fixedMessages(), nil).JSON()
	u := &schema.TokenUsage{PromptTokens: 5, CompletionTokens: 2}
	if err := db.RecordModelCallUsage("c1", 1, u, man); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordModelCallUsage("c1", 2, u, ""); err != nil {
		t.Fatal(err)
	}
	var got1, got2 *string
	rows, _ := db.Query(`SELECT manifest_json FROM model_call_usage ORDER BY call_index`)
	defer rows.Close()
	rows.Next()
	rows.Scan(&got1)
	rows.Next()
	rows.Scan(&got2)
	if got1 == nil || *got1 != man || got2 != nil {
		t.Fatalf("stored manifests: %v %v", got1, got2)
	}
}
