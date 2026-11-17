package einomcp

import (
	"context"
	"strings"
	"testing"
)

func TestUnknownToolReminderText(t *testing.T) {
	s := unknownToolReminderText("bad_tool")
	if !strings.Contains(s, "bad_tool") {
		t.Fatalf("expected requested name in message: %s", s)
	}
	if strings.Contains(s, "Tools currently available") {
		t.Fatal("unified message must not list tool names")
	}
}

func TestApplyToolResultEvidenceRecorderNilIsNoop(t *testing.T) {
	out := applyToolResultEvidenceRecorder(context.Background(), nil, "nmap", "", "body text")
	if out != "body text" {
		t.Fatalf("expected content unchanged with a nil recorder, got %q", out)
	}
}

func TestApplyToolResultEvidenceRecorderAppendsLine(t *testing.T) {
	var gotTool, gotBody string
	rec := func(ctx context.Context, toolName, executionID, content string) string {
		gotTool, gotBody = toolName, content
		return content + "\n[evidence: ev-1]"
	}
	out := applyToolResultEvidenceRecorder(context.Background(), rec, "nmap", "", "scan output")
	if out != "scan output\n[evidence: ev-1]" {
		t.Fatalf("unexpected output: %q", out)
	}
	if gotTool != "nmap" || gotBody != "scan output" {
		t.Fatalf("recorder got (%q, %q)", gotTool, gotBody)
	}
}

func TestApplyToolResultEvidenceRecorderPreservesErrorPrefix(t *testing.T) {
	var gotBody string
	rec := func(ctx context.Context, toolName, executionID, content string) string {
		gotBody = content
		return content + "\n[evidence: ev-2]"
	}
	out := applyToolResultEvidenceRecorder(context.Background(), rec, "execute", "", ToolErrorPrefix+"command failed")
	if !strings.HasPrefix(out, ToolErrorPrefix) {
		t.Fatalf("expected the error prefix to be preserved: %q", out)
	}
	if gotBody != "command failed" {
		t.Fatalf("recorder must see the body without the prefix, got %q", gotBody)
	}
	if !strings.HasSuffix(out, "\n[evidence: ev-2]") {
		t.Fatalf("expected the evidence line appended after the prefix+body: %q", out)
	}
}
