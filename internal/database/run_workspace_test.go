package database

import (
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func setupRunWorkspaceTest(t *testing.T) (*DB, *Conversation, *Message) {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "run-workspace.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	conv, err := db.CreateConversation("conv", ConversationCreateMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMessage(conv.ID, "user", "do the thing", nil); err != nil {
		t.Fatal(err)
	}
	assistant, err := db.AddMessage(conv.ID, "assistant", "working", nil)
	if err != nil {
		t.Fatal(err)
	}
	return db, conv, assistant
}

func TestRunWorkspaceRunningWithoutDoneEvent(t *testing.T) {
	db, _, assistant := setupRunWorkspaceTest(t)
	if err := db.AddProcessDetail(assistant.ID, assistant.ConversationID, "progress", "working on it", nil); err != nil {
		t.Fatal(err)
	}
	ws, err := db.GetRunWorkspace(assistant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Run.Status != "running" {
		t.Fatalf("status = %q, want running", ws.Run.Status)
	}
	if ws.Run.EndedAt != nil || ws.Run.DurationMs != nil {
		t.Fatalf("expected no end marker while running: %+v", ws.Run)
	}
}

func TestRunWorkspaceCompletedOnDoneEvent(t *testing.T) {
	db, _, assistant := setupRunWorkspaceTest(t)
	if err := db.AddProcessDetail(assistant.ID, assistant.ConversationID, "done", "finished", nil); err != nil {
		t.Fatal(err)
	}
	ws, err := db.GetRunWorkspace(assistant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Run.Status != "completed" {
		t.Fatalf("status = %q, want completed", ws.Run.Status)
	}
	if ws.Run.EndedAt == nil || ws.Run.DurationMs == nil {
		t.Fatalf("expected an end marker once done: %+v", ws.Run)
	}
}

func TestRunWorkspaceBillingTextMakesStatusInterrupted(t *testing.T) {
	db, _, assistant := setupRunWorkspaceTest(t)
	if err := db.AddProcessDetail(assistant.ID, assistant.ConversationID, "progress", "upstream call failed: HTTP 402 insufficient balance", nil); err != nil {
		t.Fatal(err)
	}
	ws, err := db.GetRunWorkspace(assistant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Run.Status != "interrupted" {
		t.Fatalf("status = %q, want interrupted", ws.Run.Status)
	}
}

func TestRunWorkspaceErrorEventMakesStatusInterrupted(t *testing.T) {
	db, _, assistant := setupRunWorkspaceTest(t)
	if err := db.AddProcessDetail(assistant.ID, assistant.ConversationID, "error", "the model call failed", nil); err != nil {
		t.Fatal(err)
	}
	ws, err := db.GetRunWorkspace(assistant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Run.Status != "interrupted" {
		t.Fatalf("status = %q, want interrupted", ws.Run.Status)
	}
}

func TestRunWorkspaceCompletedWithUnresolvedStage(t *testing.T) {
	db, conv, assistant := setupRunWorkspaceTest(t)
	eng, err := db.CreateEngagement(&Engagement{Name: "eng"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AttachConversationToEngagement(eng.ID, conv.ID); err != nil {
		t.Fatal(err)
	}
	// No tool evidence recorded for the stage: MarkAssessmentStageStalled leaves it "blocked",
	// which is an unresolved stage just like "needs_review".
	if _, err := db.MarkAssessmentStageStalled(eng.ID, StageAuthorisation, "stalled for the test", "system"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddProcessDetail(assistant.ID, assistant.ConversationID, "done", "finished", nil); err != nil {
		t.Fatal(err)
	}
	ws, err := db.GetRunWorkspace(assistant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Run.Status != "completed_with_unresolved" {
		t.Fatalf("status = %q, want completed_with_unresolved", ws.Run.Status)
	}
}

// TestRunWorkspaceWindowsToolsAndEvidence verifies that tool executions and evidence outside the
// run window (before started_at, or after the done event) are excluded, while rows inside it and
// evidence linked to one of the run's tool executions are kept.
func TestRunWorkspaceWindowsToolsAndEvidence(t *testing.T) {
	db, conv, assistant := setupRunWorkspaceTest(t)
	eng, err := db.CreateEngagement(&Engagement{Name: "eng"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AttachConversationToEngagement(eng.ID, conv.ID); err != nil {
		t.Fatal(err)
	}

	startedAt := assistant.CreatedAt
	beforeStart := startedAt.Add(-1 * time.Hour)
	inWindow := startedAt.Add(1 * time.Minute)
	doneAt := startedAt.Add(2 * time.Minute)
	afterEnd := startedAt.Add(1 * time.Hour)

	// Tool execution before the run started: excluded.
	if _, err := db.Exec(`INSERT INTO tool_executions (id, tool_name, arguments, status, start_time, conversation_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"exec-before", "nmap", "{}", "completed", beforeStart, conv.ID); err != nil {
		t.Fatal(err)
	}
	// Tool execution inside the window: included.
	if _, err := db.Exec(`INSERT INTO tool_executions (id, tool_name, arguments, status, start_time, conversation_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"exec-in", "nmap", "{}", "completed", inWindow, conv.ID); err != nil {
		t.Fatal(err)
	}
	// Tool execution after the run ends: excluded.
	if _, err := db.Exec(`INSERT INTO tool_executions (id, tool_name, arguments, status, start_time, conversation_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"exec-after", "nmap", "{}", "completed", afterEnd, conv.ID); err != nil {
		t.Fatal(err)
	}

	// Evidence linked to the in-window tool execution: included regardless of its own timestamp.
	evLinked := NewEvidenceRecord(eng.ID)
	evLinked.Kind, evLinked.Origin, evLinked.ToolExecutionID = EvidenceToolOutput, EvidenceOriginTool, "exec-in"
	evLinked.StoragePath, evLinked.SHA256 = "x/"+evLinked.ID, "abc"
	evLinked.CreatedAt = afterEnd // timestamp alone would place it outside the window
	if err := db.InsertEvidence(evLinked); err != nil {
		t.Fatal(err)
	}
	// Evidence with no tool_execution_id, created outside the window: excluded.
	evOutside := NewEvidenceRecord(eng.ID)
	evOutside.Kind, evOutside.Origin = EvidenceNote, EvidenceOriginManual
	evOutside.StoragePath, evOutside.SHA256 = "x/"+evOutside.ID, "def"
	evOutside.CreatedAt = afterEnd
	if err := db.InsertEvidence(evOutside); err != nil {
		t.Fatal(err)
	}
	// Evidence with no tool_execution_id, created inside the window: included.
	evInside := NewEvidenceRecord(eng.ID)
	evInside.Kind, evInside.Origin = EvidenceNote, EvidenceOriginManual
	evInside.StoragePath, evInside.SHA256 = "x/"+evInside.ID, "ghi"
	evInside.CreatedAt = inWindow
	if err := db.InsertEvidence(evInside); err != nil {
		t.Fatal(err)
	}

	if err := db.AddProcessDetail(assistant.ID, conv.ID, "done", "finished", nil); err != nil {
		t.Fatal(err)
	}
	// Pin the done event's timestamp so the window end is deterministic.
	if _, err := db.Exec(`UPDATE process_details SET created_at = ? WHERE message_id = ? AND event_type = 'done'`, doneAt, assistant.ID); err != nil {
		t.Fatal(err)
	}

	ws, err := db.GetRunWorkspace(assistant.ID)
	if err != nil {
		t.Fatal(err)
	}

	gotTools := map[string]bool{}
	for _, tool := range ws.Tools {
		gotTools[tool.ExecutionID] = true
	}
	if gotTools["exec-before"] || gotTools["exec-after"] {
		t.Fatalf("tools outside the window were included: %+v", ws.Tools)
	}
	if !gotTools["exec-in"] {
		t.Fatalf("tool inside the window was excluded: %+v", ws.Tools)
	}

	gotEvidence := map[string]bool{}
	for _, ev := range ws.Evidence {
		gotEvidence[ev.ID] = true
	}
	if gotEvidence[evOutside.ID] {
		t.Fatalf("evidence outside the window was included: %+v", ws.Evidence)
	}
	if !gotEvidence[evLinked.ID] {
		t.Fatalf("evidence linked to an in-window tool execution was excluded: %+v", ws.Evidence)
	}
	if !gotEvidence[evInside.ID] {
		t.Fatalf("evidence created inside the window was excluded: %+v", ws.Evidence)
	}
}

func TestRunWorkspaceUnknownMessageNotFound(t *testing.T) {
	db, _, _ := setupRunWorkspaceTest(t)
	if _, err := db.GetRunWorkspace("does-not-exist"); err == nil {
		t.Fatal("expected an error for an unknown message")
	}
}
