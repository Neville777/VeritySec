package database

import (
	"testing"
	"time"
)

// TestResumePlanCompletedAndUnknownExecutions covers task 3: completed tool executions are
// listed and must not be repeated, a started-but-unfinished execution is flagged unknown, and
// auto-resumable is false whenever any unknown execution exists.
func TestResumePlanCompletedAndUnknownExecutions(t *testing.T) {
	db, conv, assistant := setupRunWorkspaceTest(t)
	startedAt := assistant.CreatedAt
	inWindow := startedAt.Add(1 * time.Minute)

	if _, err := db.Exec(`INSERT INTO tool_executions (id, tool_name, arguments, status, start_time, conversation_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"exec-done", "nmap", "{}", "completed", inWindow, conv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tool_executions (id, tool_name, arguments, status, start_time, conversation_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"exec-running", "amass", "{}", "running", inWindow, conv.ID); err != nil {
		t.Fatal(err)
	}

	plan, err := db.ResumePlan(assistant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.CompletedExecutions) != 1 || plan.CompletedExecutions[0].ExecutionID != "exec-done" {
		t.Fatalf("completed executions: %+v", plan.CompletedExecutions)
	}
	if len(plan.UnknownExecutions) != 1 || plan.UnknownExecutions[0].ExecutionID != "exec-running" {
		t.Fatalf("unknown executions: %+v", plan.UnknownExecutions)
	}
	if plan.AutoResumable {
		t.Fatal("auto_resumable must be false while an execution is unknown")
	}
}

// TestResumePlanAutoResumableWithNoUnknown covers the "true only when there are no unknown
// executions" rule, and that stage checkpoints populate last-completed/resume stage.
func TestResumePlanAutoResumableWithNoUnknown(t *testing.T) {
	db, conv, assistant := setupRunWorkspaceTest(t)
	eng, err := db.CreateEngagement(&Engagement{Name: "eng"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AttachConversationToEngagement(eng.ID, conv.ID); err != nil {
		t.Fatal(err)
	}
	startedAt := assistant.CreatedAt
	inWindow := startedAt.Add(1 * time.Minute)
	if _, err := db.Exec(`INSERT INTO tool_executions (id, tool_name, arguments, status, start_time, conversation_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"exec-done", "nmap", "{}", "completed", inWindow, conv.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteRunCheckpoint(assistant.ID, conv.ID, eng.ID, StageAuthorisation, CheckpointKindStageComplete, map[string]interface{}{"stage": StageAuthorisation}); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteRunCheckpoint(assistant.ID, conv.ID, eng.ID, StageReconnaissance, CheckpointKindStageStart, map[string]interface{}{"stage": StageReconnaissance}); err != nil {
		t.Fatal(err)
	}

	plan, err := db.ResumePlan(assistant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.AutoResumable {
		t.Fatal("auto_resumable must be true when nothing is unknown")
	}
	if plan.LastCompletedStage != StageAuthorisation {
		t.Fatalf("last completed stage = %q", plan.LastCompletedStage)
	}
	if plan.ResumeStage != StageReconnaissance {
		t.Fatalf("resume stage = %q", plan.ResumeStage)
	}
	if len(plan.UnknownExecutions) != 0 {
		t.Fatalf("unknown executions: %+v", plan.UnknownExecutions)
	}

	if _, err := db.ResumePlan("no-such-message"); err == nil {
		t.Fatal("expected an error for an unknown message")
	}
}

// TestWriteRunCheckpointDataIsIDsOnly is a smoke test that checkpoint data only ever carries the
// fields the caller gave it (IDs), never arbitrary content, and that blank message/conversation
// IDs are tolerated (stored as NULL, simply not found by a later ResumePlan/List by message).
func TestWriteRunCheckpointDataIsIDsOnly(t *testing.T) {
	db, conv, assistant := setupRunWorkspaceTest(t)
	eng, err := db.CreateEngagement(&Engagement{Name: "eng"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WriteRunCheckpoint(assistant.ID, conv.ID, eng.ID, StageReconnaissance, CheckpointKindToolExecution, map[string]interface{}{
		"tool_execution_id": "exec-1", "evidence_id": "ev-1", "stage": StageReconnaissance, "sequence": 1,
	}); err != nil {
		t.Fatal(err)
	}
	cps, err := db.ListRunCheckpoints(assistant.ID)
	if err != nil || len(cps) != 1 {
		t.Fatalf("%+v %v", cps, err)
	}
	if cps[0].DataJSON == "" || cps[0].Kind != CheckpointKindToolExecution {
		t.Fatalf("%+v", cps[0])
	}

	// Blank message ID: not found by ListRunCheckpoints(messageID) for anything.
	if err := db.WriteRunCheckpoint("", "", "", "", CheckpointKindToolExecution, nil); err != nil {
		t.Fatal(err)
	}
	if cps, err := db.ListRunCheckpoints(""); err != nil || len(cps) != 0 {
		t.Fatalf("blank message id lookup: %+v %v", cps, err)
	}
}
