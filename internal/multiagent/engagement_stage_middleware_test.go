package multiagent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"veritysec/internal/config"
	"veritysec/internal/database"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

func engagementTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "eng.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func createEngagementWithConversation(t *testing.T, db *database.DB) (*database.Engagement, string) {
	t.Helper()
	e, err := db.CreateEngagement(&database.Engagement{
		Name:              "e1",
		AuthorizationNote: "SOW-1",
		ScopeJSON:         []byte(`{"included":["acme.example"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "conv-eng", "t"); err != nil {
		t.Fatal(err)
	}
	if err := db.AttachConversationToEngagement(e.ID, "conv-eng"); err != nil {
		t.Fatal(err)
	}
	return e, "conv-eng"
}

// TestEngagementStageMiddlewareAutoStartsOnce exercises the auto-start behaviour through repeated
// BeforeModelRewriteState calls (as happens across a run's many model-call iterations): the first
// stage must move to "running" exactly once, with initiated_by "system".
func TestEngagementStageMiddlewareAutoStartsOnce(t *testing.T) {
	db := engagementTestDB(t)
	e, convID := createEngagementWithConversation(t, db)
	mw := newEngagementStageMiddleware(db, convID)
	if mw == nil {
		t.Fatal("expected non-nil middleware")
	}
	for i := 0; i < 3; i++ {
		state := &adk.TypedChatModelAgentState[*schema.AgenticMessage]{}
		if _, _, err := mw.BeforeModelRewriteState(context.Background(), state, &adk.TypedModelContext[*schema.AgenticMessage]{}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	stages, err := db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].Status != database.StageRunning {
		t.Fatalf("expected AUTHORISATION running after repeated calls, got %+v", stages[0])
	}
	if stages[0].InitiatedBy != "system" {
		t.Fatalf("expected initiated_by system, got %q", stages[0].InitiatedBy)
	}
	if stages[1].Status != database.StagePending {
		t.Fatalf("second stage must not be auto-started: %+v", stages[1])
	}
}

// TestEngagementStageMiddlewareInjectsStageContext checks the injected system message names the
// right stage, lists evidence IDs only (never content) and stays under the length budget.
func TestEngagementStageMiddlewareInjectsStageContext(t *testing.T) {
	db := engagementTestDB(t)
	e, convID := createEngagementWithConversation(t, db)
	mw := newEngagementStageMiddleware(db, convID)

	for i := 0; i < 25; i++ {
		ev := database.NewEvidenceRecord(e.ID)
		ev.Kind, ev.StoragePath, ev.SHA256 = database.EvidenceNote, "p", "h"
		ev.Title = "SECRET-CONTENT-SHOULD-NOT-APPEAR"
		if err := db.InsertEvidence(ev); err != nil {
			t.Fatal(err)
		}
	}

	state := &adk.TypedChatModelAgentState[*schema.AgenticMessage]{}
	_, state, err := mw.BeforeModelRewriteState(context.Background(), state, &adk.TypedModelContext[*schema.AgenticMessage]{})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Messages) != 1 {
		t.Fatalf("expected exactly one injected message, got %d", len(state.Messages))
	}
	msg := state.Messages[0]
	if msg.Role != schema.AgenticRoleTypeSystem {
		t.Fatalf("expected a system message, got role %q", msg.Role)
	}
	var text string
	for _, b := range msg.ContentBlocks {
		if b != nil && b.UserInputText != nil {
			text += b.UserInputText.Text
		}
	}
	if !strings.Contains(text, database.StageAuthorisation) {
		t.Fatalf("expected the current stage name in the message: %q", text)
	}
	if strings.Contains(text, "SECRET-CONTENT-SHOULD-NOT-APPEAR") {
		t.Fatalf("message must carry evidence IDs only, never content: %q", text)
	}
	if len(text) > maxEngagementStageContextChars {
		t.Fatalf("message exceeds the %d char budget: %d", maxEngagementStageContextChars, len(text))
	}
}

func TestBuildEngagementStageContextMessageTruncatesEvidenceList(t *testing.T) {
	cur := &database.AssessmentStage{Stage: database.StageEnumeration, Title: "Enumeration", Status: database.StageRunning}
	evidence := make([]*database.Evidence, 0, 100)
	for i := 0; i < 100; i++ {
		evidence = append(evidence, &database.Evidence{ID: "11111111-1111-1111-1111-111111111111"})
	}
	msg := buildEngagementStageContextMessage(cur, evidence)
	if len(msg) > maxEngagementStageContextChars {
		t.Fatalf("message too long: %d chars", len(msg))
	}
	if !strings.Contains(msg, database.StageEnumeration) {
		t.Fatalf("missing stage name: %q", msg)
	}
}

func TestEngagementStageMiddlewareNoEngagementIsNoop(t *testing.T) {
	db := engagementTestDB(t)
	if _, err := db.Exec(`INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "conv-no-eng", "t"); err != nil {
		t.Fatal(err)
	}
	mw := newEngagementStageMiddleware(db, "conv-no-eng")
	state := &adk.TypedChatModelAgentState[*schema.AgenticMessage]{}
	_, state, err := mw.BeforeModelRewriteState(context.Background(), state, &adk.TypedModelContext[*schema.AgenticMessage]{})
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Messages) != 0 {
		t.Fatalf("expected no injected message for a conversation without an engagement, got %d", len(state.Messages))
	}
}

func TestNewEngagementToolEvidenceRecorderStoresEvidenceAndAppendsLine(t *testing.T) {
	db := engagementTestDB(t)
	e, convID := createEngagementWithConversation(t, db)
	appCfg := &config.Config{}
	appCfg.Database.Path = filepath.Join(t.TempDir(), "conversations.db")
	mw := &config.MultiAgentEinoMiddlewareConfig{}

	recorder := newEngagementToolEvidenceRecorder(db, appCfg, mw, convID, zap.NewNop())
	if recorder == nil {
		t.Fatal("expected a non-nil recorder")
	}
	out := recorder(context.Background(), "nmap", "exec-1", "scan output body")
	if !strings.HasPrefix(out, "scan output body\n[evidence: ") {
		t.Fatalf("expected an evidence line appended: %q", out)
	}
	list, err := db.ListEvidence(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one evidence row, got %d", len(list))
	}
	if list[0].Kind != database.EvidenceToolOutput || list[0].SourceTool != "nmap" || list[0].Title != "nmap" {
		t.Fatalf("unexpected evidence row: %+v", list[0])
	}
	if list[0].SHA256 == "" || list[0].SizeBytes == 0 {
		t.Fatalf("expected a populated hash/size: %+v", list[0])
	}
	content, err := (&database.EvidenceStore{Root: evidenceRootFromDBPath(appCfg.Database.Path)}).Read(list[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "scan output body" {
		t.Fatalf("stored content mismatch: %q", content)
	}
}

func TestNewEngagementToolEvidenceRecorderTruncatesOversizedResult(t *testing.T) {
	db := engagementTestDB(t)
	e, convID := createEngagementWithConversation(t, db)
	appCfg := &config.Config{}
	appCfg.Database.Path = filepath.Join(t.TempDir(), "conversations.db")
	mw := &config.MultiAgentEinoMiddlewareConfig{}
	recorder := newEngagementToolEvidenceRecorder(db, appCfg, mw, convID, zap.NewNop())

	big := strings.Repeat("a", maxEngagementToolEvidenceBytes+1024)
	_ = recorder(context.Background(), "dirb", "", big)
	list, err := db.ListEvidence(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one evidence row, got %d", len(list))
	}
	if !strings.Contains(list[0].Title, "truncated") {
		t.Fatalf("expected the title to note truncation: %q", list[0].Title)
	}
	if list[0].SizeBytes != maxEngagementToolEvidenceBytes {
		t.Fatalf("expected the stored size to be capped at %d, got %d", maxEngagementToolEvidenceBytes, list[0].SizeBytes)
	}
}

func TestNewEngagementToolEvidenceRecorderDisabledByFlag(t *testing.T) {
	db := engagementTestDB(t)
	_, convID := createEngagementWithConversation(t, db)
	appCfg := &config.Config{}
	appCfg.Database.Path = filepath.Join(t.TempDir(), "conversations.db")
	off := false
	mw := &config.MultiAgentEinoMiddlewareConfig{EngagementAutoStages: &off}
	if recorder := newEngagementToolEvidenceRecorder(db, appCfg, mw, convID, zap.NewNop()); recorder != nil {
		t.Fatal("expected a nil recorder when the flag is off")
	}
}

func TestNewEngagementToolEvidenceRecorderNoEngagementIsNoop(t *testing.T) {
	db := engagementTestDB(t)
	if _, err := db.Exec(`INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "conv-no-eng", "t"); err != nil {
		t.Fatal(err)
	}
	appCfg := &config.Config{}
	appCfg.Database.Path = filepath.Join(t.TempDir(), "conversations.db")
	mw := &config.MultiAgentEinoMiddlewareConfig{}
	recorder := newEngagementToolEvidenceRecorder(db, appCfg, mw, "conv-no-eng", zap.NewNop())
	if recorder == nil {
		t.Fatal("recorder should exist (flag is on); it must no-op per call instead")
	}
	out := recorder(context.Background(), "nmap", "", "body")
	if out != "body" {
		t.Fatalf("expected content unchanged for a conversation without an engagement, got %q", out)
	}
}

func TestToolEvidenceRecorderSetsProvenance(t *testing.T) {
	db := engagementTestDB(t)
	e, convID := createEngagementWithConversation(t, db)
	appCfg := &config.Config{}
	appCfg.Database.Path = filepath.Join(t.TempDir(), "conversations.db")
	recorder := newEngagementToolEvidenceRecorder(db, appCfg, &config.MultiAgentEinoMiddlewareConfig{}, convID, zap.NewNop())
	_ = recorder(context.Background(), "nmap", "exec-42", "with id")
	_ = recorder(context.Background(), "nmap", "", "without id")
	list, err := db.ListEvidence(e.ID)
	if err != nil || len(list) != 2 {
		t.Fatal(err, len(list))
	}
	stages, _ := db.ListAssessmentStages(e.ID)
	cur := database.CurrentStage(stages).Stage
	for _, ev := range list {
		if ev.Origin != database.EvidenceOriginTool || ev.Stage != cur {
			t.Fatalf("provenance: %+v (current stage %s)", ev, cur)
		}
	}
	ids := map[string]bool{list[0].ToolExecutionID: true, list[1].ToolExecutionID: true}
	if !ids["exec-42"] || !ids[""] {
		t.Fatalf("execution ids: %+v", ids)
	}
}
