package handler

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"veritysec/internal/agent"
	"veritysec/internal/agentfinalizer"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/multiagent"

	"go.uber.org/zap"
)

func TestShouldNudgeForEngagementStage(t *testing.T) {
	pending := &database.AssessmentStage{Status: database.StagePending}
	running := &database.AssessmentStage{Status: database.StageRunning}
	done := &database.AssessmentStage{Status: database.StageCompleted}

	cases := []struct {
		name     string
		decision agentfinalizer.Decision
		cur      *database.AssessmentStage
		want     bool
	}{
		{"finalizable + pending", agentfinalizer.Decision{Finalizable: true}, pending, true},
		{"finalizable + running", agentfinalizer.Decision{Finalizable: true}, running, true},
		{"finalizable + done", agentfinalizer.Decision{Finalizable: true}, done, false},
		{"not finalizable", agentfinalizer.Decision{Finalizable: false}, pending, false},
		{"nil stage", agentfinalizer.Decision{Finalizable: true}, nil, false},
	}
	for _, c := range cases {
		if got := shouldNudgeForEngagementStage(c.decision, c.cur); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func engagementGateTestHandler(t *testing.T) (*AgentHandler, *database.DB) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "gate.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &AgentHandler{db: db, logger: zap.NewNop()}
	return h, db
}

func engagementGateFixture(t *testing.T, db *database.DB) (*database.Engagement, string) {
	t.Helper()
	e, err := db.CreateEngagement(&database.Engagement{
		Name:              "e1",
		AuthorizationNote: "SOW-1",
		ScopeJSON:         []byte(`{"included":["acme.example"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "conv-gate", "t"); err != nil {
		t.Fatal(err)
	}
	if err := db.AttachConversationToEngagement(e.ID, "conv-gate"); err != nil {
		t.Fatal(err)
	}
	return e, "conv-gate"
}

func engagementGateResult() *multiagent.RunResult {
	return &multiagent.RunResult{
		LastAgentTraceInput:  `[{"role":"user","content":"hello"}]`,
		LastAgentTraceOutput: "ok",
	}
}

// TestEngagementStageNudgeLimitThenAnnotates drives the gate exactly as the handler loops do: it
// must fire for the first engagementStageNudgeMaxAttempts calls, then stop and set the stage to
// blocked with a note.
func TestEngagementStageNudgeLimitThenAnnotates(t *testing.T) {
	h, db := engagementGateTestHandler(t)
	e, convID := engagementGateFixture(t, db)
	mw := &config.MultiAgentEinoMiddlewareConfig{}
	decision := agentfinalizer.Decision{Finalizable: true}
	result := engagementGateResult()

	var attempt int
	var curHistory []agent.ChatMessage
	curFinalMessage := ""

	for i := 1; i <= engagementStageNudgeMaxAttempts; i++ {
		ok := h.tryAutoContinueForEngagementStage(context.Background(), mw, convID, result, decision, &attempt, &curHistory, &curFinalMessage, nil)
		if !ok {
			t.Fatalf("attempt %d: expected the gate to continue the run", i)
		}
		if attempt != i {
			t.Fatalf("attempt %d: counter is %d", i, attempt)
		}
		if curFinalMessage == "" {
			t.Fatalf("attempt %d: expected a nudge message", i)
		}
	}

	// The stage must still be pending: nothing was completed or skipped by the gate itself.
	stages, err := db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].Status != database.StagePending {
		t.Fatalf("gate must never transition the stage, got %+v", stages[0])
	}

	// One more attempt: the limit is reached, so the run is allowed to end and the stage gets an
	// operational note instead of a status change.
	ok := h.tryAutoContinueForEngagementStage(context.Background(), mw, convID, result, decision, &attempt, &curHistory, &curFinalMessage, nil)
	if ok {
		t.Fatal("expected the gate to stop nudging after the limit")
	}
	stages, err = db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].Status != database.StageBlocked || stages[0].Reason != "nudge limit reached; stage not recorded" {
		t.Fatalf("exhausted gate without tool evidence must block the stage, got %+v", stages[0])
	}
	if stages[0].Note != engagementStageNudgeNote {
		t.Fatalf("expected the note %q, got %+v", engagementStageNudgeNote, stages[0])
	}
	if stages[0].InitiatedBy != "system" {
		t.Fatalf("expected initiated_by system, got %+v", stages[0])
	}
}

func TestEngagementStageGateDisabledByFlag(t *testing.T) {
	h, db := engagementGateTestHandler(t)
	e, convID := engagementGateFixture(t, db)
	off := false
	mw := &config.MultiAgentEinoMiddlewareConfig{EngagementAutoStages: &off}
	decision := agentfinalizer.Decision{Finalizable: true}
	result := engagementGateResult()

	var attempt int
	var curHistory []agent.ChatMessage
	curFinalMessage := ""
	if ok := h.tryAutoContinueForEngagementStage(context.Background(), mw, convID, result, decision, &attempt, &curHistory, &curFinalMessage, nil); ok {
		t.Fatal("expected no-op when the flag is off")
	}
	if attempt != 0 || curFinalMessage != "" {
		t.Fatalf("flag off must change nothing: attempt=%d curFinalMessage=%q", attempt, curFinalMessage)
	}
	stages, err := db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].Status != database.StagePending || stages[0].Note != "" {
		t.Fatalf("flag off must not touch the stage: %+v", stages[0])
	}
}

func TestEngagementStageGateNoEngagementIsNoop(t *testing.T) {
	h, db := engagementGateTestHandler(t)
	if _, err := db.Exec(`INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, "conv-no-eng", "t"); err != nil {
		t.Fatal(err)
	}
	mw := &config.MultiAgentEinoMiddlewareConfig{}
	decision := agentfinalizer.Decision{Finalizable: true}
	result := engagementGateResult()

	var attempt int
	var curHistory []agent.ChatMessage
	curFinalMessage := ""
	if ok := h.tryAutoContinueForEngagementStage(context.Background(), mw, "conv-no-eng", result, decision, &attempt, &curHistory, &curFinalMessage, nil); ok {
		t.Fatal("expected no-op for a conversation without an engagement")
	}
	if attempt != 0 || curFinalMessage != "" {
		t.Fatalf("runs without an engagement must be unaffected: attempt=%d curFinalMessage=%q", attempt, curFinalMessage)
	}
}

func TestEngagementStageGateIgnoresNonFinalizableReplies(t *testing.T) {
	h, db := engagementGateTestHandler(t)
	_, convID := engagementGateFixture(t, db)
	mw := &config.MultiAgentEinoMiddlewareConfig{}
	decision := agentfinalizer.Decision{Finalizable: false}
	result := engagementGateResult()

	var attempt int
	var curHistory []agent.ChatMessage
	curFinalMessage := ""
	if ok := h.tryAutoContinueForEngagementStage(context.Background(), mw, convID, result, decision, &attempt, &curHistory, &curFinalMessage, nil); ok {
		t.Fatal("a non-finalizable reply (e.g. a tool call pending) must not be nudged")
	}
}

// With some tool evidence recorded during the stage but no completion, exhaustion asks a person to
// decide (needs_review) instead of blocking.
func TestEngagementStageNudgeLimitNeedsReviewWithToolEvidence(t *testing.T) {
	h, db := engagementGateTestHandler(t)
	e, convID := engagementGateFixture(t, db)
	ev := database.NewEvidenceRecord(e.ID)
	ev.Kind, ev.StoragePath, ev.SHA256, ev.Origin = database.EvidenceToolOutput, "x", "y", database.EvidenceOriginTool
	if err := db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	mw := &config.MultiAgentEinoMiddlewareConfig{}
	attempt := engagementStageNudgeMaxAttempts
	var curHistory []agent.ChatMessage
	curFinalMessage := ""
	if ok := h.tryAutoContinueForEngagementStage(context.Background(), mw, convID, engagementGateResult(), agentfinalizer.Decision{Finalizable: true}, &attempt, &curHistory, &curFinalMessage, nil); ok {
		t.Fatal("expected the gate to stop")
	}
	stages, _ := db.ListAssessmentStages(e.ID)
	if stages[0].Status != database.StageNeedsReview || stages[0].Reason != "nudge limit reached; stage not recorded" ||
		stages[0].Note != engagementStageNudgeNote || stages[0].InitiatedBy != "system" {
		t.Fatalf("expected needs_review, got %+v", stages[0])
	}
	// Blocked and needs_review stages are not nudged again.
	if shouldNudgeForEngagementStage(agentfinalizer.Decision{Finalizable: true}, &stages[0]) {
		t.Fatal("needs_review must not be nudged")
	}
}

// TestClassifyRunEndForEngagementStage covers task 1 and task 4: cancelled/timeout map to
// INTERRUPTED with a fixed reason, a billing/402 error maps to INTERRUPTED with exactly "billing
// or payment error", and any other error maps to FAILED.
func TestClassifyRunEndForEngagementStage(t *testing.T) {
	cases := []struct {
		name       string
		kind       string
		err        error
		wantStatus string
		wantReason string
	}{
		{"cancelled", "cancelled", nil, database.StageInterrupted, "run cancelled"},
		{"timeout", "timeout", nil, database.StageInterrupted, "run timed out"},
		{"billing 402", "", errors.New("upstream returned 402 Payment Required"), database.StageInterrupted, "billing or payment error"},
		{"insufficient balance", "", errors.New("insufficient_balance: top up your account"), database.StageInterrupted, "billing or payment error"},
		{"generic error", "", errors.New("connection reset by peer"), database.StageFailed, "connection reset by peer"},
		{"nil error, no kind", "", nil, database.StageFailed, "run ended with an error"},
	}
	for _, c := range cases {
		status, reason := classifyRunEndForEngagementStage(c.kind, c.err)
		if status != c.wantStatus || reason != c.wantReason {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, status, reason, c.wantStatus, c.wantReason)
		}
	}
}

// TestMarkEngagementStageOnRunEnd covers tasks 1 and 4 end to end: a running stage is marked
// FAILED or INTERRUPTED (billing reason exactly) when a run ends outside the normal completion
// path, a checkpoint is written, and a non-running stage (including a terminal one) is untouched.
func TestMarkEngagementStageOnRunEnd(t *testing.T) {
	h, db := engagementGateTestHandler(t)
	e, convID := engagementGateFixture(t, db)

	// AUTHORISATION is pending, not running: no-op.
	h.markEngagementStageOnRunEnd(convID, "msg-1", "", errors.New("boom"))
	stages, err := db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].Status != database.StagePending {
		t.Fatalf("must not touch a non-running stage: %+v", stages[0])
	}

	if _, err := db.TransitionAssessmentStage(e.ID, database.StageAuthorisation, database.StageTransition{Action: "start", Actor: "u"}); err != nil {
		t.Fatal(err)
	}

	// Billing error while running: INTERRUPTED with the exact reason, and a checkpoint.
	h.markEngagementStageOnRunEnd(convID, "msg-billing", "", errors.New("HTTP 402: insufficient balance"))
	stages, err = db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].Status != database.StageInterrupted || stages[0].Reason != "billing or payment error" || stages[0].InitiatedBy != "system" {
		t.Fatalf("expected interrupted/billing, got %+v", stages[0])
	}
	cps, err := db.ListRunCheckpoints("msg-billing")
	if err != nil || len(cps) != 1 || cps[0].Kind != database.CheckpointKindStageInterrupted {
		t.Fatalf("checkpoint: %+v %v", cps, err)
	}

	// Already interrupted (not running): a further call is a no-op and writes no checkpoint.
	h.markEngagementStageOnRunEnd(convID, "msg-again", "cancelled", nil)
	stages, err = db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].Status != database.StageInterrupted || stages[0].Reason != "billing or payment error" {
		t.Fatalf("non-running stage must not be re-marked: %+v", stages[0])
	}
	if cps, _ := db.ListRunCheckpoints("msg-again"); len(cps) != 0 {
		t.Fatalf("no-op must not write a checkpoint: %+v", cps)
	}

	// Restart, then a generic (non-billing, non-cancel/timeout) error: FAILED.
	if _, err := db.TransitionAssessmentStage(e.ID, database.StageAuthorisation, database.StageTransition{Action: "start", Actor: "u"}); err != nil {
		t.Fatal(err)
	}
	h.markEngagementStageOnRunEnd(convID, "msg-failed", "", errors.New("panic: nil pointer"))
	stages, err = db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].Status != database.StageFailed || stages[0].Reason != "panic: nil pointer" {
		t.Fatalf("expected failed, got %+v", stages[0])
	}
}
