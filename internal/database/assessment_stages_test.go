package database

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func stageFixture(t *testing.T, auth bool) (*DB, *Engagement) {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "s.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &Engagement{Name: "e"}
	if auth {
		e.AuthorizationNote = "SOW-1"
		e.ScopeJSON = []byte(`{"included":["acme.example"]}`)
	}
	e, err = db.CreateEngagement(e)
	if err != nil {
		t.Fatal(err)
	}
	return db, e
}

func addEvidence(t *testing.T, db *DB, engID string) string {
	t.Helper()
	ev := NewEvidenceRecord(engID)
	ev.Kind, ev.StoragePath, ev.SHA256 = EvidenceNote, "x", "y"
	if err := db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	return ev.ID
}

func isConflict(err error) bool {
	var c *ErrStageConflict
	return errors.As(err, &c)
}

func TestStagesAlwaysListAllInOrder(t *testing.T) {
	db, e := stageFixture(t, true)
	st, err := db.ListAssessmentStages(e.ID)
	if err != nil || len(st) != 8 {
		t.Fatal(err, len(st))
	}
	for i, s := range st {
		if s.Stage != AssessmentStageDefs[i].Name || s.Order != i+1 || s.Status != StagePending || s.EvidenceIDs == nil {
			t.Fatalf("stage %d: %+v", i, s)
		}
	}
	if _, err := db.ListAssessmentStages("nope"); !errors.Is(err, ErrEngagementNotFound) {
		t.Fatal(err)
	}
}

func TestStageTransitionOrderAndTerminal(t *testing.T) {
	db, e := stageFixture(t, true)
	_, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "start", Actor: "u1"})
	if !isConflict(err) || err.Error() == "" || !contains(err.Error(), StageAuthorisation) {
		t.Fatalf("out-of-order start: %v", err)
	}
	if _, err := db.TransitionAssessmentStage(e.ID, "BOGUS", StageTransition{Action: "start"}); !errors.Is(err, ErrStageUnknown) {
		t.Fatal(err)
	}
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "start", Actor: "u1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "start"}); !isConflict(err) {
		t.Fatalf("restart running: %v", err)
	}
	ev := addEvidence(t, db, e.ID)
	st, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "complete", EvidenceIDs: []string{ev, ev}, Note: "ok", Actor: "u1"})
	if err != nil || st.Status != StageCompleted || len(st.EvidenceIDs) != 1 || st.FinishedAt == nil || st.InitiatedBy != "u1" {
		t.Fatalf("complete: %+v %v", st, err)
	}
	for _, a := range []StageTransition{{Action: "start"}, {Action: "complete", EvidenceIDs: []string{ev}}, {Action: "skip", Reason: "r"}} {
		if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, a); !isConflict(err) {
			t.Fatalf("terminal stage changed by %s: %v", a.Action, err)
		}
	}
	if _, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "start", Actor: "agent"}); err != nil {
		t.Fatal(err)
	}
	// ASSET_DISCOVERY cannot start while RECONNAISSANCE is running
	if _, err := db.TransitionAssessmentStage(e.ID, StageAssetDiscovery, StageTransition{Action: "start"}); !isConflict(err) {
		t.Fatalf("start after running: %v", err)
	}
	// skipping the running stage unlocks the next one
	if _, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "skip", Reason: "out of scope"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionAssessmentStage(e.ID, StageAssetDiscovery, StageTransition{Action: "start"}); err != nil {
		t.Fatal(err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestStageSkipNeedsReason(t *testing.T) {
	db, e := stageFixture(t, true)
	for _, r := range []string{"", "   "} {
		_, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "skip", Reason: r})
		var inv *ErrStageInvalid
		if !errors.As(err, &inv) {
			t.Fatalf("reason %q: %v", r, err)
		}
	}
	st, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "skip", Reason: "pre-approved", Actor: "u1"})
	if err != nil || st.Status != StageSkipped || st.Reason != "pre-approved" {
		t.Fatal(st, err)
	}
}

func TestStageCompleteNeedsValidEngagementEvidence(t *testing.T) {
	db, e := stageFixture(t, true)
	other, _ := db.CreateEngagement(&Engagement{Name: "other"})
	foreign := addEvidence(t, db, other.ID)
	mine := addEvidence(t, db, e.ID)
	for _, ids := range [][]string{nil, {}, {"missing"}, {foreign}, {mine, foreign}} {
		if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "complete", EvidenceIDs: ids}); !isConflict(err) {
			t.Fatalf("ids %v accepted: %v", ids, err)
		}
	}
	// pending complete starts it; nothing was stored by the failed attempts
	st, _ := db.ListAssessmentStages(e.ID)
	if st[0].Status != StagePending {
		t.Fatal("failed completion changed state")
	}
	got, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "complete", EvidenceIDs: []string{mine}, Actor: "u1"})
	if err != nil || got.StartedAt == nil {
		t.Fatal(got, err)
	}
}

func TestCurrentStage(t *testing.T) {
	db, e := stageFixture(t, true)
	st, _ := db.ListAssessmentStages(e.ID)
	cur := CurrentStage(st)
	if cur == nil || cur.Stage != StageAuthorisation {
		t.Fatalf("expected AUTHORISATION current, got %+v", cur)
	}
	ev := addEvidence(t, db, e.ID)
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "complete", EvidenceIDs: []string{ev}, Actor: "u1"}); err != nil {
		t.Fatal(err)
	}
	st, _ = db.ListAssessmentStages(e.ID)
	cur = CurrentStage(st)
	if cur == nil || cur.Stage != StageReconnaissance {
		t.Fatalf("expected RECONNAISSANCE current, got %+v", cur)
	}
	// Skip every remaining stage; CurrentStage should then report nil.
	for _, s := range AssessmentStageDefs[1:] {
		if _, err := db.TransitionAssessmentStage(e.ID, s.Name, StageTransition{Action: "skip", Reason: "n/a"}); err != nil {
			t.Fatalf("skip %s: %v", s.Name, err)
		}
	}
	st, _ = db.ListAssessmentStages(e.ID)
	if cur := CurrentStage(st); cur != nil {
		t.Fatalf("expected nil once every stage is terminal, got %+v", cur)
	}
}

func TestAnnotateAssessmentStageNote(t *testing.T) {
	db, e := stageFixture(t, true)
	// Annotating a never-started (pending, no row) stage inserts a row without changing status.
	if err := db.AnnotateAssessmentStageNote(e.ID, StageAuthorisation, "run ended before the stage was recorded", "system"); err != nil {
		t.Fatal(err)
	}
	st, err := db.ListAssessmentStages(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st[0].Status != StagePending || st[0].Note != "run ended before the stage was recorded" || st[0].InitiatedBy != "system" {
		t.Fatalf("annotate on pending: %+v", st[0])
	}
	if len(st[0].EvidenceIDs) != 0 {
		t.Fatalf("annotate must not invent evidence: %+v", st[0].EvidenceIDs)
	}

	// Start it, then annotate again: status/started_at stay, only note/initiated_by move.
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "start", Actor: "u1"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AnnotateAssessmentStageNote(e.ID, StageAuthorisation, "second note", "system"); err != nil {
		t.Fatal(err)
	}
	st, _ = db.ListAssessmentStages(e.ID)
	if st[0].Status != StageRunning || st[0].Note != "second note" || st[0].InitiatedBy != "system" || st[0].StartedAt == nil {
		t.Fatalf("annotate on running: %+v", st[0])
	}

	// Completing the stage, then annotating again, must not change the terminal stage.
	ev := addEvidence(t, db, e.ID)
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "complete", EvidenceIDs: []string{ev}, Actor: "u1"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AnnotateAssessmentStageNote(e.ID, StageAuthorisation, "should not land", "system"); err != nil {
		t.Fatal(err)
	}
	st, _ = db.ListAssessmentStages(e.ID)
	if st[0].Status != StageCompleted || st[0].Note == "should not land" {
		t.Fatalf("annotate must not touch a terminal stage: %+v", st[0])
	}

	if err := db.AnnotateAssessmentStageNote("nope", StageAuthorisation, "x", "system"); !errors.Is(err, ErrEngagementNotFound) {
		t.Fatal(err)
	}
	if err := db.AnnotateAssessmentStageNote(e.ID, "BOGUS", "x", "system"); !errors.Is(err, ErrStageUnknown) {
		t.Fatal(err)
	}
}

func TestConversationEngagementID(t *testing.T) {
	db, e := stageFixture(t, true)
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO conversations (id, title, created_at, updated_at) VALUES (?, ?, ?, ?)`, "conv-1", "t", now, now); err != nil {
		t.Fatal(err)
	}
	id, err := db.ConversationEngagementID("conv-1")
	if err != nil || id != "" {
		t.Fatalf("expected no engagement, got %q err=%v", id, err)
	}
	if err := db.AttachConversationToEngagement(e.ID, "conv-1"); err != nil {
		t.Fatal(err)
	}
	id, err = db.ConversationEngagementID("conv-1")
	if err != nil || id != e.ID {
		t.Fatalf("expected %q, got %q err=%v", e.ID, id, err)
	}
	if id, err := db.ConversationEngagementID("missing-conv"); err != nil || id != "" {
		t.Fatalf("missing conversation: %q %v", id, err)
	}
}

func TestAuthorisationNeedsNoteAndScope(t *testing.T) {
	db, e := stageFixture(t, false)
	ev := addEvidence(t, db, e.ID)
	in := StageTransition{Action: "complete", EvidenceIDs: []string{ev}}
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, in); !isConflict(err) {
		t.Fatalf("no note/scope: %v", err)
	}
	e.AuthorizationNote = "SOW"
	if _, err := db.UpdateEngagement(e.ID, e); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, in); !isConflict(err) {
		t.Fatalf("no scope: %v", err)
	}
	e.ScopeJSON = []byte(`{"included":["  "]}`)
	db.UpdateEngagement(e.ID, e)
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, in); !isConflict(err) {
		t.Fatalf("blank scope: %v", err)
	}
	e.ScopeJSON = []byte(`{"included":["a.example"]}`)
	db.UpdateEngagement(e.ID, e)
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, in); err != nil {
		t.Fatal(err)
	}
}

// addEvidenceAs inserts evidence with explicit provenance; stage "" means the engagement's current stage.
func addEvidenceAs(t *testing.T, db *DB, engID, origin, stage string) string {
	t.Helper()
	ev := NewEvidenceRecord(engID)
	ev.Kind, ev.StoragePath, ev.SHA256 = EvidenceToolOutput, "x", "y"
	ev.Origin, ev.Stage = origin, stage
	if err := db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	return ev.ID
}

// passAuthorisation completes AUTHORISATION (no tool evidence needed) and starts RECONNAISSANCE.
func passAuthorisation(t *testing.T, db *DB, e *Engagement) {
	t.Helper()
	ev := addEvidence(t, db, e.ID) // manual note: enough for AUTHORISATION only
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "complete", EvidenceIDs: []string{ev}, Actor: "u"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "start", Actor: "u"}); err != nil {
		t.Fatal(err)
	}
}

func TestStageCompletionNeedsToolEvidenceFromThisStage(t *testing.T) {
	db, e := stageFixture(t, true)
	passAuthorisation(t, db, e)
	complete := func(ids ...string) error {
		_, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "complete", EvidenceIDs: ids, Actor: "u"})
		return err
	}
	manual := addEvidenceAs(t, db, e.ID, EvidenceOriginManual, "")
	otherStage := addEvidenceAs(t, db, e.ID, EvidenceOriginTool, StageEnumeration)
	other, _ := db.CreateEngagement(&Engagement{Name: "other"})
	foreign := addEvidenceAs(t, db, other.ID, EvidenceOriginTool, StageReconnaissance)
	for name, ids := range map[string][]string{"manual": {manual}, "other stage": {otherStage}, "none": nil, "manual+other stage": {manual, otherStage}} {
		err := complete(ids...)
		if !isConflict(err) || err.Error() != "cite at least one tool evidence row recorded during this stage" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := complete(foreign); !isConflict(err) {
		t.Fatalf("other engagement's evidence: %v", err)
	}
	tool := addEvidenceAs(t, db, e.ID, EvidenceOriginTool, "") // stage stamped = current = RECONNAISSANCE
	got, err := db.GetEvidence(tool)
	if err != nil || got.Stage != StageReconnaissance || got.Origin != EvidenceOriginTool {
		t.Fatalf("provenance not stored: %+v %v", got, err)
	}
	if err := complete(manual, tool); err != nil {
		t.Fatalf("tool evidence from this engagement and stage must complete: %v", err)
	}
}

func TestEvidenceToolExecutionIDStoredAndNullable(t *testing.T) {
	db, e := stageFixture(t, true)
	ev := NewEvidenceRecord(e.ID)
	ev.Kind, ev.StoragePath, ev.SHA256, ev.Origin, ev.ToolExecutionID = EvidenceToolOutput, "x", "y", EvidenceOriginTool, "exec-9"
	if err := db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetEvidence(ev.ID)
	if got.ToolExecutionID != "exec-9" {
		t.Fatalf("%+v", got)
	}
	var n int
	id2 := addEvidenceAs(t, db, e.ID, EvidenceOriginTool, "")
	if err := db.QueryRow(`SELECT COUNT(*) FROM evidence WHERE id = ? AND tool_execution_id IS NULL`, id2).Scan(&n); err != nil || n != 1 {
		t.Fatalf("expected NULL execution id: %d %v", n, err)
	}
	bad := NewEvidenceRecord(e.ID)
	bad.Kind, bad.Origin = EvidenceNote, "bogus"
	if err := db.InsertEvidence(bad); err == nil {
		t.Fatal("invalid origin accepted")
	}
}

func TestStageBlockedNeedsReviewTransitions(t *testing.T) {
	db, e := stageFixture(t, true)
	passAuthorisation(t, db, e)
	status := func() AssessmentStage {
		st, _ := db.ListAssessmentStages(e.ID)
		return st[1]
	}
	// No tool evidence: blocked, with the reason and the note kept.
	got, err := db.MarkAssessmentStageStalled(e.ID, StageReconnaissance, "run ended before the stage was recorded", "system")
	if err != nil || got != StageBlocked {
		t.Fatal(got, err)
	}
	s := status()
	if s.Status != StageBlocked || s.Reason != StageNudgeLimitReason || s.InitiatedBy != "system" || s.Note != "run ended before the stage was recorded" || s.StartedAt == nil {
		t.Fatalf("%+v", s)
	}
	// blocked -> running by start
	if st, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "start", Actor: "u"}); err != nil || st.Status != StageRunning || st.Reason != "" {
		t.Fatal(st, err)
	}
	// Some tool evidence but no completion: needs_review.
	addEvidenceAs(t, db, e.ID, EvidenceOriginTool, "")
	addEvidenceAs(t, db, e.ID, EvidenceOriginManual, "")
	got, err = db.MarkAssessmentStageStalled(e.ID, StageReconnaissance, "n", "system")
	if err != nil || got != StageNeedsReview || status().Status != StageNeedsReview {
		t.Fatal(got, err, status())
	}
	if st, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "start", Actor: "u"}); err != nil || st.Status != StageRunning {
		t.Fatal(st, err)
	}
	// Tool evidence of another stage alone still gives blocked.
	db2, e2 := stageFixture(t, true)
	passAuthorisation(t, db2, e2)
	addEvidenceAs(t, db2, e2.ID, EvidenceOriginTool, StageEnumeration)
	if got, _ := db2.MarkAssessmentStageStalled(e2.ID, StageReconnaissance, "n", "system"); got != StageBlocked {
		t.Fatalf("other-stage tool evidence must not count: %s", got)
	}
	// blocked/needs_review can be skipped; needs_review can be completed with tool evidence.
	if _, err := db2.TransitionAssessmentStage(e2.ID, StageReconnaissance, StageTransition{Action: "skip", Reason: "r", Actor: "u"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MarkAssessmentStageStalled(e.ID, StageReconnaissance, "n", "system"); err != nil {
		t.Fatal(err)
	}
	tool := addEvidenceAs(t, db, e.ID, EvidenceOriginTool, StageReconnaissance)
	if st, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "complete", EvidenceIDs: []string{tool}, Actor: "u"}); err != nil || st.Status != StageCompleted || st.Reason != "" {
		t.Fatal(st, err)
	}
	// Terminal stages are immutable, including against the gate.
	if got, err := db.MarkAssessmentStageStalled(e.ID, StageReconnaissance, "n", "system"); err != nil || got != StageCompleted || status().Status != StageCompleted {
		t.Fatal(got, err)
	}
	if got, _ := db2.MarkAssessmentStageStalled(e2.ID, StageReconnaissance, "n", "system"); got != StageSkipped {
		t.Fatal(got)
	}
	for _, a := range []string{"start", "skip"} {
		if _, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: a, Reason: "r"}); !isConflict(err) {
			t.Fatalf("completed stage changed by %s: %v", a, err)
		}
		if _, err := db2.TransitionAssessmentStage(e2.ID, StageReconnaissance, StageTransition{Action: a, Reason: "r"}); !isConflict(err) {
			t.Fatalf("skipped stage changed by %s: %v", a, err)
		}
	}
}

// TestStageFailedInterruptedTransitions covers the FAILED/INTERRUPTED recovery states: they only
// apply to a running stage, a checkpoint is written with each mark, start restores running and
// folds the prior reason into the note as history, complete/skip apply as for blocked, and
// COMPLETED/SKIPPED stay immutable against them.
func TestStageFailedInterruptedTransitions(t *testing.T) {
	db, e := stageFixture(t, true)
	passAuthorisation(t, db, e)
	status := func() AssessmentStage {
		st, _ := db.ListAssessmentStages(e.ID)
		return st[1]
	}

	// passAuthorisation already started RECONNAISSANCE, so it is running here.
	if status().Status != StageRunning {
		t.Fatalf("expected running, got %+v", status())
	}

	// Running -> failed, with checkpoint.
	got, err := db.MarkAssessmentStageFailed(e.ID, StageReconnaissance, "boom", "run ended before the stage finished", "system", "conv-1", "msg-1")
	if err != nil || got != StageFailed {
		t.Fatal(got, err)
	}
	s := status()
	if s.Status != StageFailed || s.Reason != "boom" || s.InitiatedBy != "system" {
		t.Fatalf("%+v", s)
	}
	cps, err := db.ListRunCheckpoints("msg-1")
	if err != nil || len(cps) != 1 || cps[0].Kind != CheckpointKindStageFailed || cps[0].Stage != StageReconnaissance || cps[0].ConversationID != "conv-1" {
		t.Fatalf("checkpoint: %+v %v", cps, err)
	}

	// Terminal (not running): marking again is a no-op.
	if got, err := db.MarkAssessmentStageFailed(e.ID, StageReconnaissance, "boom2", "n", "system", "conv-1", "msg-2"); err != nil || got != StageFailed {
		t.Fatalf("mark failed again: %v %v", got, err)
	}
	if cps, _ := db.ListRunCheckpoints("msg-2"); len(cps) != 0 {
		t.Fatalf("no-op mark must not write a checkpoint: %+v", cps)
	}

	// start restarts it: back to running, prior reason folded into the note as history.
	st, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "start", Actor: "u"})
	if err != nil || st.Status != StageRunning || st.Reason != "" {
		t.Fatalf("restart failed stage: %+v %v", st, err)
	}
	if !contains(st.Note, "previous (failed): boom") {
		t.Fatalf("history not kept: %q", st.Note)
	}

	// Running -> interrupted (billing), with checkpoint.
	got, err = db.MarkAssessmentStageInterrupted(e.ID, StageReconnaissance, "billing or payment error", "run ended before the stage finished", "system", "conv-2", "msg-3")
	if err != nil || got != StageInterrupted {
		t.Fatal(got, err)
	}
	s = status()
	if s.Status != StageInterrupted || s.Reason != "billing or payment error" {
		t.Fatalf("%+v", s)
	}
	cps, err = db.ListRunCheckpoints("msg-3")
	if err != nil || len(cps) != 1 || cps[0].Kind != CheckpointKindStageInterrupted {
		t.Fatalf("checkpoint: %+v %v", cps, err)
	}

	// complete/skip apply to interrupted exactly as they do to blocked.
	tool := addEvidenceAs(t, db, e.ID, EvidenceOriginTool, StageReconnaissance)
	if st, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "complete", EvidenceIDs: []string{tool}, Actor: "u"}); err != nil || st.Status != StageCompleted {
		t.Fatalf("complete interrupted stage: %+v %v", st, err)
	}

	// Terminal stages are immutable, including against failed/interrupted marks and start/skip.
	if got, err := db.MarkAssessmentStageFailed(e.ID, StageReconnaissance, "n", "n", "system", "", ""); err != nil || got != StageCompleted {
		t.Fatalf("mark on completed stage: %v %v", got, err)
	}
	if got, err := db.MarkAssessmentStageInterrupted(e.ID, StageReconnaissance, "n", "n", "system", "", ""); err != nil || got != StageCompleted {
		t.Fatalf("mark on completed stage: %v %v", got, err)
	}
	for _, a := range []string{"start", "skip"} {
		if _, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: a, Reason: "r"}); !isConflict(err) {
			t.Fatalf("completed stage changed by %s: %v", a, err)
		}
	}

	// A skipped stage is also immutable against failed/interrupted marks.
	db2, e2 := stageFixture(t, true)
	passAuthorisation(t, db2, e2) // also starts RECONNAISSANCE
	if _, err := db2.TransitionAssessmentStage(e2.ID, StageReconnaissance, StageTransition{Action: "skip", Reason: "r", Actor: "u"}); err != nil {
		t.Fatal(err)
	}
	if got, err := db2.MarkAssessmentStageFailed(e2.ID, StageReconnaissance, "n", "n", "system", "", ""); err != nil || got != StageSkipped {
		t.Fatalf("mark on skipped stage: %v %v", got, err)
	}

	// Unknown engagement/stage.
	if _, err := db.MarkAssessmentStageFailed("nope", StageReconnaissance, "n", "n", "system", "", ""); !errors.Is(err, ErrEngagementNotFound) {
		t.Fatal(err)
	}
	if _, err := db.MarkAssessmentStageInterrupted(e.ID, "BOGUS", "n", "n", "system", "", ""); !errors.Is(err, ErrStageUnknown) {
		t.Fatal(err)
	}
}

// TestStageStartAndCompleteWriteCheckpoints covers task 2: a checkpoint is written when a stage
// starts and when it completes, holding IDs only.
func TestStageStartAndCompleteWriteCheckpoints(t *testing.T) {
	db, e := stageFixture(t, true)
	st, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{
		Action: "start", Actor: "u1", ConversationID: "conv-a", MessageID: "msg-a",
	})
	if err != nil || st.Status != StageRunning {
		t.Fatal(st, err)
	}
	cps, err := db.ListRunCheckpoints("msg-a")
	if err != nil || len(cps) != 1 || cps[0].Kind != CheckpointKindStageStart || cps[0].Stage != StageAuthorisation {
		t.Fatalf("start checkpoint: %+v %v", cps, err)
	}
	var data map[string]interface{}
	if err := jsonUnmarshalForTest(t, cps[0].DataJSON, &data); err != nil || data["stage"] != StageAuthorisation {
		t.Fatalf("start checkpoint data: %v %v", data, err)
	}

	ev := addEvidence(t, db, e.ID)
	st, err = db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{
		Action: "complete", EvidenceIDs: []string{ev}, Actor: "u1", ConversationID: "conv-a", MessageID: "msg-a",
	})
	if err != nil || st.Status != StageCompleted {
		t.Fatal(st, err)
	}
	cps, err = db.ListRunCheckpoints("msg-a")
	if err != nil || len(cps) != 2 {
		t.Fatalf("expected start+complete checkpoints: %+v %v", cps, err)
	}
	if cps[1].Kind != CheckpointKindStageComplete {
		t.Fatalf("second checkpoint kind: %+v", cps[1])
	}
	if err := jsonUnmarshalForTest(t, cps[1].DataJSON, &data); err != nil {
		t.Fatal(err)
	}
	ids, _ := data["evidence_ids"].([]interface{})
	if len(ids) != 1 || ids[0] != ev {
		t.Fatalf("complete checkpoint data: %v", data)
	}
}

func jsonUnmarshalForTest(t *testing.T, s string, v interface{}) error {
	t.Helper()
	return json.Unmarshal([]byte(s), v)
}
