package database

import (
	"errors"
	"strings"
	"testing"
)

func TestStageCompletionRefusedWhileRequiredTaskOpen(t *testing.T) {
	db, e := stageFixture(t, true)
	task, err := db.CreateStageTask(e.ID, StageAuthorisation, StageTaskInput{Title: "Confirm RoE signed", ProposedBy: StageTaskByHuman})
	if err != nil || !task.Required || task.Status != StageTaskOpen {
		t.Fatalf("create: %+v %v", task, err)
	}
	if _, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "start", Actor: "u1"}); err != nil {
		t.Fatal(err)
	}
	ev := addEvidence(t, db, e.ID)
	_, err = db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "complete", EvidenceIDs: []string{ev}, Actor: "u1"})
	if !isConflict(err) || !strings.Contains(err.Error(), "Confirm RoE signed") {
		t.Fatalf("want conflict naming open task, got %v", err)
	}
	if _, err := db.SetStageTaskStatus(task.ID, "done", "", StageTaskByModel); err != nil {
		t.Fatal(err)
	}
	if st, err := db.TransitionAssessmentStage(e.ID, StageAuthorisation, StageTransition{Action: "complete", EvidenceIDs: []string{ev}, Actor: "u1"}); err != nil || st.Status != StageCompleted {
		t.Fatalf("complete after done: %+v %v", st, err)
	}
}

func TestStageTaskOptionalAndSkipRules(t *testing.T) {
	db, e := stageFixture(t, true)
	req, _ := db.CreateStageTask(e.ID, StageReconnaissance, StageTaskInput{Title: "req", ProposedBy: StageTaskByModel})
	f := false
	opt, _ := db.CreateStageTask(e.ID, StageReconnaissance, StageTaskInput{Title: "opt", Required: &f, ProposedBy: StageTaskByModel})

	// A model cannot skip (or reopen) a required task.
	if _, err := db.SetStageTaskStatus(req.ID, "skipped", "not needed", StageTaskByModel); !isConflict(err) {
		t.Fatalf("model skip required: %v", err)
	}
	// Skip without a reason is refused, even for a human.
	var inv *ErrStageInvalid
	if _, err := db.SetStageTaskStatus(req.ID, "skipped", "  ", StageTaskByHuman); !errors.As(err, &inv) {
		t.Fatalf("skip without reason: %v", err)
	}
	// A human can skip with a reason.
	if got, err := db.SetStageTaskStatus(req.ID, "skipped", "covered elsewhere", StageTaskByHuman); err != nil || got.Status != StageTaskSkipped || got.Reason == "" {
		t.Fatalf("human skip: %+v %v", got, err)
	}
	// A model may skip an optional task with a reason.
	if _, err := db.SetStageTaskStatus(opt.ID, "skipped", "", StageTaskByModel); !errors.As(err, &inv) {
		t.Fatalf("optional skip no reason: %v", err)
	}
	if _, err := db.SetStageTaskStatus(opt.ID, "skipped", "n/a", StageTaskByModel); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListStageTasks(e.ID, StageReconnaissance)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
	if _, err := db.SetStageTaskStatus("nope", "done", "", StageTaskByHuman); !errors.Is(err, ErrStageTaskNotFound) {
		t.Fatalf("missing: %v", err)
	}
}
