package database

import "testing"

func completeRecon(t *testing.T, db *DB, e *Engagement) {
	t.Helper()
	passAuthorisation(t, db, e)
	ev := addEvidenceAs(t, db, e.ID, EvidenceOriginTool, StageReconnaissance)
	if _, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "complete", EvidenceIDs: []string{ev}, Actor: "u"}); err != nil {
		t.Fatal(err)
	}
}

func stageOf(t *testing.T, db *DB, id, stage string) AssessmentStage {
	t.Helper()
	sts, err := db.ListAssessmentStages(id)
	if err != nil {
		t.Fatal(err)
	}
	return sts[StageIndex(stage)]
}

func reviewCheckpoints(t *testing.T, db *DB, id string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM run_checkpoints WHERE engagement_id = ? AND kind = ?`, id, CheckpointKindStageReview).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNewAssetSendsCompletedStageToReview(t *testing.T) {
	db, e := stageFixture(t, true)
	completeRecon(t, db, e)
	res, err := db.UpsertAssets([]*Asset{{Host: "new.acme.example"}}, "")
	if err != nil || res.Created != 1 {
		t.Fatal(res, err)
	}
	a := &Asset{Host: "other.acme.example"}
	if _, err := db.UpsertAssets([]*Asset{a}, ""); err != nil {
		t.Fatal(err)
	}
	if err := db.ReviewStageForNewItem(e.ID, StageReconnaissance, "asset", a.ID); err != nil {
		t.Fatal(err)
	}
	st := stageOf(t, db, e.ID, StageReconnaissance)
	if st.Status != StageNeedsReview || st.Reason == "" || !contains(st.Reason, a.ID) {
		t.Fatalf("stage: %+v", st)
	}
	if reviewCheckpoints(t, db, e.ID) != 1 {
		t.Fatal("want one stage_review_triggered checkpoint")
	}
}

func TestReviewLeavesOtherStatusesAlone(t *testing.T) {
	db, e := stageFixture(t, true)
	passAuthorisation(t, db, e) // AUTHORISATION completed, RECONNAISSANCE running
	// running: untouched
	if err := db.ReviewStageForNewItem(e.ID, "", "asset", "a1"); err != nil {
		t.Fatal(err)
	}
	if st := stageOf(t, db, e.ID, StageReconnaissance); st.Status != StageRunning || st.Reason != "" {
		t.Fatalf("running changed: %+v", st)
	}
	// pending: untouched
	if ok, err := db.ReviewStageForDiscovery(e.ID, StageEnumeration, "x"); err != nil || ok {
		t.Fatal(ok, err)
	}
	// skipped: untouched
	if _, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "skip", Reason: "n/a", Actor: "u"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.ReviewStageForDiscovery(e.ID, StageReconnaissance, "x"); err != nil || ok {
		t.Fatal(ok, err)
	}
	if st := stageOf(t, db, e.ID, StageReconnaissance); st.Status != StageSkipped || st.Reason != "n/a" {
		t.Fatalf("skipped changed: %+v", st)
	}
	if reviewCheckpoints(t, db, e.ID) != 0 {
		t.Fatal("no checkpoint expected")
	}
}

func TestToolEvidenceForCompletedStageAndFailureDoesNotFailWrite(t *testing.T) {
	db, e := stageFixture(t, true)
	completeRecon(t, db, e)
	id := addEvidenceAs(t, db, e.ID, EvidenceOriginTool, StageReconnaissance)
	if st := stageOf(t, db, e.ID, StageReconnaissance); st.Status != StageNeedsReview || !contains(st.Reason, id) {
		t.Fatalf("stage: %+v", st)
	}
	// Manual evidence does not trigger a review.
	db2, e2 := stageFixture(t, true)
	completeRecon(t, db2, e2)
	addEvidenceAs(t, db2, e2.ID, EvidenceOriginManual, StageReconnaissance)
	if st := stageOf(t, db2, e2.ID, StageReconnaissance); st.Status != StageCompleted {
		t.Fatalf("manual evidence changed stage: %+v", st)
	}
	// Marking fails (unknown stage): the evidence and asset writes still succeed.
	addEvidenceAs(t, db, e.ID, EvidenceOriginTool, "NO_SUCH_STAGE")
	a := &Asset{Host: "z.acme.example"}
	if res, err := db.UpsertAssets([]*Asset{a}, ""); err != nil || res.Created != 1 {
		t.Fatal(res, err)
	}
	if err := db.ReviewStageForNewItem(e.ID, "NO_SUCH_STAGE", "asset", a.ID); err == nil {
		t.Fatal("want marking error")
	}
	if _, err := db.GetAsset(a.ID, RBACListAccess{}); err != nil {
		t.Fatalf("asset lost: %v", err)
	}
}

func TestHumanCanCompleteNeedsReviewStageAgain(t *testing.T) {
	db, e := stageFixture(t, true)
	completeRecon(t, db, e)
	if ok, err := db.ReviewStageForDiscovery(e.ID, StageReconnaissance, "new asset a9"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	ev := addEvidenceAs(t, db, e.ID, EvidenceOriginTool, StageReconnaissance)
	st, err := db.TransitionAssessmentStage(e.ID, StageReconnaissance, StageTransition{Action: "complete", EvidenceIDs: []string{ev}, Actor: "human"})
	if err != nil || st.Status != StageCompleted || st.Reason != "" {
		t.Fatalf("recomplete: %+v %v", st, err)
	}
}
