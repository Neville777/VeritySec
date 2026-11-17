package database

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestFindingVerificationRoundTripAndLatest(t *testing.T) {
	db, err := NewDB(filepath.Join(t.TempDir(), "fv.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.LatestFindingVerification("f1"); !errors.Is(err, ErrVerificationNotFound) {
		t.Fatalf("empty = %v", err)
	}
	t0 := time.Now().UTC()
	for i, st := range []string{"INCONCLUSIVE", "NEEDS_MANUAL_REVIEW"} {
		if err := db.InsertFindingVerification(&FindingVerification{VulnerabilityID: "f1", Status: st, Reasons: []string{"r" + st},
			PrimaryVerdicts: []byte(`[{"claim_id":"c"}]`), PrimaryModel: "m", ChallengerModel: "m", CreatedAt: t0.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.LatestFindingVerification("f1")
	if err != nil || got.Status != "NEEDS_MANUAL_REVIEW" || got.Reasons[0] != "rNEEDS_MANUAL_REVIEW" || string(got.PrimaryVerdicts) != `[{"claim_id":"c"}]` || string(got.ChallengerVerdicts) != "[]" {
		t.Fatalf("%+v %v", got, err)
	}
}
