package database

import (
	"errors"
	"testing"
)

func newClaimEvidence(t *testing.T, db *DB, engagementID string) string {
	t.Helper()
	ev := NewEvidenceRecord(engagementID)
	ev.Kind = EvidenceToolOutput
	ev.Origin = EvidenceOriginTool
	ev.StoragePath = "x/" + ev.ID
	ev.SHA256 = "abc"
	ev.SizeBytes = 1
	if err := db.InsertEvidence(ev); err != nil {
		t.Fatal(err)
	}
	return ev.ID
}

func TestClaimCreateListAndLink(t *testing.T) {
	db, v, eng := setupConfidenceTestFinding(t)
	c, err := db.CreateFindingClaim(v.ID, "  login is injectable ")
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != ClaimUnverified || c.Position != 1 || c.EngagementID != eng.ID || c.Text != "login is injectable" {
		t.Fatalf("unexpected claim %+v", c)
	}
	if _, err := db.CreateFindingClaim(v.ID, "  "); !errors.Is(err, ErrClaimText) {
		t.Fatalf("empty text err = %v", err)
	}
	c2, _ := db.CreateFindingClaim(v.ID, "second")
	if c2.Position != 2 {
		t.Fatalf("position = %d", c2.Position)
	}
	evID := newClaimEvidence(t, db, eng.ID)
	if err := db.LinkClaimEvidence(c.ID, evID); err != nil {
		t.Fatal(err)
	}
	if err := db.LinkClaimEvidence(c.ID, evID); err != nil { // idempotent
		t.Fatal(err)
	}
	list, err := db.ListFindingClaims(v.ID)
	if err != nil || len(list) != 2 || len(list[0].EvidenceIDs) != 1 || list[0].EvidenceIDs[0] != evID || len(list[1].EvidenceIDs) != 0 {
		t.Fatalf("list = %+v err=%v", list, err)
	}
	if _, err := db.CreateFindingClaim("missing", "x"); err == nil {
		t.Fatal("claim on unknown finding accepted")
	}
}

func TestClaimLinkAcrossEngagementsRefused(t *testing.T) {
	db, v, _ := setupConfidenceTestFinding(t)
	other, err := db.CreateEngagement(&Engagement{Name: "other"})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := db.CreateFindingClaim(v.ID, "x")
	if err := db.LinkClaimEvidence(c.ID, newClaimEvidence(t, db, other.ID)); err == nil {
		t.Fatal("cross-engagement evidence link accepted")
	}
	if err := db.LinkClaimEvidence(c.ID, "nope"); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("err = %v", err)
	}
	if err := db.LinkClaimEvidence("nope", "nope"); !errors.Is(err, ErrClaimNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestClaimStatusReasonAndSummary(t *testing.T) {
	db, v, _ := setupConfidenceTestFinding(t)
	a, _ := db.CreateFindingClaim(v.ID, "a")
	b, _ := db.CreateFindingClaim(v.ID, "b")
	c, _ := db.CreateFindingClaim(v.ID, "c")
	for _, st := range []string{ClaimSupported, ClaimDisputed, ClaimUnsupported} {
		if _, err := db.SetClaimStatus(a.ID, st, " "); !errors.Is(err, ErrClaimReason) {
			t.Fatalf("%s without reason: %v", st, err)
		}
	}
	if _, err := db.SetClaimStatus(a.ID, "bogus", "r"); !errors.Is(err, ErrClaimStatusInvalid) {
		t.Fatalf("bogus: %v", err)
	}
	if _, err := db.SetClaimStatus("nope", ClaimSupported, "r"); !errors.Is(err, ErrClaimNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if got, err := db.SetClaimStatus(a.ID, ClaimSupported, "seen"); err != nil || got.Status != ClaimSupported || got.StatusReason != "seen" {
		t.Fatalf("%+v %v", got, err)
	}
	_, _ = db.SetClaimStatus(b.ID, ClaimDisputed, "r")
	_ = c
	s, err := db.ClaimSummary(v.ID)
	if err != nil || s.Total != 3 || s.Supported != 1 || s.Disputed != 1 || s.Unverified != 1 || s.Unsupported != 0 || s.AllSupported() {
		t.Fatalf("summary = %+v err=%v", s, err)
	}
}

func TestConfidenceGateRequiresAllClaimsSupported(t *testing.T) {
	db, v, eng := setupConfidenceTestFinding(t)
	addToolEvidence(t, db, eng.ID, v.ID, "x1")
	raise := func() error {
		_, err := db.SetVulnerabilityConfidence(SetVulnerabilityConfidenceParams{FindingID: v.ID, Confidence: ConfidenceValidated, Reason: "checked", ActorHasProjectWrite: true})
		return err
	}
	// No claims: existing rules apply.
	if err := raise(); err != nil {
		t.Fatalf("no-claims raise refused: %v", err)
	}
	if _, err := db.SetVulnerabilityConfidence(SetVulnerabilityConfidenceParams{FindingID: v.ID, Confidence: ConfidencePotential}); err != nil {
		t.Fatal(err)
	}
	a, _ := db.CreateFindingClaim(v.ID, "a")
	b, _ := db.CreateFindingClaim(v.ID, "b")
	var refused *ErrConfidenceRefused
	if err := raise(); !errors.As(err, &refused) {
		t.Fatalf("unverified claims: err = %v", err)
	}
	_, _ = db.SetClaimStatus(a.ID, ClaimSupported, "r")
	if err := raise(); !errors.As(err, &refused) {
		t.Fatalf("one unsupported claim left: err = %v", err)
	}
	_, _ = db.SetClaimStatus(b.ID, ClaimUnsupported, "r")
	if err := raise(); !errors.As(err, &refused) {
		t.Fatalf("unsupported claim: err = %v", err)
	}
	_, _ = db.SetClaimStatus(b.ID, ClaimSupported, "r")
	if err := raise(); err != nil {
		t.Fatalf("all supported refused: %v", err)
	}
	// Lowering is always allowed even with a disputed claim.
	_, _ = db.SetClaimStatus(b.ID, ClaimDisputed, "r")
	if _, err := db.SetVulnerabilityConfidence(SetVulnerabilityConfidenceParams{FindingID: v.ID, Confidence: ConfidenceObserved}); err != nil {
		t.Fatalf("lowering refused: %v", err)
	}
}
