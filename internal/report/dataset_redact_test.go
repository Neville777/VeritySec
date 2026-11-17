package report

import (
	"encoding/json"
	"strings"
	"testing"

	"veritysec/internal/database"
)

func TestDatasetRedactsTextAndSummarises(t *testing.T) {
	eng := &database.Engagement{ID: "e", Name: "n", Status: "draft", ScopeJSON: []byte("{}"), LimitsJSON: []byte("{}")}
	vulns := []*database.Vulnerability{{ID: "v1", Title: "Leak", Severity: "high", Status: "open",
		Description: "Found password=Hunter2secret and key AKIAIOSFODNN7EXAMPLE, contact bob@example.com"}}
	claims := map[string][]*database.FindingClaim{"v1": {{ID: "c1", Text: "Bearer abcdef1234567890xyz was accepted", Status: database.ClaimSupported}}}
	d := assembleWithClaims(eng, vulns, nil, nil, nil, nil, claims)
	b, _ := json.Marshal(d)
	for _, s := range []string{"Hunter2secret", "AKIAIOSFODNN7EXAMPLE", "bob@example.com", "abcdef1234567890xyz"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("dataset leaks %q", s)
		}
	}
	rs := d.RedactionSummary
	if rs["password"] != 1 || rs["aws_access_key"] != 1 || rs["email"] != 1 || rs["bearer_token"] != 1 {
		t.Fatalf("summary %v", rs)
	}
	// The input row is a different object: the stored original is not modified.
	if !strings.Contains(vulns[0].Description, "Hunter2secret") {
		t.Fatal("original finding was modified")
	}
	if clean := assembleWithClaims(eng, nil, nil, nil, nil, nil, nil); clean.RedactionSummary == nil || len(clean.RedactionSummary) != 0 {
		t.Fatalf("clean summary %v", clean.RedactionSummary)
	}
}
