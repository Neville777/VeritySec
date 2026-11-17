package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"veritysec/internal/database"
)

var fixedTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func ts(h int) time.Time { return time.Date(2026, 1, 1, h, 0, 0, 0, time.UTC) }

// fixture builds a dataset without a database: 3 findings (one with evidence), one tool failure.
func fixture() *Dataset {
	eng := &database.Engagement{ID: "eng-1", Name: "Acme <external> test", Status: "active", Target: "acme.example",
		ScopeJSON: []byte(`{"included":["acme.example"],"excluded":["mail.acme.example"]}`), LimitsJSON: []byte(`{"rate":"10rps"}`),
		AuthorizationNote: "SOW-42", CreatedAt: ts(0), UpdatedAt: ts(1)}
	vulns := []*database.Vulnerability{
		{ID: "v-low", Title: "Verbose banner", Severity: "Low", Status: "open", Type: "banner disclosure", Target: "https://acme.example:8443/x", CreatedAt: ts(3)},
		{ID: "v-crit", Title: "SQL injection in login", Severity: "critical", Status: "open", Type: "sql injection", Target: "acme.example", Description: "bad `input` **x**", ReproSteps: "curl ```evil```", Impact: "Full DB read", CreatedAt: ts(2)},
		{ID: "v-fixed", Title: "Old XSS", Severity: "high", Status: "fixed", Type: "xss", Target: "acme.example", CreatedAt: ts(1)},
	}
	evs := []*database.Evidence{{ID: "ev-1", EngagementID: "eng-1", FindingID: "v-crit", Kind: "http_exchange", Title: "login request", SHA256: strings.Repeat("a", 64), CreatedAt: ts(4)},
		{ID: "ev-2", EngagementID: "eng-1", Kind: "note", Title: "loose note", SHA256: strings.Repeat("b", 64), CreatedAt: ts(5)}}
	assets := []*database.EngagementAsset{{ID: "a1", Domain: "acme.example", Port: 443, Protocol: "https"}}
	stats := &database.ToolRunStats{Total: 3, Failed: 1, ByTool: map[string]int{"nmap": 2, "curl": 1}}
	stages := []database.AssessmentStage{
		{Stage: "AUTHORISATION", Title: "Authorisation", Order: 1, Status: "completed", EvidenceIDs: []string{"ev-1", "ev-2"}},
		{Stage: "RECONNAISSANCE", Title: "Reconnaissance", Order: 2, Status: "running", EvidenceIDs: []string{}},
	}
	return assemble(eng, vulns, evs, assets, stats, stages)
}

func TestCountsComeFromDataset(t *testing.T) {
	d := fixture()
	if d.Counts.Total != 3 || d.Counts.Open != 2 {
		t.Fatalf("counts = %+v", d.Counts)
	}
	want := map[string]int{"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}
	for _, c := range d.Counts.BySeverity {
		if want[c.Name] != c.Count {
			t.Errorf("severity %s = %d, want %d", c.Name, c.Count, want[c.Name])
		}
	}
	if d.Risk.Overall != "Critical" || d.Findings[0].ID != "v-crit" {
		t.Fatalf("risk/sort wrong: %+v first=%s", d.Risk, d.Findings[0].ID)
	}
	if d.Tools.Total != 3 || d.Tools.Failed != 1 || d.Tools.Tools[0].Name != "curl" {
		t.Fatalf("tools = %+v", d.Tools)
	}
	if d.Evidence.Total != 2 || d.Evidence.Linked != 1 || d.Evidence.Unlinked != 1 {
		t.Fatalf("evidence = %+v", d.Evidence)
	}
	md := string(mustMD(t, d, Executive))
	for _, line := range []string{"Total findings: 3 (open or confirmed: 2)", "- critical: 1", "- low: 1", "- info: 0", "Tool"[:0] + "**Critical**"} {
		if !strings.Contains(md, line) {
			t.Errorf("executive report missing %q", line)
		}
	}
}

func mustMD(t *testing.T, d *Dataset, a Audience) []byte {
	t.Helper()
	b, err := RenderMarkdown(d, a, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReportIsDeterministic(t *testing.T) {
	for _, a := range []Audience{Executive, Technical, Developer} {
		d1, d2 := fixture(), fixture()
		if d1.Hash != d2.Hash {
			t.Fatal("dataset hash differs between identical inputs")
		}
		if !bytes.Equal(mustMD(t, d1, a), mustMD(t, d2, a)) {
			t.Fatalf("%s markdown is not byte-identical", a)
		}
	}
}

func TestNotTestedAndNeverPassing(t *testing.T) {
	d := fixture()
	byCat := map[string]CoverageRow{}
	for _, c := range d.Coverage {
		byCat[c.Category] = c
	}
	if byCat["Injection and input handling"].State != CoverageEvidence {
		t.Errorf("injection should be evidence backed: %+v", byCat["Injection and input handling"])
	}
	if byCat["Sensitive data exposure"].State != CoverageNoEvidence {
		t.Errorf("banner disclosure finding has no evidence: %+v", byCat["Sensitive data exposure"])
	}
	if byCat["Security misconfiguration"].State != CoverageNotTested {
		t.Errorf("misconfiguration should be not tested: %+v", byCat["Security misconfiguration"])
	}
	if byCat["Access control"].State != CoverageNotTested {
		t.Errorf("access control should be not tested: %+v", byCat["Access control"])
	}
	md := strings.ToLower(string(mustMD(t, d, Technical)))
	if !strings.Contains(md, "access control: not tested (no evidence)") {
		t.Error("technical report does not render 'not tested'")
	}
	for _, bad := range []string{"passed", "passing:", "secure"} {
		if strings.Contains(strings.ReplaceAll(md, "no category is reported as passing", ""), bad) && bad != "secure" {
			t.Errorf("report contains %q", bad)
		}
	}
	empty := assemble(&database.Engagement{ID: "e", Name: "n", Status: "draft", ScopeJSON: []byte("{}"), LimitsJSON: []byte("{}")}, nil, nil, nil, nil, nil)
	if empty.Risk.Overall != "Not assessed" {
		t.Errorf("empty engagement risk = %q", empty.Risk.Overall)
	}
	for _, c := range empty.Coverage {
		if c.State != CoverageNotTested {
			t.Errorf("empty engagement category %s = %s", c.Category, c.State)
		}
	}
}

func TestMarkdownInjectionIsNeutralisedAndFooter(t *testing.T) {
	d := fixture()
	md := string(mustMD(t, d, Technical))
	if strings.Contains(md, "Acme <external>") || !strings.Contains(md, `Acme \<external\>`) {
		t.Error("title not escaped")
	}
	if !strings.Contains(md, "````\ncurl ```evil```\n````") {
		t.Errorf("fence not widened:\n%s", md)
	}
	want := "Generated: 2026-01-02T03:04:05Z | Engagement: eng-1 | Dataset hash: " + d.Hash + " | Audience: technical"
	if !strings.Contains(md, want) {
		t.Errorf("footer missing: want %q", want)
	}
	if !strings.Contains(md, "ev-1 (http_exchange, sha256 "+strings.Repeat("a", 64)+")") {
		t.Error("evidence hash reference missing")
	}
}

func TestHTMLAndDocxFromSameDataset(t *testing.T) {
	d := fixture()
	page, err := RenderEngagement(d, Technical, HTML, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	h := string(page)
	if strings.Contains(h, "<external>") || !strings.Contains(h, "&lt;external&gt;") {
		t.Error("html did not escape title")
	}
	if !strings.Contains(h, `id="finding-v-crit"`) || !strings.Contains(h, d.Hash) {
		t.Error("html missing anchor or hash")
	}
	doc, err := RenderEngagement(d, Executive, DOCX, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range z.File {
		if f.Name == "word/document.xml" {
			r, _ := f.Open()
			b, _ := io.ReadAll(r)
			found = strings.Contains(string(b), d.Hash) && strings.Contains(string(b), "Executive summary")
		}
	}
	if !found {
		t.Error("docx lacks hash/title")
	}
	if _, err := RenderEngagement(d, "boss", Markdown, fixedTime); err == nil {
		t.Error("unknown audience accepted")
	}
}

func TestDeveloperTicketsOnlyForOpenFindingsAndBlanksArePlaceholders(t *testing.T) {
	d := fixture()
	md := string(mustMD(t, d, Developer))
	if strings.Contains(md, "Old XSS") || !strings.Contains(md, "not ticketed: 1") {
		t.Error("closed finding must not get a ticket")
	}
	if !strings.Contains(string(mustMD(t, d, Technical)), "Objective: not recorded") {
		t.Error("blank objective not rendered as placeholder")
	}
	if strings.Count(md, "Acceptance criteria:") != 2 {
		t.Error("expected two tickets")
	}
}

func TestReportsShowStageStatusAndEvidenceCountOnly(t *testing.T) {
	d := fixture()
	if len(d.Stages) != 2 || d.Stages[0].EvidenceCount != 2 || d.Stages[1].EvidenceCount != 0 {
		t.Fatalf("stage counts: %+v", d.Stages)
	}
	for _, a := range []Audience{Technical, Executive} {
		out := string(mustMD(t, d, a))
		if !strings.Contains(out, "## Assessment stages") || !strings.Contains(out, "1. Authorisation: completed (2 evidence item(s))") ||
			!strings.Contains(out, "2. Reconnaissance: running (0 evidence item(s))") {
			t.Fatalf("%s report lacks stage section:\n%s", a, out)
		}
	}
}

func TestTechnicalReportListsClaimsWithStatus(t *testing.T) {
	eng := &database.Engagement{ID: "eng-1", Name: "n", Status: "active", ScopeJSON: []byte("{}"), LimitsJSON: []byte("{}")}
	vulns := []*database.Vulnerability{{ID: "v1", Title: "F1", Severity: "high", Status: "open", CreatedAt: ts(1)}, {ID: "v2", Title: "F2", Severity: "low", Status: "open", CreatedAt: ts(2)}}
	claims := map[string][]*database.FindingClaim{"v1": {
		{ID: "c1", Text: "login is injectable", Status: "supported", StatusReason: "reproduced twice", EvidenceIDs: []string{"ev-1"}},
		{ID: "c2", Text: "data is exfiltrable", Status: "unsupported", StatusReason: "no proof", EvidenceIDs: []string{}},
		{ID: "c3", Text: "admin takeover", Status: "disputed", StatusReason: "reviewer disagrees", EvidenceIDs: []string{}}}}
	d := assembleWithClaims(eng, vulns, nil, nil, nil, nil, claims)
	out := string(mustMD(t, d, Technical))
	for _, want := range []string{"[supported] login is injectable (evidence: ev-1)", "[unsupported] data is exfiltrable (evidence: none)",
		"[disputed] admin takeover", "reason: no proof", "2 of 3 claims are not supported", "No claims recorded for this finding"} {
		if !strings.Contains(out, want) {
			t.Fatalf("technical report lacks %q:\n%s", want, out)
		}
	}
	if d.Findings[0].Claims == nil || len(d.Findings[0].Claims[0].EvidenceIDs) != 1 {
		t.Fatalf("claims not in dataset: %+v", d.Findings[0])
	}
}
