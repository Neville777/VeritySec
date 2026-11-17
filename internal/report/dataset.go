package report

import (
	"crypto/sha256"
	"veritysec/internal/redact"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"veritysec/internal/database"
)

// NotRecorded is printed wherever a source field is empty.
const NotRecorded = "not recorded"

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// Coverage states. "Passing" is deliberately not a state: absence of findings is not evidence.
const (
	CoverageEvidence   = "evidence_backed"
	CoverageNoEvidence = "findings_without_evidence"
	CoverageNotTested  = "not_tested"
)

var coverageLabels = map[string]string{
	CoverageEvidence:   "Findings recorded, evidence attached",
	CoverageNoEvidence: "Findings recorded, NO evidence attached",
	CoverageNotTested:  "Not tested (no evidence)",
}

// coverageCategories are matched against finding type and title (lower case, substring).
var coverageCategories = []struct {
	Name     string
	Keywords []string
}{
	{"Authentication and session management", []string{"authentication", "login", "session", "password", "credential", "jwt", "token", "brute"}},
	{"Access control", []string{"access", "authorization", "idor", "privilege", "bola", "rbac", "permission"}},
	{"Injection and input handling", []string{"injection", "sqli", "sql", "xss", "command", "rce", "ssti", "xxe", "deserialization"}},
	{"Sensitive data exposure", []string{"exposure", "disclosure", "leak", "secret", "sensitive", "information"}},
	{"Security misconfiguration", []string{"misconfiguration", "header", "tls", "ssl", "cors", "default", "cipher", "hardening", "banner"}},
	{"Network and infrastructure", []string{"port", "service", "network", "smb", "ssh", "dns", "firewall"}},
	{"File handling and SSRF", []string{"ssrf", "upload", "traversal", "lfi", "rfi", "path"}},
	{"Vulnerable components", []string{"outdated", "cve", "component", "version"}},
	{"Business logic and abuse", []string{"logic", "race", "abuse"}},
}

const otherCategory = "Other (uncategorised findings)"

// Count is one named tally.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Counts holds tallies computed in Go; templates only print them.
type Counts struct {
	Total      int     `json:"total"`
	Open       int     `json:"open"` // status open or confirmed
	Closed     int     `json:"closed"`
	BySeverity []Count `json:"by_severity"`
	ByStatus   []Count `json:"by_status"`
}

// EvidenceRef links a finding to stored evidence by ID and hash.
type EvidenceRef struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	SHA256 string `json:"sha256"`
}

// Finding is one vulnerability as presented in reports.
type Finding struct {
	Index           int           `json:"index"` // 1-based position after sorting
	ID              string        `json:"id"`
	Title           string        `json:"title"`
	Severity        string        `json:"severity"`
	Status          string        `json:"status"`
	Type            string        `json:"type"`
	Description     string        `json:"description"`
	AffectedAsset   string        `json:"affected_asset"`
	Preconditions   string        `json:"preconditions"`
	ReproSteps      string        `json:"reproduction_steps"`
	Impact          string        `json:"impact"`
	Recommendation  string        `json:"recommendation"`
	RetestNotes     string        `json:"retest_notes"`
	Evidence        []EvidenceRef `json:"evidence"`
	HasEvidence     bool          `json:"has_evidence"`
	Open            bool          `json:"open"` // status open or confirmed
	Category        string        `json:"category"`
	Summary         string        `json:"summary"`          // plain-language one-liner for executives
	Confidence      string        `json:"confidence"`       // potential, observed, reproduced, validated, confirmed
	ConfidenceLabel string        `json:"confidence_label"` // exact executive-report wording for Confidence
	Claims          []ClaimRef    `json:"claims"`
	ClaimsNote      string        `json:"claims_note"` // states plainly when claims are missing or not all supported
	// Verification is the latest independent review of the claims, nil when none was run.
	Verification *VerificationRef `json:"verification,omitempty"`
}

// VerificationRef is the status and reasons of a finding's latest verification record.
type VerificationRef struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
	At      string   `json:"at"`
}

// ClaimRef is one separately checkable claim of a finding, with its status and evidence IDs.
// Unsupported and disputed claims are listed like any other; nothing is hidden.
type ClaimRef struct {
	ID          string   `json:"id"`
	Text        string   `json:"text"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason"`
	EvidenceIDs []string `json:"evidence_ids"`
}

// Asset is an asset tied to the engagement.
type Asset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Criticality string `json:"criticality"`
	Status      string `json:"status"`
}

// ToolSummary summarises tool executions in the engagement's conversations.
type ToolSummary struct {
	Total  int     `json:"total"`
	Failed int     `json:"failed"`
	Tools  []Count `json:"tools"`
}

// CoverageRow reports one assessment category.
type CoverageRow struct {
	Category      string `json:"category"`
	State         string `json:"state"`
	StateLabel    string `json:"state_label"`
	FindingCount  int    `json:"finding_count"`
	EvidenceCount int    `json:"evidence_count"`
}

// EvidenceSummary counts evidence items.
type EvidenceSummary struct {
	Total    int `json:"total"`
	Linked   int `json:"linked_to_findings"`
	Unlinked int `json:"not_linked_to_findings"`
}

// EngagementInfo is the engagement header, with scope parsed for display.
type EngagementInfo struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Objective         string   `json:"objective"`
	Target            string   `json:"target"`
	Status            string   `json:"status"`
	ScopeIncluded     []string `json:"scope_included"`
	ScopeExcluded     []string `json:"scope_excluded"`
	Limits            []string `json:"limits"` // "key: value", sorted by key
	AuthorizationNote string   `json:"authorization_note"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
}

// StageRow reports one assessment stage: status and evidence count only, never content.
type StageRow struct {
	Stage         string `json:"stage"`
	Title         string `json:"title"`
	Order         int    `json:"order"`
	Status        string `json:"status"`
	EvidenceCount int    `json:"evidence_count"`
	// Attention is a fixed sentence for the stages that were not recorded (blocked, needs_review).
	Attention string `json:"attention,omitempty"`
}

// Risk is the overall rating derived from open findings only.
type Risk struct {
	Overall string `json:"overall"`
	Basis   string `json:"basis"`
}

// Dataset is the canonical, database-derived input of every audience and format.
type Dataset struct {
	Engagement EngagementInfo  `json:"engagement"`
	Risk       Risk            `json:"risk"`
	Counts     Counts          `json:"counts"`
	Findings   []Finding       `json:"findings"`
	TopRisks   []Finding       `json:"top_risks"`
	Assets     []Asset         `json:"assets"`
	Tools      ToolSummary     `json:"tools"`
	Evidence   EvidenceSummary `json:"evidence"`
	Coverage   []CoverageRow   `json:"coverage"`
	Stages     []StageRow      `json:"stages"`
	Decisions  []string        `json:"decisions"`
	// ConfidenceGroups tallies findings by confidence label, in order from "Potential exposure"
	// to "Confirmed". The count is always computed here; templates only print it.
	ConfidenceGroups []Count `json:"confidence_groups"`
	// RedactionSummary counts values masked in the text fields below (kind -> count, never the
	// values). Redaction is applied to the dataset copy only; stored evidence and finding rows
	// are unchanged and evidence SHA-256 values still describe the original bytes.
	RedactionSummary map[string]int `json:"redaction_summary"`
	Hash             string         `json:"-"` // sha256 of the JSON encoding of everything above
}

// Build assembles the canonical dataset for an engagement from the database only.
func Build(db *database.DB, engagementID string) (*Dataset, error) {
	eng, err := db.GetEngagement(engagementID)
	if err != nil {
		return nil, err
	}
	vulns, err := db.ListEngagementFindings(engagementID)
	if err != nil {
		return nil, err
	}
	evs, err := db.ListEvidence(engagementID)
	if err != nil {
		return nil, err
	}
	targets := make([]string, 0, len(vulns))
	for _, v := range vulns {
		if h := hostOf(v.Target); h != "" {
			targets = append(targets, h)
		}
	}
	assets, err := db.ListEngagementAssets(engagementID, targets)
	if err != nil {
		return nil, err
	}
	stats, err := db.EngagementToolStats(engagementID)
	if err != nil {
		return nil, err
	}
	stages, err := db.ListAssessmentStages(engagementID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	claims, err := db.ListEngagementClaims(ids)
	if err != nil {
		return nil, err
	}
	d := assembleWithClaims(eng, vulns, evs, assets, stats, stages, claims)
	for i := range d.Findings {
		v, verr := db.LatestFindingVerification(d.Findings[i].ID)
		if errors.Is(verr, database.ErrVerificationNotFound) {
			continue
		}
		if verr != nil {
			return nil, verr
		}
		d.Findings[i].Verification = &VerificationRef{Status: v.Status, Reasons: v.Reasons, At: v.CreatedAt.UTC().Format(time.RFC3339)}
	}
	return d, nil
}

// assemble is the pure part of Build: the same inputs always give the same Dataset.
func assemble(eng *database.Engagement, vulns []*database.Vulnerability, evs []*database.Evidence, assets []*database.EngagementAsset, stats *database.ToolRunStats, stages []database.AssessmentStage) *Dataset {
	return assembleWithClaims(eng, vulns, evs, assets, stats, stages, nil)
}

// assembleWithClaims is assemble plus the finding claims (keyed by finding ID), which are part of
// the dataset and therefore of its hash.
func assembleWithClaims(eng *database.Engagement, vulns []*database.Vulnerability, evs []*database.Evidence, assets []*database.EngagementAsset, stats *database.ToolRunStats, stages []database.AssessmentStage, claims map[string][]*database.FindingClaim) *Dataset {
	d := &Dataset{Engagement: engagementInfo(eng)}
	d.Findings = buildFindings(vulns, evs)
	for i := range d.Findings {
		d.Findings[i].Claims, d.Findings[i].ClaimsNote = claimRefs(claims[d.Findings[i].ID])
	}
	d.RedactionSummary = redactDatasetText(d.Findings)
	d.Counts = countFindings(d.Findings)
	d.Evidence = summariseEvidence(evs, d.Findings)
	d.Coverage = buildCoverage(d.Findings, evs)
	d.Assets = buildAssets(assets)
	d.Stages = buildStages(stages)
	d.Tools = buildTools(stats)
	d.ConfidenceGroups = confidenceGroups(d.Findings)
	d.Risk = overallRisk(d.Findings, d.Counts)
	d.TopRisks = topRisks(d.Findings, 5)
	d.Decisions = decisions(d)
	d.Hash = hashDataset(d)
	return d
}

func hashDataset(d *Dataset) string {
	b, _ := json.Marshal(d) // structs and sorted slices only: stable
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func engagementInfo(e *database.Engagement) EngagementInfo {
	var scope struct {
		Included []string `json:"included"`
		Excluded []string `json:"excluded"`
	}
	_ = json.Unmarshal(e.ScopeJSON, &scope)
	var limits map[string]interface{}
	_ = json.Unmarshal(e.LimitsJSON, &limits)
	keys := make([]string, 0, len(limits))
	for k := range limits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s: %v", k, limits[k]))
	}
	return EngagementInfo{
		ID: e.ID, Name: e.Name, Objective: e.Objective, Target: e.Target, Status: e.Status,
		ScopeIncluded: nonNil(scope.Included), ScopeExcluded: nonNil(scope.Excluded), Limits: lines,
		AuthorizationNote: e.AuthorizationNote,
		CreatedAt:         e.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), UpdatedAt: e.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func severityRank(s string) int {
	for i, n := range severityOrder {
		if n == s {
			return i
		}
	}
	return len(severityOrder)
}

// isOpenStatus reports whether a finding still needs action.
func isOpenStatus(s string) bool { return s == "open" || s == "confirmed" }

// buildFindings sorts by severity, creation time, ID and attaches evidence references.
func buildFindings(vulns []*database.Vulnerability, evs []*database.Evidence) []Finding {
	byFinding := map[string][]EvidenceRef{}
	for _, e := range evs {
		if e.FindingID != "" {
			byFinding[e.FindingID] = append(byFinding[e.FindingID], EvidenceRef{ID: e.ID, Kind: e.Kind, Title: e.Title, SHA256: e.SHA256})
		}
	}
	sorted := append([]*database.Vulnerability(nil), vulns...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if ra, rb := severityRank(norm(a.Severity)), severityRank(norm(b.Severity)); ra != rb {
			return ra < rb
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID < b.ID
	})
	out := make([]Finding, 0, len(sorted))
	for i, v := range sorted {
		refs := byFinding[v.ID]
		if refs == nil {
			refs = []EvidenceRef{}
		}
		f := Finding{
			Index: i + 1, ID: v.ID, Title: orNR(v.Title), Severity: norm(v.Severity), Status: norm(v.Status), Type: orNR(v.Type),
			Description: orNR(v.Description), AffectedAsset: orNR(v.Target), Preconditions: orNR(v.Preconditions),
			ReproSteps: orNR(v.ReproSteps), Impact: orNR(v.Impact), Recommendation: orNR(v.Recommendation), RetestNotes: orNR(v.RetestNotes),
			Evidence: refs, HasEvidence: len(refs) > 0, Open: isOpenStatus(norm(v.Status)), Category: categoryOf(v.Type, v.Title),
		}
		f.Confidence = confidenceOf(v.Confidence)
		f.ConfidenceLabel = confidenceLabel(f.Confidence)
		f.Summary = plainSummary(v)
		out = append(out, f)
	}
	return out
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// confidenceOf normalises a stored confidence value, defaulting to "potential".
func confidenceOf(c string) string {
	c = norm(c)
	if !database.ValidConfidence(c) {
		return database.ConfidencePotential
	}
	return c
}

// confidenceLabel returns the exact executive-report wording for a confidence value.
func confidenceLabel(c string) string {
	if label, ok := database.ConfidenceLabels[c]; ok {
		return label
	}
	return database.ConfidenceLabels[database.ConfidencePotential]
}

// confidenceGroups tallies findings by confidence label, in fixed order, lowest first.
func confidenceGroups(fs []Finding) []Count {
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.Confidence]++
	}
	out := make([]Count, 0, len(database.ConfidenceLevels))
	for _, lvl := range database.ConfidenceLevels {
		out = append(out, Count{Name: database.ConfidenceLabels[lvl], Count: counts[lvl]})
	}
	return out
}

func orNR(s string) string {
	if strings.TrimSpace(s) == "" {
		return NotRecorded
	}
	return strings.TrimSpace(s)
}

// plainSummary prefers the recorded impact, then the description, shortened to 240 runes.
func plainSummary(v *database.Vulnerability) string {
	s := strings.TrimSpace(v.Impact)
	if s == "" {
		s = strings.TrimSpace(v.Description)
	}
	if s == "" {
		return "No impact statement recorded"
	}
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > 240 {
		s = string([]rune(s)[:237]) + "..."
	}
	return s
}

// categoryOf maps a finding to a coverage category. The type is consulted first because titles
// mention incidental words ("SQL injection in login"); the title is the fallback.
func categoryOf(typ, title string) string {
	for _, text := range []string{typ, title} {
		tokens := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		for _, c := range coverageCategories {
			if hasKeyword(tokens, c.Keywords) {
				return c.Name
			}
		}
	}
	return otherCategory
}

// hasKeyword matches whole tokens; keywords of seven or more letters also match as a token prefix
// (so "injection" covers "injections" but "port" does not match "report").
func hasKeyword(tokens, keywords []string) bool {
	for _, t := range tokens {
		for _, k := range keywords {
			if t == k || (len(k) >= 7 && strings.HasPrefix(t, k)) {
				return true
			}
		}
	}
	return false
}

// countFindings tallies severities (known ones always listed, even at zero) and statuses.
func countFindings(fs []Finding) Counts {
	c := Counts{Total: len(fs)}
	sev, st := map[string]int{}, map[string]int{}
	for _, f := range fs {
		sev[f.Severity]++
		st[f.Status]++
		if isOpenStatus(f.Status) {
			c.Open++
		}
	}
	c.Closed = c.Total - c.Open
	for _, n := range severityOrder {
		c.BySeverity = append(c.BySeverity, Count{n, sev[n]})
		delete(sev, n)
	}
	c.BySeverity = append(c.BySeverity, sortedCounts(sev)...)
	c.ByStatus = sortedCounts(st)
	if c.ByStatus == nil {
		c.ByStatus = []Count{}
	}
	return c
}

func sortedCounts(m map[string]int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func summariseEvidence(evs []*database.Evidence, fs []Finding) EvidenceSummary {
	known := map[string]bool{}
	for _, f := range fs {
		known[f.ID] = true
	}
	s := EvidenceSummary{Total: len(evs)}
	for _, e := range evs {
		if e.FindingID != "" && known[e.FindingID] {
			s.Linked++
		}
	}
	s.Unlinked = s.Total - s.Linked
	return s
}

// buildCoverage lists every category. A category is never reported as passing: without a
// finding that carries evidence it is "not tested".
func buildCoverage(fs []Finding, evs []*database.Evidence) []CoverageRow {
	names := make([]string, 0, len(coverageCategories)+1)
	for _, c := range coverageCategories {
		names = append(names, c.Name)
	}
	names = append(names, otherCategory)
	rows := make([]CoverageRow, 0, len(names))
	for _, n := range names {
		r := CoverageRow{Category: n}
		for _, f := range fs {
			if f.Category == n {
				r.FindingCount++
				r.EvidenceCount += len(f.Evidence)
			}
		}
		switch {
		case r.EvidenceCount > 0:
			r.State = CoverageEvidence
		case r.FindingCount > 0:
			r.State = CoverageNoEvidence
		default:
			r.State = CoverageNotTested
		}
		r.StateLabel = coverageLabels[r.State]
		if n == otherCategory && r.FindingCount == 0 {
			continue // only shown when something fell outside the named categories
		}
		rows = append(rows, r)
	}
	return rows
}

func buildAssets(as []*database.EngagementAsset) []Asset {
	out := make([]Asset, 0, len(as))
	for _, a := range as {
		name := firstNonEmpty(a.Domain, a.Host, a.IP, a.Title, a.ID)
		if a.Port > 0 {
			name = fmt.Sprintf("%s:%d", name, a.Port)
		}
		out = append(out, Asset{ID: a.ID, Name: name, Protocol: orNR(a.Protocol), Criticality: orNR(a.Criticality), Status: orNR(a.Status)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// buildStages keeps the fixed order; counts are computed here, evidence content never enters the dataset.
func buildStages(in []database.AssessmentStage) []StageRow {
	out := make([]StageRow, 0, len(in))
	for _, s := range in {
		row := StageRow{Stage: s.Stage, Title: s.Title, Order: s.Order, Status: s.Status, EvidenceCount: len(s.EvidenceIDs)}
		switch s.Status {
		case database.StageBlocked:
			row.Attention = "not recorded: automatic handling stopped and no tool evidence exists for this stage"
		case database.StageNeedsReview:
			row.Attention = "not recorded: tool evidence exists for this stage, a person must decide whether to complete or skip it"
		case database.StageFailed:
			row.Attention = "not recorded: the stage's run ended with an error it could not continue from"
		case database.StageInterrupted:
			row.Attention = "not recorded: the run ended without completing (cancelled, timed out, or a billing/payment failure) while this stage was running"
		}
		out = append(out, row)
	}
	return out
}

func buildTools(st *database.ToolRunStats) ToolSummary {
	ts := ToolSummary{Tools: []Count{}}
	if st == nil {
		return ts
	}
	ts.Total, ts.Failed = st.Total, st.Failed
	for _, n := range st.SortedToolNames() {
		ts.Tools = append(ts.Tools, Count{n, st.ByTool[n]})
	}
	return ts
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// overallRisk rates by the highest severity among open findings. No findings means "not assessed".
func overallRisk(fs []Finding, c Counts) Risk {
	if c.Total == 0 {
		return Risk{"Not assessed", "No findings are recorded for this engagement. This is not evidence that the target is secure."}
	}
	for _, sev := range severityOrder {
		n := 0
		for _, f := range fs {
			if f.Severity == sev && isOpenStatus(f.Status) {
				n++
			}
		}
		if n > 0 {
			return Risk{strings.ToUpper(sev[:1]) + sev[1:], fmt.Sprintf("Based on the highest severity among open or confirmed findings (%d at this level).", n)}
		}
	}
	return Risk{"No open findings", fmt.Sprintf("All %d recorded findings are fixed, ignored or marked false positive. Coverage gaps below still apply.", c.Total)}
}

func topRisks(fs []Finding, n int) []Finding {
	out := []Finding{}
	for _, f := range fs {
		if isOpenStatus(f.Status) && len(out) < n {
			out = append(out, f)
		}
	}
	return out
}

// decisions lists the choices a reader must make, derived from the dataset.
func decisions(d *Dataset) []string {
	out := []string{}
	crit := 0
	for _, f := range d.Findings {
		if isOpenStatus(f.Status) && (f.Severity == "critical" || f.Severity == "high") {
			crit++
		}
	}
	if crit > 0 {
		out = append(out, fmt.Sprintf("Open critical or high findings: %d. Assign owners and deadlines.", crit))
	}
	noEv := 0
	for _, f := range d.Findings {
		if !f.HasEvidence {
			noEv++
		}
	}
	if noEv > 0 {
		out = append(out, fmt.Sprintf("Findings without evidence: %d. Collect evidence or accept them as unverified.", noEv))
	}
	gaps := 0
	for _, c := range d.Coverage {
		if c.State == CoverageNotTested {
			gaps++
		}
	}
	if gaps > 0 {
		out = append(out, fmt.Sprintf("Assessment categories not tested: %d. Extend testing or accept the gap.", gaps))
	}
	if d.Engagement.AuthorizationNote == "" {
		out = append(out, "No authorization reference is recorded for this engagement: record who authorized the work.")
	}
	if d.Engagement.Status == database.EngagementDraft {
		out = append(out, "The engagement is still a draft: confirm scope and activate or close it.")
	}
	return out
}

// hostOf reduces a target (URL, host:port or bare host) to a lower-case host for asset matching.
func hostOf(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndex(t, "@"); i >= 0 {
		t = t[i+1:]
	}
	if i := strings.LastIndex(t, ":"); i >= 0 && !strings.Contains(t[i:], "]") && strings.Count(t, ":") == 1 {
		t = t[:i]
	}
	return strings.Trim(t, "[]")
}

// claimRefs converts stored claims and states the support position in words.
func claimRefs(cs []*database.FindingClaim) ([]ClaimRef, string) {
	out := make([]ClaimRef, 0, len(cs))
	notSupported := 0
	for _, c := range cs {
		ids := append([]string{}, c.EvidenceIDs...)
		out = append(out, ClaimRef{ID: c.ID, Text: c.Text, Status: c.Status, Reason: c.StatusReason, EvidenceIDs: ids})
		if c.Status != database.ClaimSupported {
			notSupported++
		}
	}
	switch {
	case len(out) == 0:
		return out, "No claims recorded for this finding"
	case notSupported > 0:
		return out, fmt.Sprintf("%d of %d claims are not supported", notSupported, len(out))
	}
	return out, "All claims supported"
}

// redactDatasetText masks sensitive values in the free-text fields of the findings (description,
// evidence titles, claim text and the other narrative fields) in place on the dataset copy and
// returns the per-kind counts. The dataset holds no evidence bodies, only IDs, titles and hashes.
func redactDatasetText(fs []Finding) map[string]int {
	sum := map[string]int{}
	do := func(p *string) {
		out, found := redact.Redact(*p)
		*p = out
		redact.Add(sum, found)
	}
	for i := range fs {
		f := &fs[i]
		for _, p := range []*string{&f.Title, &f.Description, &f.Preconditions, &f.ReproSteps, &f.Impact, &f.Recommendation, &f.RetestNotes, &f.ClaimsNote} {
			do(p)
		}
		// Summary is a copy of the description's start: mask it but do not count it twice.
		f.Summary, _ = redact.Redact(f.Summary)
		for j := range f.Evidence {
			do(&f.Evidence[j].Title)
		}
		for j := range f.Claims {
			do(&f.Claims[j].Text)
			do(&f.Claims[j].Reason)
		}
	}
	return sum
}
