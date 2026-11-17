package database

import (
	"path/filepath"
	"testing"
	"time"

	"veritysec/internal/mcp"

	"go.uber.org/zap"
)

func newDashTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "d.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mkEng(t *testing.T, db *DB, name, status string, age time.Duration) string {
	t.Helper()
	e, err := db.CreateEngagement(&Engagement{Name: name, Status: status})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE engagements SET updated_at = ? WHERE id = ?`, time.Now().UTC().Add(-age), e.ID); err != nil {
		t.Fatal(err)
	}
	return e.ID
}

func TestDashboardEngagementSelection(t *testing.T) {
	db := newDashTestDB(t)
	mkEng(t, db, "draft", EngagementDraft, time.Hour)
	mkEng(t, db, "active", EngagementActive, 40*24*time.Hour)
	mkEng(t, db, "recent-done", EngagementCompleted, 3*24*time.Hour)
	mkEng(t, db, "old-done", EngagementCompleted, 20*24*time.Hour)
	mkEng(t, db, "archived", EngagementArchived, time.Hour)
	rows, err := db.LoadActiveEngagements(5, RBACListAccess{Scope: RBACScopeAll})
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, r := range rows {
		got = append(got, r.Name)
	}
	if len(got) != 2 || got[0] != "recent-done" || got[1] != "active" {
		t.Fatalf("selection = %v", got)
	}
}

func TestDashboardEngagementLimitFiveNewestFirst(t *testing.T) {
	db := newDashTestDB(t)
	for i := 0; i < 7; i++ {
		mkEng(t, db, string(rune('a'+i)), EngagementActive, time.Duration(i)*time.Hour)
	}
	rows, _ := db.LoadActiveEngagements(50, RBACListAccess{Scope: RBACScopeAll})
	if len(rows) != 5 || rows[0].Name != "a" || rows[4].Name != "e" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestDashboardEngagementProgressFromStageState(t *testing.T) {
	db := newDashTestDB(t)
	id := mkEng(t, db, "p", EngagementActive, 0)
	for i, st := range []string{"completed", "completed", "completed", "running", "skipped"} {
		if _, err := db.Exec(`INSERT INTO assessment_stages (engagement_id, stage, status, evidence_ids_json, initiated_by, reason, updated_at) VALUES (?, ?, ?, '[]', '', '', ?)`,
			id, AssessmentStageDefs[i].Name, st, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	for i, st := range []string{"done", "open", "done"} {
		req := 1
		if i == 2 {
			req = 0 // optional items do not count
		}
		if _, err := db.Exec(`INSERT INTO stage_tasks (id, engagement_id, stage, title, description, required, status, reason, proposed_by, created_at, updated_at) VALUES (?, ?, ?, 't', '', ?, ?, '', 'human', ?, ?)`,
			"t"+string(rune('0'+i)), id, AssessmentStageDefs[0].Name, req, st, time.Now().UTC(), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.LoadActiveEngagements(5, RBACListAccess{Scope: RBACScopeAll})
	if err != nil || len(rows) != 1 {
		t.Fatal(err, rows)
	}
	r := rows[0]
	if r.StagesCompleted != 3 || r.StagesTotal != 8 || r.ProgressPercent != 37 || r.ChecklistDone != 1 || r.ChecklistTotal != 2 {
		t.Fatalf("progress = %+v", r)
	}
	if EngagementProgressPercent(8, 8) != 100 || EngagementProgressPercent(0, 8) != 0 {
		t.Fatal("bounds")
	}
}

func TestRecentActivityAllowlist(t *testing.T) {
	db := newDashTestDB(t)
	engID := mkEng(t, db, "Acme", EngagementActive, 0)
	allowed := []string{"tool_execution_completed", "tool_execution_failed", "evidence_created", "finding_proposed", "finding_verified",
		"stage_started", "stage_completed", "stage_blocked", "stage_interrupted", "stage_review_triggered", "approval_requested", "run_interrupted"}
	for _, ty := range allowed {
		if RecentActivityLabel(ty) == "" {
			t.Fatalf("%s has no label", ty)
		}
	}
	if RecentActivityLabel("stage_blocked") != "Assessment stage blocked" || RecentActivityLabel("evidence_created") != "Evidence captured" {
		t.Fatal("labels")
	}
	if len(recentActivityLabels) != len(allowed) {
		t.Fatalf("allowlist has %d entries", len(recentActivityLabels))
	}
	for i, ty := range []string{"response_delta", "thinking", "tool_result", "eino_usage_summary", "stage_blocked"} {
		if _, err := db.AppendRunEvent("run1", "", engID, ty, "", map[string]interface{}{"reason": "x"}); err != nil {
			t.Fatal(i, err)
		}
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := db.AppendRunEvent("run1", "", engID, "evidence_created", "", map[string]interface{}{"reason": string(long)}); err != nil {
		t.Fatal(err)
	}
	evs, err := db.LoadRecentActivity(20, RBACListAccess{Scope: RBACScopeAll})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].EventType != "evidence_created" || evs[1].EventType != "stage_blocked" {
		t.Fatalf("events = %+v", evs)
	}
	if evs[0].EngagementName != "Acme" || evs[1].Label != "Assessment stage blocked" || len([]rune(evs[0].Summary)) > 120 {
		t.Fatalf("event fields = %+v", evs[0])
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM run_events`).Scan(&n)
	if n != 6 {
		t.Fatalf("run_events rows were altered: %d", n)
	}
}

func TestClassifyToolExecution(t *testing.T) {
	cases := []struct{ status, err, want string }{
		{"completed", "", ExecSuccess},
		{"hard_timeout", "", ExecTimeout},
		{"failed", "context: operation Timed Out", ExecTimeout},
		{"failed", "402 Payment Required", ExecProviderFailure},
		{"failed", "Payment Required", ExecProviderFailure},
		{"failed", "HTTP 402", ExecProviderFailure},
		{"failed", "Rate Limit exceeded", ExecProviderFailure},
		{"orphaned", "upstream provider down", ExecProviderFailure},
		{"failed", "scope check refused: host out of scope", ExecPolicyRejected},
		{"failed", "approval required for this tool", ExecPolicyRejected},
		{"hard_timeout", "scope check refused", ExecPolicyRejected},
		{"cancelled", "", ExecCancelled},
		{"cancelled", "timed out", ExecCancelled},
		{"failed", "exit status 1", ExecExecutionFailure},
		{"orphaned", "", ExecExecutionFailure},
		{"running", "", ""},
		{"blocked", "x", ""},
	}
	for _, c := range cases {
		if got := ClassifyToolExecution(c.status, c.err); got != c.want {
			t.Errorf("%s/%q = %q want %q", c.status, c.err, got, c.want)
		}
	}
}

func TestExecutionHealthDenominatorAndBanner(t *testing.T) {
	db := newDashTestDB(t)
	now := time.Now()
	rows := []struct{ status, err string }{
		{"completed", ""}, {"completed", ""}, {"completed", ""},
		{"hard_timeout", ""}, {"failed", "402"}, {"failed", "boom"}, {"cancelled", ""},
		{"failed", "scope check refused"}, {"failed", "approval required"},
	}
	for i, r := range rows {
		ex := &mcp.ToolExecution{ID: string(rune('a' + i)), ToolName: "t", Status: r.status, Error: r.err, StartTime: now, EndTime: &now}
		if err := db.SaveToolExecution(ex); err != nil {
			t.Fatal(err)
		}
	}
	h, err := db.LoadExecutionHealth(RBACListAccess{Scope: RBACScopeAll})
	if err != nil {
		t.Fatal(err)
	}
	if h.Success != 3 || h.Timeout != 1 || h.ProviderFailure != 1 || h.ExecutionFailure != 1 || h.Cancelled != 1 || h.PolicyRejected != 2 {
		t.Fatalf("counts = %+v", h)
	}
	if h.Denominator != 7 || h.SuccessRate < 42.8 || h.SuccessRate > 42.9 {
		t.Fatalf("denominator/rate = %d %v", h.Denominator, h.SuccessRate)
	}
	if h.FailedCount != h.ExecutionFailure+h.Timeout+h.ProviderFailure || h.FailedCount != 3 {
		t.Fatalf("failed count = %d", h.FailedCount)
	}
	var empty ExecutionHealth
	empty.Add(ExecPolicyRejected, 4)
	empty.Finalize()
	if empty.Denominator != 0 || empty.SuccessRate != -1 {
		t.Fatalf("policy-only = %+v", empty)
	}
}
