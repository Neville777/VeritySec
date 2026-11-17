package database

import (
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// ToolPolicyCounts separates scope/approval refusals from genuine tool failures.
type ToolPolicyCounts struct {
	// PolicyRejected counts executions whose error is a scope or approval refusal (any status).
	PolicyRejected int
	// PolicyRejectedFailed is the part of PolicyRejected stored with a failure status
	// (failed, hard_timeout, orphaned); it is subtracted from the failure count.
	PolicyRejectedFailed int
	// Cancelled counts user-cancelled executions.
	Cancelled int
}

const toolPolicyErrorSQL = `(LOWER(COALESCE(error,'')) LIKE '%scope check refused%' OR LOWER(COALESCE(error,'')) LIKE '%approval required%')`

// LoadToolPolicyCounts counts policy rejections and cancellations over tool_executions.
func (db *DB) LoadToolPolicyCounts(access RBACListAccess) (ToolPolicyCounts, error) {
	var out ToolPolicyCounts
	fromSQL, args := appendToolExecutionAccessSQL(` FROM tool_executions`, nil, access, false)
	err := db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN `+toolPolicyErrorSQL+` THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN `+toolPolicyErrorSQL+` AND status IN ('failed','hard_timeout','orphaned') THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END), 0)`+fromSQL, args...).
		Scan(&out.PolicyRejected, &out.PolicyRejectedFailed, &out.Cancelled)
	return out, err
}

// VerificationCounts groups findings by confidence and counts unlinked ones.
type VerificationCounts struct {
	ByConfidence map[string]int `json:"by_confidence"`
	Unlinked     int            `json:"unlinked"`
}

// LoadVerificationCounts counts vulnerabilities per confidence label and those with source_status 'unlinked'.
func (db *DB) LoadVerificationCounts(access RBACListAccess) (VerificationCounts, error) {
	out := VerificationCounts{ByConfidence: map[string]int{}}
	for _, c := range ConfidenceLevels {
		out.ByConfidence[c] = 0
	}
	where, args := "", []interface{}{}
	if access.Scope != RBACScopeAll {
		where, args = ` WHERE owner_user_id = ?`, []interface{}{strings.TrimSpace(access.UserID)}
	}
	rows, err := db.Query(`SELECT LOWER(COALESCE(confidence,'potential')), COUNT(*) FROM vulnerabilities`+where+` GROUP BY 1`, args...)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var c string
		var n int
		if err := rows.Scan(&c, &n); err != nil {
			rows.Close()
			return out, err
		}
		if _, ok := out.ByConfidence[c]; ok {
			out.ByConfidence[c] += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	unlinkedWhere := ` WHERE COALESCE(source_status,'unlinked') = 'unlinked'`
	if where != "" {
		unlinkedWhere += ` AND owner_user_id = ?`
	}
	err = db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities`+unlinkedWhere, args...).Scan(&out.Unlinked)
	return out, err
}

// Dashboard engagement selection: active/running engagements plus completed ones updated recently.
const (
	dashboardEngagementLimit       = 5
	dashboardCompletedWindow       = 14 * 24 * time.Hour
	dashboardActivityLimit         = 8
	dashboardActivitySummaryMaxLen = 120
)

// ActiveEngagementSummary is one row of the dashboard's active engagements panel.
type ActiveEngagementSummary struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	UpdatedAt       time.Time `json:"updated_at"`
	FindingCount    int       `json:"finding_count"`
	AttentionStages int       `json:"attention_stages"`
	// StagesCompleted / StagesTotal come from persisted assessment_stages rows (status completed of 8).
	StagesCompleted int `json:"stages_completed"`
	StagesTotal     int `json:"stages_total"`
	// ProgressPercent is StagesCompleted / StagesTotal as a whole number (rounded down).
	ProgressPercent int `json:"progress_percent"`
	// ChecklistDone / ChecklistTotal count required stage_tasks (done / all); total 0 means none.
	ChecklistDone  int `json:"checklist_done"`
	ChecklistTotal int `json:"checklist_total"`
}

// EngagementProgressPercent is completed stages over total as a whole number.
func EngagementProgressPercent(completed, total int) int {
	if total <= 0 || completed <= 0 {
		return 0
	}
	if completed > total {
		completed = total
	}
	return completed * 100 / total
}

// DashboardEngagementIncluded applies the selection rule: status active or running, or status
// completed and updated within the last 14 days. Everything else (draft, paused, archived,
// older completed) is excluded.
func DashboardEngagementIncluded(status string, updatedAt, now time.Time) bool {
	switch status {
	case EngagementActive, "running":
		return true
	case EngagementCompleted:
		return !updatedAt.Before(now.Add(-dashboardCompletedWindow))
	}
	return false
}

// LoadActiveEngagements returns up to limit (at most 5) dashboard engagements, newest first.
func (db *DB) LoadActiveEngagements(limit int, access RBACListAccess) ([]ActiveEngagementSummary, error) {
	return db.loadActiveEngagementsAt(time.Now().UTC(), limit, access)
}

func (db *DB) loadActiveEngagementsAt(now time.Time, limit int, access RBACListAccess) ([]ActiveEngagementSummary, error) {
	if limit <= 0 || limit > dashboardEngagementLimit {
		limit = dashboardEngagementLimit
	}
	q := `SELECT e.id, e.name, e.status, e.updated_at,
		(SELECT COUNT(*) FROM vulnerabilities v WHERE v.engagement_id = e.id),
		(SELECT COUNT(*) FROM assessment_stages s WHERE s.engagement_id = e.id AND s.status IN ('needs_review','blocked')),
		(SELECT COUNT(*) FROM assessment_stages s WHERE s.engagement_id = e.id AND s.status = 'completed'),
		(SELECT COUNT(*) FROM stage_tasks t WHERE t.engagement_id = e.id AND t.required = 1),
		(SELECT COUNT(*) FROM stage_tasks t WHERE t.engagement_id = e.id AND t.required = 1 AND t.status = 'done')
		FROM engagements e WHERE e.status IN ('active','running','completed')`
	args := []interface{}{}
	if access.Scope != RBACScopeAll {
		q += ` AND e.owner_user_id = ?`
		args = append(args, strings.TrimSpace(access.UserID))
	}
	q += ` ORDER BY e.updated_at DESC, e.id`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActiveEngagementSummary{}
	for rows.Next() {
		var r ActiveEngagementSummary
		if err := rows.Scan(&r.ID, &r.Name, &r.Status, &r.UpdatedAt, &r.FindingCount, &r.AttentionStages,
			&r.StagesCompleted, &r.ChecklistTotal, &r.ChecklistDone); err != nil {
			return nil, err
		}
		if !DashboardEngagementIncluded(r.Status, r.UpdatedAt, now) {
			continue
		}
		r.StagesTotal = len(AssessmentStageDefs)
		r.ProgressPercent = EngagementProgressPercent(r.StagesCompleted, r.StagesTotal)
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

// RecentActivityEvent is a run_events row reduced to a short, output-free summary.
type RecentActivityEvent struct {
	EventType      string    `json:"event_type"`
	Label          string    `json:"label"`
	CreatedAt      time.Time `json:"created_at"`
	Summary        string    `json:"summary"`
	EngagementID   string    `json:"engagement_id,omitempty"`
	EngagementName string    `json:"engagement_name,omitempty"`
}

// recentActivityLabels is the allowlist of user-facing run_events types and their labels.
// Any other event type has no entry and is dropped from the dashboard (presentation only; rows are untouched).
var recentActivityLabels = map[string]string{
	"tool_execution_completed": "Security tool execution completed",
	"tool_execution_failed":    "Security tool execution failed",
	"evidence_created":         "Evidence captured",
	"finding_proposed":         "Finding proposed",
	"finding_verified":         "Finding verified",
	"stage_started":            "Assessment stage started",
	"stage_completed":          "Assessment stage completed",
	"stage_blocked":            "Assessment stage blocked",
	"stage_interrupted":        "Assessment stage interrupted",
	"stage_review_triggered":   "Assessment stage sent for review",
	"approval_requested":       "Approval requested",
	"run_interrupted":          "Run interrupted",
}

// RecentActivityLabel returns the human label for an allowlisted event type, or "" (drop).
func RecentActivityLabel(eventType string) string {
	return recentActivityLabels[eventType]
}

// recentActivitySummaryKeys are the only data_json keys used for the summary; tool output is never read.
var recentActivitySummaryKeys = []string{"tool_name", "toolName", "tool", "status", "stage", "reason", "error_code", "message_kind"}

// LoadRecentActivity returns the most recent allowlisted run_events (at most 8), newest first,
// with a short summary built from a fixed allow-list of data_json keys. limit only lowers the cap.
func (db *DB) LoadRecentActivity(limit int, access RBACListAccess) ([]RecentActivityEvent, error) {
	if limit <= 0 || limit > dashboardActivityLimit {
		limit = dashboardActivityLimit
	}
	types := make([]string, 0, len(recentActivityLabels))
	args := []interface{}{}
	for t := range recentActivityLabels {
		types = append(types, t)
	}
	sort.Strings(types)
	marks := make([]string, len(types))
	for i, t := range types {
		marks[i] = "?"
		args = append(args, t)
	}
	q := `SELECT r.event_type, r.created_at, COALESCE(r.stage,''), COALESCE(r.engagement_id,''), COALESCE(r.data_json,'{}'), COALESCE(e.name,'')
		FROM run_events r LEFT JOIN engagements e ON e.id = r.engagement_id
		WHERE r.event_type IN (` + strings.Join(marks, ",") + `)`
	if access.Scope != RBACScopeAll {
		q += ` AND r.engagement_id IN (SELECT id FROM engagements WHERE owner_user_id = ?)`
		args = append(args, strings.TrimSpace(access.UserID))
	}
	q += ` ORDER BY r.created_at DESC, r.seq DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecentActivityEvent{}
	for rows.Next() {
		var typ, stage, eng, data, engName string
		var created sql.NullString
		if err := rows.Scan(&typ, &created, &stage, &eng, &data, &engName); err != nil {
			return nil, err
		}
		label := RecentActivityLabel(typ)
		if label == "" {
			continue
		}
		ev := RecentActivityEvent{EventType: typ, Label: label, EngagementID: eng, EngagementName: engName,
			Summary: truncateRunes(summarizeRunEventData(stage, data), dashboardActivitySummaryMaxLen)}
		if created.Valid {
			ev.CreatedAt = parseDBTime(created.String)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func truncateRunes(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max])
	}
	return s
}

func summarizeRunEventData(stage, dataJSON string) string {
	var m map[string]interface{}
	_ = json.Unmarshal([]byte(dataJSON), &m)
	parts := []string{}
	if stage != "" {
		parts = append(parts, stage)
	}
	for _, k := range recentActivitySummaryKeys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			s = strings.TrimSpace(s)
			if r := []rune(s); len(r) > 80 {
				s = string(r[:80]) + "..."
			}
			if k == "stage" && s == stage {
				continue
			}
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " | ")
}
