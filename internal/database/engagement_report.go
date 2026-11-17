package database

import (
	"sort"
	"strings"
)

// findingInEngagementSQL selects vulnerabilities linked to an engagement directly or through an
// attached conversation. It takes the engagement ID twice. Aliased columns must be unqualified.
const findingInEngagementSQL = `(engagement_id = ? OR conversation_id IN (SELECT id FROM conversations WHERE engagement_id = ?))`

// ListEngagementFindings returns the engagement's findings with the full record, in ID order
// (callers sort for presentation).
func (db *DB) ListEngagementFindings(engagementID string) ([]*Vulnerability, error) {
	rows, err := db.Query(`SELECT id, COALESCE(conversation_id, ''), title, COALESCE(description, ''), severity, status,
		COALESCE(vulnerability_type, ''), COALESCE(target, ''), COALESCE(preconditions, ''), COALESCE(reproduction_steps, ''),
		COALESCE(evidence, ''), COALESCE(impact, ''), COALESCE(recommendation, ''), COALESCE(retest_notes, ''), COALESCE(retest_log, ''),
		COALESCE(confidence, 'potential'), created_at, updated_at
		FROM vulnerabilities WHERE `+findingInEngagementSQL+` ORDER BY id`, engagementID, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Vulnerability{}
	for rows.Next() {
		v := &Vulnerability{}
		if err := rows.Scan(&v.ID, &v.ConversationID, &v.Title, &v.Description, &v.Severity, &v.Status, &v.Type, &v.Target,
			&v.Preconditions, &v.ReproSteps, &v.Evidence, &v.Impact, &v.Recommendation, &v.RetestNotes, &v.RetestLog, &v.Confidence, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// EngagementAsset is the asset subset shown in reports.
type EngagementAsset struct {
	ID, Host, IP, Domain, Protocol, Title, Criticality, Status string
	Port                                                       int
}

// ListEngagementAssets returns assets referenced by the engagement's evidence, plus assets whose
// host, domain or IP equals one of the given finding targets (already normalised by the caller).
func (db *DB) ListEngagementAssets(engagementID string, targets []string) ([]*EngagementAsset, error) {
	q := `SELECT id, host, ip, domain, protocol, title, criticality, status, port FROM assets
		WHERE (id IN (SELECT asset_id FROM evidence WHERE engagement_id = ? AND asset_id IS NOT NULL) OR engagement_id = ?)`
	args := []interface{}{engagementID, engagementID}
	if len(targets) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(targets)), ",")
		q += ` OR lower(host) IN (` + ph + `) OR lower(domain) IN (` + ph + `) OR lower(ip) IN (` + ph + `)`
		for i := 0; i < 3; i++ {
			for _, t := range targets {
				args = append(args, t)
			}
		}
	}
	rows, err := db.Query(q+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*EngagementAsset{}
	for rows.Next() {
		a := &EngagementAsset{}
		if err := rows.Scan(&a.ID, &a.Host, &a.IP, &a.Domain, &a.Protocol, &a.Title, &a.Criticality, &a.Status, &a.Port); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ToolRunStats aggregates tool executions of the engagement's conversations.
type ToolRunStats struct {
	Total  int
	Failed int            // failed, hard_timeout, blocked, orphaned
	ByTool map[string]int // calls per tool name
}

// EngagementToolStats summarises tool executions run in conversations attached to the engagement.
func (db *DB) EngagementToolStats(engagementID string) (*ToolRunStats, error) {
	rows, err := db.Query(`SELECT tool_name, status FROM tool_executions
		WHERE conversation_id IN (SELECT id FROM conversations WHERE engagement_id = ?)`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	st := &ToolRunStats{ByTool: map[string]int{}}
	for rows.Next() {
		var tool, status string
		if err := rows.Scan(&tool, &status); err != nil {
			return nil, err
		}
		st.Total++
		st.ByTool[tool]++
		switch status {
		case "failed", "hard_timeout", "blocked", "orphaned":
			st.Failed++
		}
	}
	return st, rows.Err()
}

// SortedToolNames returns tool names in alphabetical order.
func (s *ToolRunStats) SortedToolNames() []string {
	names := make([]string, 0, len(s.ByTool))
	for n := range s.ByTool {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
