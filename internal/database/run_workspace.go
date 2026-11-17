package database

import (
	"database/sql"
	"regexp"
	"strings"
	"time"
)

// A run is one assistant message: the window from the message's creation to its "done" event (or
// the last event recorded, if the run ended without one). This file assembles a read-only view of
// everything recorded inside that window for GET /api/runs/:messageId/workspace.

// billingFailurePattern matches an HTTP 402 or an "insufficient balance" style message,
// case-insensitively, in a timeline step's text.
var billingFailurePattern = regexp.MustCompile(`(?i)\b402\b|insufficient[ _]?balance|payment\s+required`)

// IsBillingFailureText reports whether s reads as an HTTP 402 or an "insufficient balance" style
// failure. Exported so the handler layer can classify a run-ending error the same way this file
// classifies a timeline step, without duplicating the pattern.
func IsBillingFailureText(s string) bool { return billingFailurePattern.MatchString(s) }

// RunRow is the run's identity, status and time window.
type RunRow struct {
	MessageID      string     `json:"message_id"`
	ConversationID string     `json:"conversation_id"`
	EngagementID   string     `json:"engagement_id,omitempty"`
	Status         string     `json:"status"`
	StartedAt      time.Time  `json:"started_at"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	DurationMs     *int64     `json:"duration_ms,omitempty"`
}

// RunTimelineEvent is one process_details row.
type RunTimelineEvent struct {
	Seq       int       `json:"seq"`
	EventType string    `json:"event_type"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// RunToolExecution is one tool_executions row that started inside the run window.
type RunToolExecution struct {
	ExecutionID string    `json:"execution_id"`
	ToolName    string    `json:"tool_name"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	DurationMs  *int64    `json:"duration_ms,omitempty"`
}

// RunEvidenceRow is one evidence row attributed to the run.
type RunEvidenceRow struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Title           string `json:"title"`
	Origin          string `json:"origin"`
	ToolExecutionID string `json:"tool_execution_id,omitempty"`
	Stage           string `json:"stage,omitempty"`
	SHA256          string `json:"sha256"`
}

// RunFindingRow is one vulnerability recorded in the run's conversation.
type RunFindingRow struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
}

// RunAssetRow is one asset attributed to the run.
type RunAssetRow struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// RunModelUsage is the token usage attributed to the run.
type RunModelUsage struct {
	Calls            int64 `json:"calls"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	CachedTokens     int64 `json:"cached_tokens"`
}

// RunDiscoveries counts the rows surfaced by the run.
type RunDiscoveries struct {
	Assets   int `json:"assets"`
	Findings int `json:"findings"`
	Evidence int `json:"evidence"`
}

// RunWorkspace is the full read model returned by GET /api/runs/:messageId/workspace.
type RunWorkspace struct {
	Run         RunRow             `json:"run"`
	Timeline    []RunTimelineEvent `json:"timeline"`
	Tools       []RunToolExecution `json:"tools"`
	Evidence    []RunEvidenceRow   `json:"evidence"`
	Findings    []RunFindingRow    `json:"findings"`
	Assets      []RunAssetRow      `json:"assets"`
	Model       RunModelUsage      `json:"model"`
	Discoveries RunDiscoveries     `json:"discoveries"`
}

// GetRunWorkspace assembles the run read model for the assistant message messageID. It returns
// sql.ErrNoRows when no such message exists.
func (db *DB) GetRunWorkspace(messageID string) (*RunWorkspace, error) {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return nil, sql.ErrNoRows
	}
	var conversationID string
	var startedAt time.Time
	if err := db.QueryRow(`SELECT conversation_id, created_at FROM messages WHERE id = ?`, messageID).Scan(&conversationID, &startedAt); err != nil {
		return nil, err
	}
	engagementID, err := db.ConversationEngagementID(conversationID)
	if err != nil {
		return nil, err
	}

	events, err := db.runTimelineEvents(messageID)
	if err != nil {
		return nil, err
	}

	endedAt, status, err := db.deriveRunEndAndStatus(events, engagementID)
	if err != nil {
		return nil, err
	}

	var durationMs *int64
	if endedAt != nil {
		d := endedAt.Sub(startedAt).Milliseconds()
		if d < 0 {
			d = 0
		}
		durationMs = &d
	}

	tools, err := db.runToolExecutions(conversationID, startedAt, endedAt)
	if err != nil {
		return nil, err
	}
	toolIDs := make([]string, 0, len(tools))
	for _, t := range tools {
		toolIDs = append(toolIDs, t.ExecutionID)
	}

	evidence, err := db.runEvidenceRows(engagementID, toolIDs, startedAt, endedAt)
	if err != nil {
		return nil, err
	}
	findings, err := db.runFindingRows(conversationID)
	if err != nil {
		return nil, err
	}
	assets, err := db.runAssetRows(conversationID, engagementID)
	if err != nil {
		return nil, err
	}
	model, err := db.runModelUsage(conversationID, messageID, startedAt, endedAt)
	if err != nil {
		return nil, err
	}

	return &RunWorkspace{
		Run: RunRow{
			MessageID: messageID, ConversationID: conversationID, EngagementID: engagementID,
			Status: status, StartedAt: startedAt, EndedAt: endedAt, DurationMs: durationMs,
		},
		Timeline:    events,
		Tools:       tools,
		Evidence:    evidence,
		Findings:    findings,
		Assets:      assets,
		Model:       model,
		Discoveries: RunDiscoveries{Assets: len(assets), Findings: len(findings), Evidence: len(evidence)},
	}, nil
}

// runTimelineEvents loads every process_details row for the message, oldest first, then keeps
// only the newest 1000 when there are more (seq is assigned after trimming).
func (db *DB) runTimelineEvents(messageID string) ([]RunTimelineEvent, error) {
	rows, err := db.Query(`SELECT event_type, message, created_at FROM process_details WHERE message_id = ? ORDER BY created_at, id`, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all []RunTimelineEvent
	for rows.Next() {
		var ev RunTimelineEvent
		var msg sql.NullString
		if err := rows.Scan(&ev.EventType, &msg, &ev.CreatedAt); err != nil {
			return nil, err
		}
		ev.Message = msg.String
		all = append(all, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(all) > 1000 {
		all = all[len(all)-1000:]
	}
	out := make([]RunTimelineEvent, len(all))
	for i, ev := range all {
		ev.Seq = i + 1
		out[i] = ev
	}
	return out, nil
}

// deriveRunEndAndStatus derives the run's end time (if any) and status from its timeline.
//
// "running" when no "done" event is present and nothing has gone wrong; "interrupted" when a
// cancelled/timeout/error event exists, or a step message reads as an HTTP 402 or insufficient
// balance failure (checked across every event, regardless of "done"); "completed" when "done" is
// present and nothing is interrupted; "completed_with_unresolved" when completed but the run's
// engagement has an assessment stage left blocked or needing review.
func (db *DB) deriveRunEndAndStatus(events []RunTimelineEvent, engagementID string) (*time.Time, string, error) {
	var doneAt *time.Time
	var lastAt time.Time
	interrupted := false
	for _, e := range events {
		if e.CreatedAt.After(lastAt) {
			lastAt = e.CreatedAt
		}
		switch strings.ToLower(strings.TrimSpace(e.EventType)) {
		case "done":
			if doneAt == nil {
				t := e.CreatedAt
				doneAt = &t
			}
		case "cancelled", "canceled", "timeout", "error", "hard_timeout":
			interrupted = true
		}
		if billingFailurePattern.MatchString(e.Message) {
			interrupted = true
		}
	}
	if !interrupted {
		// Consistency with the stage recovery state: when the engagement's current stage was
		// itself marked interrupted (billing failure, cancellation, timeout or an unrecoverable
		// error while it was running), the run is interrupted even if this run's own timeline
		// carried none of those markers (for example, the run ended before any event was
		// recorded). This does not change the priority of the checks above; it only adds another
		// way to reach the same "interrupted" branch.
		stageInterrupted, err := db.engagementHasStageStatus(engagementID, StageInterrupted)
		if err != nil {
			return nil, "", err
		}
		interrupted = stageInterrupted
	}
	if interrupted {
		if doneAt != nil {
			return doneAt, "interrupted", nil
		}
		if !lastAt.IsZero() {
			return &lastAt, "interrupted", nil
		}
		return nil, "interrupted", nil
	}
	if doneAt == nil {
		return nil, "running", nil
	}
	unresolved, err := db.engagementHasUnresolvedStage(engagementID)
	if err != nil {
		return nil, "", err
	}
	if unresolved {
		return doneAt, "completed_with_unresolved", nil
	}
	return doneAt, "completed", nil
}

// engagementHasUnresolvedStage reports whether the engagement has an assessment stage left
// blocked or needing review. It returns false, not an error, when there is no engagement.
func (db *DB) engagementHasUnresolvedStage(engagementID string) (bool, error) {
	engagementID = strings.TrimSpace(engagementID)
	if engagementID == "" {
		return false, nil
	}
	stages, err := loadStages(db, engagementID)
	if err != nil {
		return false, err
	}
	for _, s := range stages {
		if s.Status == StageBlocked || s.Status == StageNeedsReview {
			return true, nil
		}
	}
	return false, nil
}

// engagementHasStageStatus reports whether the engagement has an assessment stage currently in
// the given status. It returns false, not an error, when there is no engagement.
func (db *DB) engagementHasStageStatus(engagementID, status string) (bool, error) {
	engagementID = strings.TrimSpace(engagementID)
	if engagementID == "" {
		return false, nil
	}
	stages, err := loadStages(db, engagementID)
	if err != nil {
		return false, err
	}
	for _, s := range stages {
		if s.Status == status {
			return true, nil
		}
	}
	return false, nil
}

// runToolExecutions returns tool_executions for the conversation that started inside the run
// window, oldest first, capped at 500.
func (db *DB) runToolExecutions(conversationID string, startedAt time.Time, endedAt *time.Time) ([]RunToolExecution, error) {
	query := `SELECT id, tool_name, status, start_time, duration_ms FROM tool_executions WHERE conversation_id = ? AND start_time >= ?`
	args := []interface{}{conversationID, startedAt}
	if endedAt != nil {
		query += ` AND start_time <= ?`
		args = append(args, *endedAt)
	}
	query += ` ORDER BY start_time ASC, id ASC LIMIT 500`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunToolExecution{}
	for rows.Next() {
		var t RunToolExecution
		var dur sql.NullInt64
		if err := rows.Scan(&t.ExecutionID, &t.ToolName, &t.Status, &t.StartedAt, &dur); err != nil {
			return nil, err
		}
		if dur.Valid {
			d := dur.Int64
			t.DurationMs = &d
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// runEvidenceRows returns evidence for the run's engagement whose tool_execution_id names one of
// the run's tools, or that has no tool_execution_id and was created inside the run window.
func (db *DB) runEvidenceRows(engagementID string, toolIDs []string, startedAt time.Time, endedAt *time.Time) ([]RunEvidenceRow, error) {
	engagementID = strings.TrimSpace(engagementID)
	if engagementID == "" {
		return []RunEvidenceRow{}, nil
	}
	conds := make([]string, 0, 2)
	args := []interface{}{engagementID}
	if len(toolIDs) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(toolIDs)), ",")
		conds = append(conds, "tool_execution_id IN ("+placeholders+")")
		for _, id := range toolIDs {
			args = append(args, id)
		}
	}
	windowCond := "(tool_execution_id IS NULL AND created_at >= ?"
	args = append(args, startedAt)
	if endedAt != nil {
		windowCond += " AND created_at <= ?"
		args = append(args, *endedAt)
	}
	windowCond += ")"
	conds = append(conds, windowCond)

	query := `SELECT id, kind, title, origin, COALESCE(tool_execution_id,''), COALESCE(stage,''), sha256 FROM evidence
		WHERE engagement_id = ? AND (` + strings.Join(conds, " OR ") + `) ORDER BY created_at ASC, id ASC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunEvidenceRow{}
	for rows.Next() {
		var r RunEvidenceRow
		if err := rows.Scan(&r.ID, &r.Kind, &r.Title, &r.Origin, &r.ToolExecutionID, &r.Stage, &r.SHA256); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// runFindingRows returns vulnerabilities recorded directly in the run's conversation.
func (db *DB) runFindingRows(conversationID string) ([]RunFindingRow, error) {
	rows, err := db.Query(`SELECT id, title, severity, status, COALESCE(confidence, 'potential') FROM vulnerabilities WHERE conversation_id = ? ORDER BY id`, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunFindingRow{}
	for rows.Next() {
		var r RunFindingRow
		if err := rows.Scan(&r.ID, &r.Title, &r.Severity, &r.Status, &r.Confidence); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// runAssetRows returns assets attributed to the run. Assets carry no conversation_id, so the
// conversation match uses the asset's most recently recorded scan conversation; combined with the
// engagement match, this linkage is approximate, not an exact accounting of what this run touched.
func (db *DB) runAssetRows(conversationID, engagementID string) ([]RunAssetRow, error) {
	query := `SELECT id, host, ip, port FROM assets WHERE COALESCE(last_scan_conversation_id, '') = ?`
	args := []interface{}{conversationID}
	if strings.TrimSpace(engagementID) != "" {
		query += ` OR (engagement_id IS NOT NULL AND engagement_id = ?)`
		args = append(args, engagementID)
	}
	query += ` ORDER BY id`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunAssetRow{}
	for rows.Next() {
		var r RunAssetRow
		if err := rows.Scan(&r.ID, &r.Host, &r.IP, &r.Port); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// runModelUsage prefers model_call_usage for the conversation within the run window; when no
// per-call rows exist there (not every call is persisted that way), it falls back to the
// per-message usage summary in model_token_usage.
func (db *DB) runModelUsage(conversationID, messageID string, startedAt time.Time, endedAt *time.Time) (RunModelUsage, error) {
	if err := db.ensureModelCallUsage(); err != nil {
		return RunModelUsage{}, err
	}
	query := `SELECT COUNT(*), COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0), COALESCE(SUM(cached_tokens),0)
		FROM model_call_usage WHERE conversation_id = ? AND created_at >= ?`
	args := []interface{}{conversationID, startedAt}
	if endedAt != nil {
		query += ` AND created_at <= ?`
		args = append(args, *endedAt)
	}
	var calls, prompt, completion, cached int64
	if err := db.QueryRow(query, args...).Scan(&calls, &prompt, &completion, &cached); err != nil {
		return RunModelUsage{}, err
	}
	if calls > 0 {
		return RunModelUsage{Calls: calls, PromptTokens: prompt, CompletionTokens: completion, CachedTokens: cached}, nil
	}
	var mCalls, mPrompt, mCompletion, mCached int64
	if err := db.QueryRow(`SELECT COALESCE(SUM(model_calls),0), COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0), COALESCE(SUM(cached_tokens),0)
		FROM model_token_usage WHERE message_id = ?`, messageID).Scan(&mCalls, &mPrompt, &mCompletion, &mCached); err != nil {
		return RunModelUsage{}, err
	}
	return RunModelUsage{Calls: mCalls, PromptTokens: mPrompt, CompletionTokens: mCompletion, CachedTokens: mCached}, nil
}
