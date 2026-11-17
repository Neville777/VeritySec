package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Checkpoint kinds. A checkpoint is pure bookkeeping: its data_json holds IDs only (a tool
// execution ID, an evidence ID, a stage name, a sequence number) and never tool output or other
// content. Checkpoints are written through the same functions that already record the underlying
// event (TransitionAssessmentStage, the engagement tool-result evidence recorder, and the stage
// failed/interrupted marks) — there is no separate event system.
const (
	CheckpointKindStageStart       = "stage_start"
	CheckpointKindStageComplete    = "stage_complete"
	CheckpointKindStageFailed      = "stage_failed"
	CheckpointKindStageInterrupted = "stage_interrupted"
	CheckpointKindToolExecution    = "tool_execution"
	CheckpointKindStageReview      = "stage_review_triggered"
)

// RunCheckpoint is one row of run_checkpoints.
type RunCheckpoint struct {
	ID             string    `json:"id"`
	MessageID      string    `json:"message_id,omitempty"`
	ConversationID string    `json:"conversation_id,omitempty"`
	EngagementID   string    `json:"engagement_id,omitempty"`
	Stage          string    `json:"stage,omitempty"`
	Kind           string    `json:"kind"`
	CreatedAt      time.Time `json:"created_at"`
	DataJSON       string    `json:"data_json,omitempty"`
}

type checkpointExecutor interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// writeRunCheckpoint inserts one checkpoint row through ex (either *DB or a transaction), so
// callers that must keep the checkpoint in the same transaction as the event it records can do
// so. messageID, conversationID, engagementID and stage are all optional (stored as NULL when
// blank); kind is required. data must hold IDs only.
func writeRunCheckpoint(ex checkpointExecutor, messageID, conversationID, engagementID, stage, kind string, data map[string]interface{}) error {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return errors.New("checkpoint kind is required")
	}
	if data == nil {
		data = map[string]interface{}{}
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = ex.Exec(`INSERT INTO run_checkpoints (id, message_id, conversation_id, engagement_id, stage, kind, created_at, data_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), nullIfEmpty(messageID), nullIfEmpty(conversationID), nullIfEmpty(engagementID), nullIfEmpty(stage), kind, time.Now().UTC(), string(b))
	if err != nil {
		return err
	}
	// Mirror into run_events inside the same executor (transaction). When the caller does not
	// know the run/message ID this falls back to the conversation's latest message: best-effort,
	// it can be the wrong message if a newer one was added meanwhile. With no run at all, skip.
	runID := strings.TrimSpace(messageID)
	if runID == "" && strings.TrimSpace(conversationID) != "" {
		_ = ex.QueryRow(`SELECT id FROM messages WHERE conversation_id = ? ORDER BY created_at DESC, id DESC LIMIT 1`, conversationID).Scan(&runID)
	}
	if runID != "" {
		if _, err := appendRunEvent(ex, runID, conversationID, engagementID, kind, stage, data); err != nil {
			return err
		}
	}
	return nil
}

// WriteRunCheckpoint records a durable checkpoint outside of any other transaction. See
// writeRunCheckpoint for the field rules.
func (db *DB) WriteRunCheckpoint(messageID, conversationID, engagementID, stage, kind string, data map[string]interface{}) error {
	return writeRunCheckpoint(db, messageID, conversationID, engagementID, stage, kind, data)
}

// ListRunCheckpoints returns the checkpoints recorded for one run (one assistant message), oldest
// first.
func (db *DB) ListRunCheckpoints(messageID string) ([]RunCheckpoint, error) {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return []RunCheckpoint{}, nil
	}
	rows, err := db.Query(`SELECT id, COALESCE(message_id,''), COALESCE(conversation_id,''), COALESCE(engagement_id,''), COALESCE(stage,''), kind, created_at, COALESCE(data_json,'{}')
		FROM run_checkpoints WHERE message_id = ? ORDER BY created_at ASC, id ASC`, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunCheckpoint{}
	for rows.Next() {
		var c RunCheckpoint
		if err := rows.Scan(&c.ID, &c.MessageID, &c.ConversationID, &c.EngagementID, &c.Stage, &c.Kind, &c.CreatedAt, &c.DataJSON); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LatestMessageIDForConversation returns the most recently created message of a conversation
// (empty when the conversation has none), used to best-effort attribute a checkpoint written
// mid-run to the run's assistant message when the caller has only the conversation ID.
func (db *DB) LatestMessageIDForConversation(conversationID string) (string, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return "", nil
	}
	var id string
	err := db.QueryRow(`SELECT id FROM messages WHERE conversation_id = ? ORDER BY created_at DESC, id DESC LIMIT 1`, conversationID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// ResumeExecution is one tool execution named in a resume plan.
type ResumeExecution struct {
	ExecutionID string `json:"execution_id"`
	ToolName    string `json:"tool_name"`
	Status      string `json:"status"`
}

// ResumePlanResult is the read-only answer to "what would resuming this run mean". It never runs
// anything; it is bookkeeping only.
type ResumePlanResult struct {
	MessageID string `json:"message_id"`
	// LastCompletedStage is the most recently completed stage recorded by a checkpoint of this
	// run (empty when none was completed in it).
	LastCompletedStage string `json:"last_completed_stage,omitempty"`
	// ResumeStage is the stage to resume: the most recent stage_start/stage_failed/
	// stage_interrupted checkpoint of this run, or LastCompletedStage when there is none.
	ResumeStage string `json:"resume_stage,omitempty"`
	// CompletedExecutions are tool executions that finished (any end state) inside the run window;
	// they must not be repeated.
	CompletedExecutions []ResumeExecution `json:"completed_executions"`
	// UnknownExecutions are tool executions that started inside the run window and have no
	// completion record. They must be treated as unknown outcome and must not be silently re-run;
	// they are returned for a human decision.
	UnknownExecutions []ResumeExecution `json:"unknown_executions"`
	// AutoResumable is true only when UnknownExecutions is empty.
	AutoResumable bool `json:"auto_resumable"`
}

// toolExecutionIsFinished reports whether a tool_executions.status value names an execution that
// has actually finished (one way or another), as opposed to one still in flight.
func toolExecutionIsFinished(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "failed", "blocked", "cancelled", "canceled", "hard_timeout", "orphaned":
		return true
	default:
		return false
	}
}

// ResumePlan reads the checkpoints and the tool_executions recorded for the run (one assistant
// message) and reports, read-only, what resuming it would mean: the last completed stage, the
// stage to resume, which tool executions completed (must not be repeated), which started but have
// no completion record (unknown outcome, must not be silently re-run), and whether the run may be
// resumed automatically (true only when there are no unknown executions). It adds no way to run
// anything.
func (db *DB) ResumePlan(messageID string) (*ResumePlanResult, error) {
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
	endedAt, _, err := db.deriveRunEndAndStatus(events, engagementID)
	if err != nil {
		return nil, err
	}

	checkpoints, err := db.ListRunCheckpoints(messageID)
	if err != nil {
		return nil, err
	}
	result := &ResumePlanResult{MessageID: messageID, CompletedExecutions: []ResumeExecution{}, UnknownExecutions: []ResumeExecution{}}
	for _, cp := range checkpoints {
		switch cp.Kind {
		case CheckpointKindStageComplete:
			if cp.Stage != "" {
				result.LastCompletedStage = cp.Stage
			}
		case CheckpointKindStageStart, CheckpointKindStageFailed, CheckpointKindStageInterrupted:
			if cp.Stage != "" {
				result.ResumeStage = cp.Stage
			}
		}
	}
	if result.ResumeStage == "" {
		result.ResumeStage = result.LastCompletedStage
	}

	tools, err := db.runToolExecutions(conversationID, startedAt, endedAt)
	if err != nil {
		return nil, err
	}
	for _, t := range tools {
		re := ResumeExecution{ExecutionID: t.ExecutionID, ToolName: t.ToolName, Status: t.Status}
		if toolExecutionIsFinished(t.Status) {
			result.CompletedExecutions = append(result.CompletedExecutions, re)
		} else {
			result.UnknownExecutions = append(result.UnknownExecutions, re)
		}
	}
	result.AutoResumable = len(result.UnknownExecutions) == 0
	return result, nil
}
