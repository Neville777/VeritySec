package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// RunEvent is one row of run_events: a durable, ordered event of a run (an assistant message).
// seq is monotonic and gap-free per run. DataJSON never carries tool output.
type RunEvent struct {
	ID             string          `json:"id"`
	RunID          string          `json:"run_id"`
	ConversationID string          `json:"conversation_id,omitempty"`
	EngagementID   string          `json:"engagement_id,omitempty"`
	Seq            int64           `json:"seq"`
	EventType      string          `json:"event_type"`
	Stage          string          `json:"stage,omitempty"`
	Data           json.RawMessage `json:"data"`
	CreatedAt      time.Time       `json:"created_at"`
}

type runEventExecutor interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}

const (
	runEventMaxString = 500
	runEventMaxDepth  = 4
)

// runEventDeniedKeys are keys that carry tool/command output or bulk content; they are dropped.
var runEventDeniedKeys = map[string]bool{
	"result": true, "output": true, "stdout": true, "stderr": true, "content": true, "body": true,
	"response": true, "resultpreview": true, "rawoutput": true, "text": true, "payload": true,
	"delta": true, "data": true,
}

// sanitizeRunEventData returns JSON for data_json with tool output removed: denied keys are
// dropped at every depth and any remaining string is truncated, so a large output can never end
// up in run_events even if a caller passes it under an unexpected key.
func sanitizeRunEventData(data interface{}) string {
	if data == nil {
		return "{}"
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return "{}"
	}
	var v interface{}
	if json.Unmarshal(raw, &v) != nil {
		return "{}"
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return "{}"
	}
	out, err := json.Marshal(scrubRunEventValue(m, 0))
	if err != nil {
		return "{}"
	}
	return string(out)
}

func scrubRunEventValue(v interface{}, depth int) interface{} {
	switch t := v.(type) {
	case string:
		if r := []rune(t); len(r) > runEventMaxString {
			return string(r[:runEventMaxString]) + "..."
		}
		return t
	case map[string]interface{}:
		if depth >= runEventMaxDepth {
			return nil
		}
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			if runEventDeniedKeys[strings.ToLower(k)] {
				continue
			}
			out[k] = scrubRunEventValue(val, depth+1)
		}
		return out
	case []interface{}:
		if depth >= runEventMaxDepth {
			return nil
		}
		if len(t) > 50 {
			t = t[:50]
		}
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = scrubRunEventValue(val, depth+1)
		}
		return out
	default:
		return v
	}
}

// appendRunEvent inserts the event with seq = max(seq)+1 for the run in a single statement, so
// the sequence is computed inside the same transaction/statement that stores the row. ex may be
// a *DB or a *sql.Tx; callers with a surrounding transaction get the event committed with it.
// A UNIQUE(run_id, seq) collision (a concurrent writer) is retried.
func appendRunEvent(ex runEventExecutor, runID, conversationID, engagementID, eventType, stage string, data interface{}) (int64, error) {
	runID = strings.TrimSpace(runID)
	eventType = strings.TrimSpace(eventType)
	if runID == "" || eventType == "" {
		return 0, errors.New("run id and event type are required")
	}
	dataJSON := sanitizeRunEventData(data)
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		var seq int64
		err := ex.QueryRow(`INSERT INTO run_events (id, run_id, conversation_id, engagement_id, seq, event_type, stage, data_json, created_at)
			SELECT ?, ?, ?, ?, COALESCE(MAX(seq), 0) + 1, ?, ?, ?, ? FROM run_events WHERE run_id = ?
			RETURNING seq`,
			uuid.New().String(), runID, nullIfEmpty(conversationID), nullIfEmpty(engagementID), eventType, nullIfEmpty(stage), dataJSON, time.Now().UTC(), runID).Scan(&seq)
		if err == nil {
			return seq, nil
		}
		lastErr = err
		if !strings.Contains(err.Error(), "UNIQUE") {
			break
		}
	}
	return 0, lastErr
}

// AppendRunEvent persists one run event and returns its seq. Publish to any live hub only after
// this returns without error.
func (db *DB) AppendRunEvent(runID, conversationID, engagementID, eventType, stage string, data interface{}) (int64, error) {
	return appendRunEvent(db, runID, conversationID, engagementID, eventType, stage, data)
}

// AppendRunEventBestEffort appends an event for a run when the caller does not know the run ID:
// it uses the latest message of the conversation, which is the running assistant message for an
// active run. This is best-effort; if a newer message was added in between, the event is
// attributed to that message. Returns 0 when there is no run to attach to or on failure.
func (db *DB) AppendRunEventBestEffort(runID, conversationID, engagementID, eventType, stage string, data interface{}) int64 {
	if strings.TrimSpace(runID) == "" {
		runID, _ = db.LatestMessageIDForConversation(conversationID)
	}
	if strings.TrimSpace(runID) == "" {
		return 0
	}
	seq, err := db.AppendRunEvent(runID, conversationID, engagementID, eventType, stage, data)
	if err != nil {
		return 0
	}
	return seq
}

// ListRunEvents returns events with seq > afterSeq in order, at most limit (default 500, max 2000).
func (db *DB) ListRunEvents(runID string, afterSeq int64, limit int) ([]RunEvent, error) {
	if limit <= 0 {
		limit = 500
	}
	if limit > 2000 {
		limit = 2000
	}
	rows, err := db.Query(`SELECT id, run_id, COALESCE(conversation_id,''), COALESCE(engagement_id,''), seq, event_type, COALESCE(stage,''), COALESCE(data_json,'{}'), created_at
		FROM run_events WHERE run_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?`, strings.TrimSpace(runID), afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RunEvent{}
	for rows.Next() {
		var e RunEvent
		var data string
		if err := rows.Scan(&e.ID, &e.RunID, &e.ConversationID, &e.EngagementID, &e.Seq, &e.EventType, &e.Stage, &data, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Data = json.RawMessage(data)
		out = append(out, e)
	}
	return out, rows.Err()
}
