package database

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ToolObservation is a deterministic fact extracted from one tool execution's output. It holds
// short labels and values only, never raw output.
type ToolObservation struct {
	ID              string    `json:"id"`
	ToolExecutionID string    `json:"tool_execution_id"`
	EvidenceID      string    `json:"evidence_id"`
	EngagementID    string    `json:"engagement_id"`
	Kind            string    `json:"kind"`
	Subject         string    `json:"subject"`
	Attribute       string    `json:"attribute"`
	Value           string    `json:"value"`
	Confidence      string    `json:"confidence"`
	CreatedAt       time.Time `json:"created_at"`
}

// InsertToolObservations stores all observations of one tool execution in one transaction.
func (db *DB) InsertToolObservations(toolExecutionID, evidenceID, engagementID string, obs []ToolObservation) error {
	if len(obs) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	for _, o := range obs {
		if _, err := tx.Exec(`INSERT INTO tool_observations (id, tool_execution_id, evidence_id, engagement_id, kind, subject, attribute, value, confidence, created_at)
			VALUES (?,?,?,?,?,?,?,?,'deterministic',?)`, uuid.NewString(), toolExecutionID, evidenceID, engagementID, o.Kind, o.Subject, o.Attribute, o.Value, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListToolObservations returns the observations of one tool execution in insertion order.
func (db *DB) ListToolObservations(toolExecutionID string) ([]ToolObservation, error) {
	rows, err := db.Query(`SELECT id, tool_execution_id, evidence_id, engagement_id, kind, subject, attribute, value, confidence, created_at
		FROM tool_observations WHERE tool_execution_id = ? ORDER BY created_at, rowid`, toolExecutionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ToolObservation{}
	for rows.Next() {
		var o ToolObservation
		if err := rows.Scan(&o.ID, &o.ToolExecutionID, &o.EvidenceID, &o.EngagementID, &o.Kind, &o.Subject, &o.Attribute, &o.Value, &o.Confidence, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ToolExecutionEngagementID returns the engagement a tool execution belongs to, resolved through
// its evidence rows or observations; empty when none is linked.
func (db *DB) ToolExecutionEngagementID(toolExecutionID string) (string, error) {
	var id string
	err := db.QueryRow(`SELECT engagement_id FROM (
		SELECT engagement_id FROM evidence WHERE tool_execution_id = ?
		UNION ALL SELECT engagement_id FROM tool_observations WHERE tool_execution_id = ?) LIMIT 1`, toolExecutionID, toolExecutionID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return id, nil
}
