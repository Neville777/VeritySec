package database

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// InputObservation is a factual note about an uploaded input: what it is and what it contains.
// It is data, not a finding, and carries no conclusion. DataJSON holds counts and short labels
// only, never raw file text.
type InputObservation struct {
	ID           string          `json:"id"`
	InputID      string          `json:"input_id"`
	EngagementID string          `json:"engagement_id"`
	Kind         string          `json:"kind"`
	Summary      string          `json:"summary"`
	Data         json.RawMessage `json:"data"`
	CreatedAt    time.Time       `json:"created_at"`
}

// InsertInputObservations stores all observations for one input in a single transaction.
func (db *DB) InsertInputObservations(inputID, engagementID string, obs []InputObservation) error {
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
		data := string(o.Data)
		if data == "" {
			data = "{}"
		}
		if _, err := tx.Exec(`INSERT INTO input_observations (id, input_id, engagement_id, kind, summary, data_json, created_at)
			VALUES (?,?,?,?,?,?,?)`, uuid.NewString(), inputID, engagementID, o.Kind, o.Summary, data, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListInputObservations returns the observations of one input in insertion order.
func (db *DB) ListInputObservations(inputID string) ([]InputObservation, error) {
	rows, err := db.Query(`SELECT id, input_id, engagement_id, kind, summary, data_json, created_at
		FROM input_observations WHERE input_id = ? ORDER BY created_at, rowid`, inputID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InputObservation{}
	for rows.Next() {
		var o InputObservation
		var data string
		if err := rows.Scan(&o.ID, &o.InputID, &o.EngagementID, &o.Kind, &o.Summary, &data, &o.CreatedAt); err != nil {
			return nil, err
		}
		o.Data = json.RawMessage(data)
		out = append(out, o)
	}
	return out, rows.Err()
}
