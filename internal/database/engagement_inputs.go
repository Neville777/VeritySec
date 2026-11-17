package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"veritysec/internal/scope"

	"github.com/google/uuid"
)

// ErrInputNotFound is returned when an engagement input does not exist.
var ErrInputNotFound = errors.New("engagement input not found")

// Indicator statuses. Inserts always use IndicatorDiscovered.
const (
	IndicatorDiscovered = "discovered"
	IndicatorRejected   = "rejected"
	IndicatorAuthorized = "authorized"
)

// EngagementInput is the metadata of one uploaded input. The bytes live on disk.
type EngagementInput struct {
	ID           string          `json:"id"`
	EngagementID string          `json:"engagement_id"`
	OriginalName string          `json:"original_name"`
	DetectedKind string          `json:"detected_kind"`
	MIME         string          `json:"mime"`
	SHA256       string          `json:"sha256"`
	Size         int64           `json:"size"`
	StoragePath  string          `json:"-"` // never exposed over the API
	Confidence   float64         `json:"confidence"`
	Reasons      json.RawMessage `json:"reasons"`
	OCRText      string          `json:"-"` // large; not in list responses
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
}

// InputIndicator is a URL/host/IP found in an input. Authorized is 0 unless the scope engine
// path set it.
type InputIndicator struct {
	ID           string    `json:"id"`
	InputID      string    `json:"input_id"`
	EngagementID string    `json:"engagement_id"`
	Kind         string    `json:"kind"`
	Value        string    `json:"value"`
	ByteOffset   int       `json:"byte_offset"`
	Status       string    `json:"status"`
	Authorized   bool      `json:"authorized"`
	CreatedAt    time.Time `json:"created_at"`
}

// NewInputIndicator builds a discovered, unauthorized indicator.
func NewInputIndicator(kind, value string, offset int) InputIndicator {
	return InputIndicator{Kind: kind, Value: value, ByteOffset: offset, Status: IndicatorDiscovered}
}

// InsertEngagementInput stores the input row and its indicators in one transaction. Whatever
// status a caller put on an indicator is ignored: all start as discovered, authorized=0.
func (db *DB) InsertEngagementInput(in *EngagementInput, indicators []InputIndicator) error {
	if in.ID == "" {
		in.ID = uuid.NewString()
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	if len(in.Reasons) == 0 {
		in.Reasons = json.RawMessage("[]")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO engagement_inputs (id, engagement_id, original_name, detected_kind, mime, sha256, size, storage_path, confidence, reasons_json, ocr_text, created_by, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, in.ID, in.EngagementID, in.OriginalName, in.DetectedKind, in.MIME, in.SHA256, in.Size,
		in.StoragePath, in.Confidence, string(in.Reasons), in.OCRText, in.CreatedBy, in.CreatedAt)
	if err != nil {
		return err
	}
	for _, ind := range indicators {
		_, err = tx.Exec(`INSERT OR IGNORE INTO input_indicators (id, input_id, engagement_id, kind, value, byte_offset, status, authorized, created_at)
			VALUES (?,?,?,?,?,?,?,0,?)`, uuid.NewString(), in.ID, in.EngagementID, ind.Kind, ind.Value, ind.ByteOffset, IndicatorDiscovered, in.CreatedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

const inputColumns = `id, engagement_id, original_name, detected_kind, mime, sha256, size, storage_path, confidence, reasons_json, ocr_text, created_by, created_at`

func scanInput(s interface{ Scan(...interface{}) error }) (*EngagementInput, error) {
	var in EngagementInput
	var reasons string
	if err := s.Scan(&in.ID, &in.EngagementID, &in.OriginalName, &in.DetectedKind, &in.MIME, &in.SHA256, &in.Size,
		&in.StoragePath, &in.Confidence, &reasons, &in.OCRText, &in.CreatedBy, &in.CreatedAt); err != nil {
		return nil, err
	}
	in.Reasons = json.RawMessage(reasons)
	return &in, nil
}

// ListEngagementInputs returns the inputs of one engagement, newest first.
func (db *DB) ListEngagementInputs(engagementID string) ([]*EngagementInput, error) {
	rows, err := db.Query(`SELECT `+inputColumns+` FROM engagement_inputs WHERE engagement_id = ? ORDER BY created_at DESC, id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*EngagementInput{}
	for rows.Next() {
		in, err := scanInput(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// GetEngagementInput loads one input scoped to its engagement, so an ID from another
// engagement is not found.
func (db *DB) GetEngagementInput(engagementID, inputID string) (*EngagementInput, error) {
	in, err := scanInput(db.QueryRow(`SELECT `+inputColumns+` FROM engagement_inputs WHERE engagement_id = ? AND id = ?`, engagementID, inputID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInputNotFound
	}
	return in, err
}

// ListInputIndicators returns the indicators of one input in byte order.
func (db *DB) ListInputIndicators(engagementID, inputID string) ([]InputIndicator, error) {
	rows, err := db.Query(`SELECT id, input_id, engagement_id, kind, value, byte_offset, status, authorized, created_at
		FROM input_indicators WHERE engagement_id = ? AND input_id = ? ORDER BY byte_offset, kind, value`, engagementID, inputID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InputIndicator{}
	for rows.Next() {
		var ind InputIndicator
		var auth int
		if err := rows.Scan(&ind.ID, &ind.InputID, &ind.EngagementID, &ind.Kind, &ind.Value, &ind.ByteOffset, &ind.Status, &auth, &ind.CreatedAt); err != nil {
			return nil, err
		}
		ind.Authorized = auth != 0
		out = append(out, ind)
	}
	return out, rows.Err()
}

// ErrIndicatorNotFound is returned when an input indicator does not exist.
var ErrIndicatorNotFound = errors.New("input indicator not found")

// InputIndicatorEngagementID returns the engagement owning an indicator.
func (db *DB) InputIndicatorEngagementID(indicatorID string) (string, error) {
	var eid string
	err := db.QueryRow(`SELECT engagement_id FROM input_indicators WHERE id = ?`, indicatorID).Scan(&eid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrIndicatorNotFound
	}
	return eid, err
}

// AuthorizeIndicatorViaScope is the ONLY path that sets status 'authorized'. It loads the
// engagement scope and evaluates the indicator value; only IN_SCOPE authorizes. OUT_OF_SCOPE and
// UNKNOWN (including an unparsable scope) leave the indicator 'discovered'. Never called from a
// model path.
func (db *DB) AuthorizeIndicatorViaScope(indicatorID string) (scope.Decision, *InputIndicator, error) {
	var ind InputIndicator
	var auth int
	err := db.QueryRow(`SELECT id, input_id, engagement_id, kind, value, byte_offset, status, authorized, created_at
		FROM input_indicators WHERE id = ?`, indicatorID).Scan(&ind.ID, &ind.InputID, &ind.EngagementID, &ind.Kind, &ind.Value, &ind.ByteOffset, &ind.Status, &auth, &ind.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return scope.Decision{}, nil, ErrIndicatorNotFound
	}
	if err != nil {
		return scope.Decision{}, nil, err
	}
	ind.Authorized = auth != 0
	d := scope.Decision{Result: scope.Unknown, Target: ind.Value}
	e, err := db.GetEngagement(ind.EngagementID)
	if err != nil {
		return scope.Decision{}, nil, err
	}
	sc, perr := scope.Parse(e.ScopeJSON)
	if perr != nil || sc == nil {
		d.Reason = "scope unavailable"
		if perr != nil {
			d.Reason += ": " + perr.Error()
		}
		return d, &ind, nil
	}
	d = scope.Evaluate(sc, ind.Value, time.Now())
	if d.Result != scope.InScope {
		return d, &ind, nil
	}
	if _, err := db.Exec(`UPDATE input_indicators SET status = ?, authorized = 1 WHERE id = ?`, IndicatorAuthorized, ind.ID); err != nil {
		return d, nil, err
	}
	ind.Status, ind.Authorized = IndicatorAuthorized, true
	return d, &ind, nil
}
