package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Engagement statuses.
const (
	EngagementDraft     = "draft"
	EngagementActive    = "active"
	EngagementPaused    = "paused"
	EngagementCompleted = "completed"
	EngagementArchived  = "archived"
)

// ErrEngagementNotFound is returned when an engagement or a linked record does not exist.
var ErrEngagementNotFound = errors.New("engagement not found")

// ValidEngagementStatus reports whether s is an allowed engagement status.
func ValidEngagementStatus(s string) bool {
	switch s {
	case EngagementDraft, EngagementActive, EngagementPaused, EngagementCompleted, EngagementArchived:
		return true
	}
	return false
}

// Engagement is one authorised assessment: its scope, limits and the records linked to it.
type Engagement struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Objective         string          `json:"objective"`
	Target            string          `json:"target"`
	Status            string          `json:"status"`
	ScopeJSON         json.RawMessage `json:"scope_json"`  // {"included":[...],"excluded":[...]}
	LimitsJSON        json.RawMessage `json:"limits_json"` // free-form object
	AuthorizationNote string          `json:"authorization_note"`
	OwnerUserID       string          `json:"owner_user_id,omitempty"`
	ProjectID         string          `json:"project_id,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

const engagementColumns = `id, name, objective, target, status, scope_json, limits_json, authorization_note, COALESCE(owner_user_id, ''), COALESCE(project_id, ''), created_at, updated_at`

type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanEngagement reads one engagement row selected with engagementColumns.
func scanEngagement(r rowScanner) (*Engagement, error) {
	e := &Engagement{}
	var scope, limits string
	if err := r.Scan(&e.ID, &e.Name, &e.Objective, &e.Target, &e.Status, &scope, &limits, &e.AuthorizationNote, &e.OwnerUserID, &e.ProjectID, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	e.ScopeJSON, e.LimitsJSON = json.RawMessage(scope), json.RawMessage(limits)
	return e, nil
}

// normalizeEngagement fills defaults and validates fields shared by create and update.
func normalizeEngagement(e *Engagement) error {
	e.Name = strings.TrimSpace(e.Name)
	if e.Name == "" {
		return errors.New("name is required")
	}
	if e.Status == "" {
		e.Status = EngagementDraft
	}
	if !ValidEngagementStatus(e.Status) {
		return fmt.Errorf("invalid status %q", e.Status)
	}
	var err error
	if e.ScopeJSON, err = normalizeJSONObject(e.ScopeJSON, "scope_json"); err != nil {
		return err
	}
	if e.LimitsJSON, err = normalizeJSONObject(e.LimitsJSON, "limits_json"); err != nil {
		return err
	}
	return nil
}

// normalizeJSONObject returns "{}" for empty input and rejects anything that is not a JSON object.
func normalizeJSONObject(raw json.RawMessage, field string) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return json.RawMessage("{}"), nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, fmt.Errorf("%s must be a JSON object", field)
	}
	return json.RawMessage(trimmed), nil
}

// CreateEngagement inserts a new engagement and assigns its ID and timestamps.
func (db *DB) CreateEngagement(e *Engagement) (*Engagement, error) {
	if err := normalizeEngagement(e); err != nil {
		return nil, err
	}
	e.ID = uuid.New().String()
	e.CreatedAt = time.Now().UTC()
	e.UpdatedAt = e.CreatedAt
	_, err := db.Exec(`INSERT INTO engagements (id, name, objective, target, status, scope_json, limits_json, authorization_note, owner_user_id, project_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Name, e.Objective, e.Target, e.Status, string(e.ScopeJSON), string(e.LimitsJSON), e.AuthorizationNote, nullIfEmpty(e.OwnerUserID), nullIfEmpty(e.ProjectID), e.CreatedAt, e.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create engagement: %w", err)
	}
	return e, nil
}

// GetEngagement loads one engagement; it returns ErrEngagementNotFound when absent.
func (db *DB) GetEngagement(id string) (*Engagement, error) {
	e, err := scanEngagement(db.QueryRow(`SELECT `+engagementColumns+` FROM engagements WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEngagementNotFound
	}
	return e, err
}

// ListEngagements returns engagements newest first, optionally filtered by status.
func (db *DB) ListEngagements(status string) ([]*Engagement, error) {
	q, args := `SELECT `+engagementColumns+` FROM engagements`, []interface{}{}
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	rows, err := db.Query(q+` ORDER BY created_at DESC, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Engagement{}
	for rows.Next() {
		e, err := scanEngagement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateEngagement replaces the mutable fields of an engagement.
func (db *DB) UpdateEngagement(id string, e *Engagement) (*Engagement, error) {
	if err := normalizeEngagement(e); err != nil {
		return nil, err
	}
	e.UpdatedAt = time.Now().UTC()
	res, err := db.Exec(`UPDATE engagements SET name=?, objective=?, target=?, status=?, scope_json=?, limits_json=?, authorization_note=?, project_id=?, updated_at=? WHERE id=?`,
		e.Name, e.Objective, e.Target, e.Status, string(e.ScopeJSON), string(e.LimitsJSON), e.AuthorizationNote, nullIfEmpty(e.ProjectID), e.UpdatedAt, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrEngagementNotFound
	}
	return db.GetEngagement(id)
}

// DeleteEngagement removes the engagement and its evidence rows, and unlinks conversations and
// findings (their engagement_id becomes NULL; the records themselves are kept). It returns the
// storage paths of the evidence rows so the caller can remove the files.
func (db *DB) DeleteEngagement(id string) ([]string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var paths []string
	rows, err := tx.Query(`SELECT storage_path FROM evidence WHERE engagement_id = ?`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return nil, err
		}
		paths = append(paths, p)
	}
	rows.Close()
	for _, q := range []string{
		`DELETE FROM evidence WHERE engagement_id = ?`,
		`DELETE FROM assessment_stages WHERE engagement_id = ?`,
		`UPDATE conversations SET engagement_id = NULL WHERE engagement_id = ?`,
		`UPDATE vulnerabilities SET engagement_id = NULL WHERE engagement_id = ?`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			return nil, err
		}
	}
	res, err := tx.Exec(`DELETE FROM engagements WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrEngagementNotFound
	}
	return paths, tx.Commit()
}

// ConversationEngagementID returns the engagement a conversation is bound to, or "" when the
// conversation has no engagement (engagement_id is NULL) or does not exist.
func (db *DB) ConversationEngagementID(conversationID string) (string, error) {
	var eid sql.NullString
	err := db.QueryRow(`SELECT engagement_id FROM conversations WHERE id = ?`, conversationID).Scan(&eid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return eid.String, nil
}

// AttachConversationToEngagement links an existing conversation, and the findings recorded in it
// that are not yet in an engagement, to the engagement. Existing conversation and finding data is
// otherwise untouched.
func (db *DB) AttachConversationToEngagement(engagementID, conversationID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM engagements WHERE id = ?`, engagementID).Scan(&n); err != nil || n == 0 {
		if err != nil {
			return err
		}
		return ErrEngagementNotFound
	}
	res, err := tx.Exec(`UPDATE conversations SET engagement_id = ? WHERE id = ?`, engagementID, conversationID)
	if err != nil {
		return err
	}
	if c, _ := res.RowsAffected(); c == 0 {
		return errors.New("conversation not found")
	}
	if _, err := tx.Exec(`UPDATE vulnerabilities SET engagement_id = ? WHERE conversation_id = ? AND COALESCE(engagement_id, '') = ''`, engagementID, conversationID); err != nil {
		return err
	}
	return tx.Commit()
}
