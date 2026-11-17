package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Stage task statuses and proposers.
const (
	StageTaskOpen    = "open"
	StageTaskDone    = "done"
	StageTaskSkipped = "skipped"

	StageTaskByModel = "model"
	StageTaskByHuman = "human"
)

// ErrStageTaskNotFound is returned for an unknown stage task ID.
var ErrStageTaskNotFound = errors.New("stage task not found")

// StageTask is one checklist item of an assessment stage.
type StageTask struct {
	ID           string    `json:"id"`
	EngagementID string    `json:"engagement_id"`
	Stage        string    `json:"stage"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Required     bool      `json:"required"`
	Status       string    `json:"status"`
	Reason       string    `json:"reason"`
	ProposedBy   string    `json:"proposed_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// StageTaskInput is the input of CreateStageTask. Required defaults to true when nil.
type StageTaskInput struct {
	Title       string
	Description string
	Required    *bool
	ProposedBy  string
}

const stageTaskColumns = `id, engagement_id, stage, title, description, required, status, reason, proposed_by, created_at, updated_at`

func scanStageTask(row interface{ Scan(...interface{}) error }) (*StageTask, error) {
	var t StageTask
	var req int
	if err := row.Scan(&t.ID, &t.EngagementID, &t.Stage, &t.Title, &t.Description, &req, &t.Status, &t.Reason, &t.ProposedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.Required = req != 0
	return &t, nil
}

// CreateStageTask adds a checklist item to a stage of an engagement.
func (db *DB) CreateStageTask(engagementID, stage string, in StageTaskInput) (*StageTask, error) {
	idx := StageIndex(stage)
	if idx < 0 {
		return nil, ErrStageUnknown
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return nil, &ErrStageInvalid{Msg: "title is required"}
	}
	if len(title) > 300 || len(in.Description) > 5000 {
		return nil, &ErrStageInvalid{Msg: "a field exceeds its length limit"}
	}
	by := in.ProposedBy
	if by != StageTaskByModel && by != StageTaskByHuman {
		return nil, &ErrStageInvalid{Msg: "proposed_by must be model or human"}
	}
	if _, err := db.GetEngagement(engagementID); err != nil {
		return nil, err
	}
	required := 1
	if in.Required != nil && !*in.Required {
		required = 0
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO stage_tasks (id, engagement_id, stage, title, description, required, status, reason, proposed_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'open', '', ?, ?, ?)`,
		id, engagementID, AssessmentStageDefs[idx].Name, title, strings.TrimSpace(in.Description), required, by, now, now); err != nil {
		return nil, err
	}
	return db.GetStageTask(id)
}

// GetStageTask returns one task.
func (db *DB) GetStageTask(id string) (*StageTask, error) {
	t, err := scanStageTask(db.QueryRow(`SELECT `+stageTaskColumns+` FROM stage_tasks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrStageTaskNotFound
	}
	return t, err
}

// StageTaskEngagementID returns the engagement that owns a task (for access checks).
func (db *DB) StageTaskEngagementID(id string) (string, error) {
	var e string
	err := db.QueryRow(`SELECT engagement_id FROM stage_tasks WHERE id = ?`, id).Scan(&e)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrStageTaskNotFound
	}
	return e, err
}

// ListStageTasks lists the tasks of one stage, oldest first.
func (db *DB) ListStageTasks(engagementID, stage string) ([]*StageTask, error) {
	idx := StageIndex(stage)
	if idx < 0 {
		return nil, ErrStageUnknown
	}
	if _, err := db.GetEngagement(engagementID); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT `+stageTaskColumns+` FROM stage_tasks WHERE engagement_id = ? AND stage = ? ORDER BY created_at, id`,
		engagementID, AssessmentStageDefs[idx].Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*StageTask{}
	for rows.Next() {
		t, err := scanStageTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetStageTaskStatus changes a task's status. actorKind is "model" or "human".
// Rules: skipping needs a non-empty reason; a model may change a required task only to 'done'
// (so only a human can skip a required task).
func (db *DB) SetStageTaskStatus(id, status, reason, actorKind string) (*StageTask, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	reason = strings.TrimSpace(reason)
	switch status {
	case StageTaskOpen, StageTaskDone, StageTaskSkipped:
	default:
		return nil, &ErrStageInvalid{Msg: "status must be open, done or skipped"}
	}
	if actorKind != StageTaskByModel && actorKind != StageTaskByHuman {
		return nil, &ErrStageInvalid{Msg: "actor must be model or human"}
	}
	if status == StageTaskSkipped && reason == "" {
		return nil, &ErrStageInvalid{Msg: "a reason is required to skip a task"}
	}
	if len(reason) > 5000 {
		return nil, &ErrStageInvalid{Msg: "reason exceeds its length limit"}
	}
	t, err := db.GetStageTask(id)
	if err != nil {
		return nil, err
	}
	if t.Required && actorKind == StageTaskByModel && status != StageTaskDone {
		return nil, stageConflict("a model may only mark a required task done; a human must %s it", map[bool]string{true: "skip", false: "reopen"}[status == StageTaskSkipped])
	}
	if status != StageTaskSkipped {
		reason = ""
	}
	if _, err := db.Exec(`UPDATE stage_tasks SET status = ?, reason = ?, updated_at = ? WHERE id = ?`, status, reason, time.Now().UTC(), id); err != nil {
		return nil, err
	}
	return db.GetStageTask(id)
}

// openRequiredTaskTitles lists titles of required tasks still open for a stage.
func openRequiredTaskTitles(q interface {
	Query(string, ...interface{}) (*sql.Rows, error)
}, engagementID, stage string) ([]string, error) {
	rows, err := q.Query(`SELECT title FROM stage_tasks WHERE engagement_id = ? AND stage = ? AND required = 1 AND status = 'open' ORDER BY created_at, id`, engagementID, stage)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var titles []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		titles = append(titles, fmt.Sprintf("%q", s))
	}
	return titles, rows.Err()
}
