package database

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrReportSnapshotNotFound is returned for an unknown snapshot ID.
var ErrReportSnapshotNotFound = errors.New("report snapshot not found")

// ReportSnapshot is one generated report: the canonical dataset JSON, its hash and the rendered
// file. Rows are insert-only; there is no update or delete path.
type ReportSnapshot struct {
	ID            string    `json:"id"`
	EngagementID  string    `json:"engagement_id"`
	Format        string    `json:"format"`
	Audience      string    `json:"audience"`
	DatasetJSON   string    `json:"-"`
	DatasetSHA256 string    `json:"dataset_sha256"`
	RenderedPath  string    `json:"rendered_path"`
	NarrativeText string    `json:"narrative_text"`
	NarrativeNote string    `json:"narrative_note"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

const reportSnapshotColumns = `id, engagement_id, format, audience, dataset_json, dataset_sha256, rendered_path, narrative_text, narrative_note, created_by, created_at`

// NewReportSnapshotID returns a fresh snapshot ID.
func NewReportSnapshotID() string { return uuid.New().String() }

// CreateReportSnapshot stores a new snapshot. An empty ID gets a fresh one.
func (db *DB) CreateReportSnapshot(s *ReportSnapshot) error {
	if s.ID == "" {
		s.ID = NewReportSnapshotID()
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	s.CreatedAt = s.CreatedAt.UTC()
	_, err := db.Exec(`INSERT INTO report_snapshots (`+reportSnapshotColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		s.ID, s.EngagementID, s.Format, s.Audience, s.DatasetJSON, s.DatasetSHA256, s.RenderedPath, s.NarrativeText, s.NarrativeNote, s.CreatedBy, s.CreatedAt)
	return err
}

// GetReportSnapshot returns one snapshot including its dataset JSON.
func (db *DB) GetReportSnapshot(id string) (*ReportSnapshot, error) {
	s := &ReportSnapshot{}
	err := db.QueryRow(`SELECT `+reportSnapshotColumns+` FROM report_snapshots WHERE id = ?`, id).Scan(
		&s.ID, &s.EngagementID, &s.Format, &s.Audience, &s.DatasetJSON, &s.DatasetSHA256, &s.RenderedPath, &s.NarrativeText, &s.NarrativeNote, &s.CreatedBy, &s.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrReportSnapshotNotFound
	}
	return s, err
}

// ListReportSnapshots returns snapshot metadata (no dataset) for an engagement, newest first.
func (db *DB) ListReportSnapshots(engagementID string) ([]*ReportSnapshot, error) {
	rows, err := db.Query(`SELECT id, engagement_id, format, audience, dataset_sha256, rendered_path, narrative_note, created_by, created_at
		FROM report_snapshots WHERE engagement_id = ? ORDER BY created_at DESC, rowid DESC`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ReportSnapshot{}
	for rows.Next() {
		s := &ReportSnapshot{}
		if err := rows.Scan(&s.ID, &s.EngagementID, &s.Format, &s.Audience, &s.DatasetSHA256, &s.RenderedPath, &s.NarrativeNote, &s.CreatedBy, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
