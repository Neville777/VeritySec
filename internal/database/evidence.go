package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Evidence kinds.
const (
	EvidenceHTTPExchange = "http_exchange"
	EvidenceToolOutput   = "tool_output"
	EvidenceScreenshot   = "screenshot"
	EvidenceNote         = "note"
	EvidenceOther        = "other"
)

// Evidence origins. Only the tool-result recorder may create origin "tool" rows; the HTTP upload
// path always stores "manual".
const (
	EvidenceOriginTool   = "tool"
	EvidenceOriginManual = "manual"
)

// MaxEvidenceBytes bounds a single evidence item.
const MaxEvidenceBytes = 25 << 20

// Integrity results reported when evidence content is read back.
var (
	ErrEvidenceNotFound     = errors.New("evidence not found")
	ErrEvidenceHashMismatch = errors.New("evidence content does not match its recorded sha256")
	ErrEvidenceMissing      = errors.New("evidence file is missing")
	// ErrEvidencePurged means the stored file was deleted by the retention rule. The database
	// row and its original sha256 remain.
	ErrEvidencePurged = errors.New("evidence file was purged by the retention policy")
)

// ValidEvidenceKind reports whether k is an allowed kind.
func ValidEvidenceKind(k string) bool {
	switch k {
	case EvidenceHTTPExchange, EvidenceToolOutput, EvidenceScreenshot, EvidenceNote, EvidenceOther:
		return true
	}
	return false
}

// IsTextEvidenceKind reports whether content of this kind may be returned inline as text.
func IsTextEvidenceKind(k string) bool {
	return k == EvidenceHTTPExchange || k == EvidenceToolOutput || k == EvidenceNote
}

// Evidence is the metadata of one stored artefact. Content lives on disk; only its hash and
// path (relative to the evidence root) are stored in the database.
type Evidence struct {
	ID           string    `json:"id"`
	EngagementID string    `json:"engagement_id"`
	FindingID    string    `json:"finding_id,omitempty"`
	AssetID      string    `json:"asset_id,omitempty"`
	Kind         string    `json:"kind"`
	SourceTool   string    `json:"source_tool,omitempty"`
	Title        string    `json:"title"`
	StoragePath  string    `json:"storage_path"`
	SHA256       string    `json:"sha256"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	// Origin is "tool" (recorded from a tool result) or "manual" (uploaded over HTTP).
	Origin string `json:"origin"`
	// ToolExecutionID is the MCP execution ID of the producing tool call; empty (stored as NULL)
	// when the result carried none or the row is manual.
	ToolExecutionID string `json:"tool_execution_id"`
	// Stage is the engagement stage that was current when the row was created; empty when every
	// stage was already terminal.
	Stage string `json:"stage"`
	// StorageDeleted is true once the retention rule removed the stored file. The row and the
	// original SHA256 are kept so integrity history survives.
	StorageDeleted bool `json:"storage_deleted"`
}

const evidenceColumns = `id, engagement_id, COALESCE(finding_id, ''), COALESCE(asset_id, ''), kind, source_tool, title, storage_path, sha256, size_bytes, created_at, origin, COALESCE(tool_execution_id, ''), COALESCE(stage, ''), COALESCE(storage_deleted, 0)`

func scanEvidence(r rowScanner) (*Evidence, error) {
	e := &Evidence{}
	var deleted int
	err := r.Scan(&e.ID, &e.EngagementID, &e.FindingID, &e.AssetID, &e.Kind, &e.SourceTool, &e.Title, &e.StoragePath, &e.SHA256, &e.SizeBytes, &e.CreatedAt, &e.Origin, &e.ToolExecutionID, &e.Stage, &deleted)
	e.StorageDeleted = deleted != 0
	return e, err
}

// EvidenceStore keeps evidence content on disk under Root/<engagement_id>/<evidence_id>.
type EvidenceStore struct{ Root string }

// resolve maps a stored relative path to an absolute one and refuses anything outside Root.
func (s *EvidenceStore) resolve(rel string) (string, error) {
	root, err := filepath.Abs(s.Root)
	if err != nil {
		return "", err
	}
	full := filepath.Join(root, filepath.FromSlash(rel))
	if r, err := filepath.Rel(root, full); err != nil || r == "." || strings.HasPrefix(r, "..") {
		return "", errors.New("evidence path escapes the evidence directory")
	}
	return full, nil
}

// Save writes content with 0600 permissions and returns its relative path, hash and size.
func (s *EvidenceStore) Save(engagementID, evidenceID string, content []byte) (rel, sum string, size int64, err error) {
	if len(content) > MaxEvidenceBytes {
		return "", "", 0, fmt.Errorf("evidence exceeds %d bytes", MaxEvidenceBytes)
	}
	rel = engagementID + "/" + evidenceID
	full, err := s.resolve(rel)
	if err != nil {
		return "", "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return "", "", 0, err
	}
	if err := os.WriteFile(full, content, 0o600); err != nil {
		return "", "", 0, err
	}
	h := sha256.Sum256(content)
	return rel, hex.EncodeToString(h[:]), int64(len(content)), nil
}

// Read returns the stored content after verifying its sha256. On a mismatch it returns
// ErrEvidenceHashMismatch and no content.
func (s *EvidenceStore) Read(ev *Evidence) ([]byte, error) {
	if ev.StorageDeleted {
		return nil, ErrEvidencePurged
	}
	full, err := s.resolve(ev.StoragePath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrEvidenceMissing
	}
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != ev.SHA256 {
		return nil, ErrEvidenceHashMismatch
	}
	return data, nil
}

// Remove deletes stored files for the given relative paths, ignoring files already gone.
func (s *EvidenceStore) Remove(rels []string) {
	for _, rel := range rels {
		if full, err := s.resolve(rel); err == nil {
			_ = os.Remove(full)
		}
	}
}

// NewEvidenceRecord prepares an Evidence row for the engagement with a fresh ID.
func NewEvidenceRecord(engagementID string) *Evidence {
	return &Evidence{ID: uuid.New().String(), EngagementID: engagementID, CreatedAt: time.Now().UTC()}
}

// InsertEvidence validates references and stores the evidence row. The finding must belong to
// the engagement; the asset must exist.
func (db *DB) InsertEvidence(e *Evidence) error {
	if !ValidEvidenceKind(e.Kind) {
		return fmt.Errorf("invalid kind %q", e.Kind)
	}
	if e.FindingID != "" {
		ok, err := db.findingInEngagement(e.EngagementID, e.FindingID)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("finding_id is not part of this engagement")
		}
	}
	if e.AssetID != "" {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE id = ?`, e.AssetID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return errors.New("asset_id not found")
		}
	}
	if e.Origin == "" {
		e.Origin = EvidenceOriginManual
	}
	if e.Origin != EvidenceOriginTool && e.Origin != EvidenceOriginManual {
		return fmt.Errorf("invalid origin %q", e.Origin)
	}
	if e.Stage == "" {
		// The stage that is running now: the first one that is not completed or skipped.
		if stages, err := loadStages(db, e.EngagementID); err == nil {
			if cur := CurrentStage(stages); cur != nil {
				e.Stage = cur.Stage
			}
		}
	}
	_, err := db.Exec(`INSERT INTO evidence (id, engagement_id, finding_id, asset_id, kind, source_tool, title, storage_path, sha256, size_bytes, created_at, origin, tool_execution_id, stage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.EngagementID, nullIfEmpty(e.FindingID), nullIfEmpty(e.AssetID), e.Kind, e.SourceTool, e.Title, e.StoragePath, e.SHA256, e.SizeBytes, e.CreatedAt,
		e.Origin, nullIfEmpty(e.ToolExecutionID), nullIfEmpty(e.Stage))
	if err != nil {
		return err
	}
	// New tool evidence for a completed stage sends it to review. A marking failure never fails
	// the evidence write; it is only logged.
	if e.Origin == EvidenceOriginTool {
		if rerr := db.ReviewStageForNewItem(e.EngagementID, e.Stage, "tool evidence", e.ID); rerr != nil {
			log.Printf("stage review after evidence %s failed: %v", e.ID, rerr)
		}
	}
	return nil
}

// findingInEngagement reports whether a vulnerability is linked to the engagement directly or
// through one of its conversations.
func (db *DB) findingInEngagement(engagementID, findingID string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE id = ? AND `+findingInEngagementSQL, findingID, engagementID, engagementID).Scan(&n)
	return n > 0, err
}

// GetEvidence loads evidence metadata.
func (db *DB) GetEvidence(id string) (*Evidence, error) {
	e, err := scanEvidence(db.QueryRow(`SELECT `+evidenceColumns+` FROM evidence WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEvidenceNotFound
	}
	return e, err
}

// EvidenceEngagementID returns the engagement an evidence item belongs to.
func (db *DB) EvidenceEngagementID(id string) (string, error) {
	var eid string
	err := db.QueryRow(`SELECT engagement_id FROM evidence WHERE id = ?`, id).Scan(&eid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrEvidenceNotFound
	}
	return eid, err
}

// EvidenceOriginRef is the ID and origin of one evidence row linked to a finding; used in
// confidence-change responses so a caller can see what the level is based on.
type EvidenceOriginRef struct {
	ID     string `json:"id"`
	Origin string `json:"origin"`
}

// ListEvidenceOriginsForFinding returns the ID and origin of every evidence row linked to a
// finding, oldest first.
func (db *DB) ListEvidenceOriginsForFinding(findingID string) ([]EvidenceOriginRef, error) {
	rows, err := db.Query(`SELECT id, origin FROM evidence WHERE finding_id = ? ORDER BY created_at, id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EvidenceOriginRef{}
	for rows.Next() {
		var r EvidenceOriginRef
		if err := rows.Scan(&r.ID, &r.Origin); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListEvidence returns an engagement's evidence in a stable order (oldest first, then ID).
func (db *DB) ListEvidence(engagementID string) ([]*Evidence, error) {
	rows, err := db.Query(`SELECT `+evidenceColumns+` FROM evidence WHERE engagement_id = ? ORDER BY created_at, id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Evidence{}
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
