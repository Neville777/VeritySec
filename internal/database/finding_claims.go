package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Claim statuses. A finding is made of separately checkable claims; each claim carries its own
// evidence links and status.
const (
	ClaimUnverified  = "unverified"
	ClaimSupported   = "supported"
	ClaimDisputed    = "disputed"
	ClaimUnsupported = "unsupported"
)

// ClaimStatuses lists every valid claim status.
var ClaimStatuses = []string{ClaimUnverified, ClaimSupported, ClaimDisputed, ClaimUnsupported}

var (
	ErrClaimNotFound      = errors.New("claim not found")
	ErrClaimStatusInvalid = errors.New("invalid claim status")
	ErrClaimReason        = errors.New("a reason is required for supported, disputed and unsupported")
	ErrClaimText          = errors.New("claim text is required")
)

// FindingClaim is one separately checkable statement a finding makes.
type FindingClaim struct {
	ID              string    `json:"id"`
	VulnerabilityID string    `json:"vulnerability_id"`
	EngagementID    string    `json:"engagement_id"`
	Position        int       `json:"position"`
	Text            string    `json:"text"`
	Status          string    `json:"status"`
	StatusReason    string    `json:"status_reason"`
	EvidenceIDs     []string  `json:"evidence_ids"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ClaimSummaryCounts counts a finding's claims by status.
type ClaimSummaryCounts struct {
	Total       int `json:"total"`
	Unverified  int `json:"unverified"`
	Supported   int `json:"supported"`
	Disputed    int `json:"disputed"`
	Unsupported int `json:"unsupported"`
}

// AllSupported is true when there is at least one claim and every claim is supported.
func (s ClaimSummaryCounts) AllSupported() bool { return s.Total > 0 && s.Supported == s.Total }

func validClaimStatus(s string) bool {
	for _, v := range ClaimStatuses {
		if v == s {
			return true
		}
	}
	return false
}

// findingEngagementID resolves the engagement a finding belongs to, directly or through its
// conversation. It returns "" when the finding is not part of any engagement.
func (db *DB) findingEngagementID(findingID string) (string, error) {
	var eid string
	err := db.QueryRow(`SELECT COALESCE(NULLIF(engagement_id,''),
		(SELECT COALESCE(c.engagement_id,'') FROM conversations c WHERE c.id = vulnerabilities.conversation_id), '')
		FROM vulnerabilities WHERE id = ?`, findingID).Scan(&eid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("vulnerability not found")
	}
	return eid, err
}

// CreateFindingClaim appends a claim (status unverified) to a finding.
func (db *DB) CreateFindingClaim(findingID, text string) (*FindingClaim, error) {
	findingID = strings.TrimSpace(findingID)
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, ErrClaimText
	}
	eid, err := db.findingEngagementID(findingID)
	if err != nil {
		return nil, err
	}
	var pos int
	if err := db.QueryRow(`SELECT COALESCE(MAX(position), 0) + 1 FROM finding_claims WHERE vulnerability_id = ?`, findingID).Scan(&pos); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	c := &FindingClaim{ID: uuid.New().String(), VulnerabilityID: findingID, EngagementID: eid, Position: pos,
		Text: text, Status: ClaimUnverified, EvidenceIDs: []string{}, CreatedAt: now, UpdatedAt: now}
	if _, err := db.Exec(`INSERT INTO finding_claims (id, vulnerability_id, engagement_id, position, text, status, status_reason, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, '', ?, ?)`, c.ID, c.VulnerabilityID, c.EngagementID, c.Position, c.Text, c.Status, now, now); err != nil {
		return nil, fmt.Errorf("failed to create claim: %w", err)
	}
	return c, nil
}

// GetFindingClaim loads one claim with its evidence IDs.
func (db *DB) GetFindingClaim(claimID string) (*FindingClaim, error) {
	var c FindingClaim
	err := db.QueryRow(`SELECT id, vulnerability_id, engagement_id, position, text, status, status_reason, created_at, updated_at
		FROM finding_claims WHERE id = ?`, claimID).
		Scan(&c.ID, &c.VulnerabilityID, &c.EngagementID, &c.Position, &c.Text, &c.Status, &c.StatusReason, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrClaimNotFound
	}
	if err != nil {
		return nil, err
	}
	ids, err := db.claimEvidenceIDs(claimID)
	if err != nil {
		return nil, err
	}
	c.EvidenceIDs = ids
	return &c, nil
}

func (db *DB) claimEvidenceIDs(claimID string) ([]string, error) {
	rows, err := db.Query(`SELECT evidence_id FROM finding_claim_evidence WHERE claim_id = ? ORDER BY evidence_id`, claimID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListFindingClaims returns a finding's claims in position order, each with its evidence IDs.
func (db *DB) ListFindingClaims(findingID string) ([]*FindingClaim, error) {
	rows, err := db.Query(`SELECT id, vulnerability_id, engagement_id, position, text, status, status_reason, created_at, updated_at
		FROM finding_claims WHERE vulnerability_id = ? ORDER BY position, id`, findingID)
	if err != nil {
		return nil, err
	}
	out := []*FindingClaim{}
	for rows.Next() {
		var c FindingClaim
		if err := rows.Scan(&c.ID, &c.VulnerabilityID, &c.EngagementID, &c.Position, &c.Text, &c.Status, &c.StatusReason, &c.CreatedAt, &c.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		c.EvidenceIDs = []string{}
		out = append(out, &c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for _, c := range out {
		ids, err := db.claimEvidenceIDs(c.ID)
		if err != nil {
			return nil, err
		}
		c.EvidenceIDs = ids
	}
	return out, nil
}

// ListEngagementClaims returns all claims of an engagement's findings, grouped by finding ID.
func (db *DB) ListEngagementClaims(findingIDs []string) (map[string][]*FindingClaim, error) {
	out := map[string][]*FindingClaim{}
	for _, id := range findingIDs {
		cs, err := db.ListFindingClaims(id)
		if err != nil {
			return nil, err
		}
		if len(cs) > 0 {
			out[id] = cs
		}
	}
	return out, nil
}

// LinkClaimEvidence links evidence to a claim; refused unless the evidence belongs to the same
// engagement as the claim.
func (db *DB) LinkClaimEvidence(claimID, evidenceID string) error {
	claimID = strings.TrimSpace(claimID)
	evidenceID = strings.TrimSpace(evidenceID)
	if claimID == "" || evidenceID == "" {
		return errors.New("claim_id and evidence_id are required")
	}
	claim, err := db.GetFindingClaim(claimID)
	if err != nil {
		return err
	}
	ev, err := db.GetEvidence(evidenceID)
	if err != nil {
		return err
	}
	if claim.EngagementID == "" || ev.EngagementID != claim.EngagementID {
		return errors.New("evidence does not belong to the same engagement as the claim")
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO finding_claim_evidence (claim_id, evidence_id) VALUES (?, ?)`, claimID, evidenceID); err != nil {
		return fmt.Errorf("failed to link claim evidence: %w", err)
	}
	return nil
}

// SetClaimStatus changes a claim's status. A non-empty reason is required for supported,
// disputed and unsupported.
func (db *DB) SetClaimStatus(claimID, status, reason string) (*FindingClaim, error) {
	status = strings.TrimSpace(status)
	reason = strings.TrimSpace(reason)
	if !validClaimStatus(status) {
		return nil, ErrClaimStatusInvalid
	}
	if status != ClaimUnverified && reason == "" {
		return nil, ErrClaimReason
	}
	if _, err := db.GetFindingClaim(claimID); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`UPDATE finding_claims SET status = ?, status_reason = ?, updated_at = ? WHERE id = ?`,
		status, reason, time.Now().UTC(), claimID); err != nil {
		return nil, fmt.Errorf("failed to update claim: %w", err)
	}
	return db.GetFindingClaim(claimID)
}

// ClaimSummary counts a finding's claims by status.
func (db *DB) ClaimSummary(findingID string) (ClaimSummaryCounts, error) {
	var s ClaimSummaryCounts
	rows, err := db.Query(`SELECT status, COUNT(*) FROM finding_claims WHERE vulnerability_id = ? GROUP BY status`, findingID)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return s, err
		}
		s.Total += n
		switch st {
		case ClaimUnverified:
			s.Unverified = n
		case ClaimSupported:
			s.Supported = n
		case ClaimDisputed:
			s.Disputed = n
		case ClaimUnsupported:
			s.Unsupported = n
		}
	}
	return s, rows.Err()
}
