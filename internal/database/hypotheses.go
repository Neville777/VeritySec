package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Hypothesis statuses.
const (
	HypothesisOpen         = "open"
	HypothesisSupported    = "supported"
	HypothesisRefuted      = "refuted"
	HypothesisInconclusive = "inconclusive"
	HypothesisPromoted     = "promoted"
)

var (
	ErrHypothesisNotFound = errors.New("hypothesis not found")
	// ErrHypothesisRule marks a refusal caused by a rule (bad input or unmet promotion condition).
	ErrHypothesisRule = errors.New("hypothesis rule")
)

func hypRule(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrHypothesisRule, fmt.Sprintf(format, a...))
}

// Hypothesis is a suspected issue that must be checked before it can become a finding.
type Hypothesis struct {
	ID              string    `json:"id"`
	EngagementID    string    `json:"engagement_id"`
	ConversationID  string    `json:"conversation_id,omitempty"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Status          string    `json:"status"`
	CreatedBy       string    `json:"created_by"`
	StatusReason    string    `json:"status_reason,omitempty"`
	VulnerabilityID string    `json:"vulnerability_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ApplicabilityCheck records whether a hypothesis applies to the target.
type ApplicabilityCheck struct {
	ID                  string    `json:"id"`
	HypothesisID        string    `json:"hypothesis_id"`
	CheckKind           string    `json:"check_kind"`
	TargetObservationID string    `json:"target_observation_id,omitempty"`
	Result              string    `json:"result"`
	Reason              string    `json:"reason"`
	CreatedAt           time.Time `json:"created_at"`
}

const hypothesisCols = `id, engagement_id, conversation_id, title, description, status, created_by, status_reason, vulnerability_id, created_at, updated_at`

func scanHypothesis(r interface{ Scan(...any) error }) (*Hypothesis, error) {
	var h Hypothesis
	if err := r.Scan(&h.ID, &h.EngagementID, &h.ConversationID, &h.Title, &h.Description, &h.Status,
		&h.CreatedBy, &h.StatusReason, &h.VulnerabilityID, &h.CreatedAt, &h.UpdatedAt); err != nil {
		return nil, err
	}
	return &h, nil
}

// GetHypothesis returns one hypothesis.
func (db *DB) GetHypothesis(id string) (*Hypothesis, error) {
	h, err := scanHypothesis(db.QueryRow(`SELECT `+hypothesisCols+` FROM hypotheses WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrHypothesisNotFound
	}
	return h, err
}

// CreateHypothesis stores a new hypothesis. The status is always 'open' whoever creates it, and
// no finding is ever created here.
func (db *DB) CreateHypothesis(h *Hypothesis) (*Hypothesis, error) {
	h.Title = strings.TrimSpace(h.Title)
	if h.Title == "" {
		return nil, hypRule("title is required")
	}
	if h.CreatedBy != "model" && h.CreatedBy != "human" {
		return nil, hypRule("created_by must be model or human")
	}
	if _, err := db.GetEngagement(h.EngagementID); err != nil {
		return nil, err
	}
	now := time.Now()
	h.ID, h.Status, h.VulnerabilityID, h.StatusReason = uuid.NewString(), HypothesisOpen, "", ""
	h.CreatedAt, h.UpdatedAt = now, now
	_, err := db.Exec(`INSERT INTO hypotheses (`+hypothesisCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		h.ID, h.EngagementID, h.ConversationID, h.Title, h.Description, h.Status, h.CreatedBy, h.StatusReason, h.VulnerabilityID, h.CreatedAt, h.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create hypothesis: %w", err)
	}
	return h, nil
}

// ListHypotheses lists the hypotheses of an engagement, newest first.
func (db *DB) ListHypotheses(engagementID string) ([]*Hypothesis, error) {
	rows, err := db.Query(`SELECT `+hypothesisCols+` FROM hypotheses WHERE engagement_id=? ORDER BY created_at DESC, id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Hypothesis{}
	for rows.Next() {
		h, err := scanHypothesis(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// LinkHypothesisEvidence links an evidence row to a hypothesis; both must be in the same engagement.
func (db *DB) LinkHypothesisEvidence(hypothesisID, evidenceID, stance string) error {
	if stance != "supports" && stance != "refutes" && stance != "context" {
		return hypRule("stance must be supports, refutes or context")
	}
	h, err := db.GetHypothesis(hypothesisID)
	if err != nil {
		return err
	}
	if h.Status == HypothesisPromoted {
		return hypRule("hypothesis is already promoted")
	}
	var evEngagement string
	err = db.QueryRow(`SELECT engagement_id FROM evidence WHERE id=?`, evidenceID).Scan(&evEngagement)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEvidenceNotFound
	}
	if err != nil {
		return err
	}
	if evEngagement != h.EngagementID {
		return hypRule("evidence belongs to a different engagement")
	}
	_, err = db.Exec(`INSERT INTO hypothesis_evidence (hypothesis_id, evidence_id, stance) VALUES (?,?,?)
		ON CONFLICT(hypothesis_id, evidence_id) DO UPDATE SET stance=excluded.stance`, hypothesisID, evidenceID, stance)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE hypotheses SET updated_at=? WHERE id=?`, time.Now(), hypothesisID)
	return err
}

// AddApplicabilityCheck records an applicability check. A target observation, when given, must be
// in the same engagement.
func (db *DB) AddApplicabilityCheck(c *ApplicabilityCheck) (*ApplicabilityCheck, error) {
	c.CheckKind = strings.TrimSpace(c.CheckKind)
	if c.CheckKind == "" {
		return nil, hypRule("check_kind is required")
	}
	if c.Result != "applies" && c.Result != "does_not_apply" && c.Result != "unknown" {
		return nil, hypRule("result must be applies, does_not_apply or unknown")
	}
	h, err := db.GetHypothesis(c.HypothesisID)
	if err != nil {
		return nil, err
	}
	if h.Status == HypothesisPromoted {
		return nil, hypRule("hypothesis is already promoted")
	}
	if c.TargetObservationID != "" {
		var eng string
		err := db.QueryRow(`SELECT engagement_id FROM input_observations WHERE id=?`, c.TargetObservationID).Scan(&eng)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && eng != h.EngagementID) {
			return nil, hypRule("target_observation_id is not an observation of this engagement")
		}
		if err != nil {
			return nil, err
		}
	}
	c.ID, c.CreatedAt = uuid.NewString(), time.Now()
	_, err = db.Exec(`INSERT INTO applicability_checks (id, hypothesis_id, check_kind, target_observation_id, result, reason, created_at) VALUES (?,?,?,?,?,?,?)`,
		c.ID, c.HypothesisID, c.CheckKind, nullIfEmpty(c.TargetObservationID), c.Result, c.Reason, c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// SetHypothesisStatus changes the status. 'promoted' is reachable only through PromoteHypothesis;
// 'refuted' and 'inconclusive' need a reason.
func (db *DB) SetHypothesisStatus(id, status, reason string) error {
	reason = strings.TrimSpace(reason)
	switch status {
	case HypothesisOpen, HypothesisSupported:
	case HypothesisRefuted, HypothesisInconclusive:
		if reason == "" {
			return hypRule("a reason is required for status %s", status)
		}
	case HypothesisPromoted:
		return hypRule("use promotion to promote a hypothesis")
	default:
		return hypRule("invalid status")
	}
	h, err := db.GetHypothesis(id)
	if err != nil {
		return err
	}
	if h.Status == HypothesisPromoted {
		return hypRule("a promoted hypothesis cannot change status")
	}
	_, err = db.Exec(`UPDATE hypotheses SET status=?, status_reason=?, updated_at=? WHERE id=?`, status, reason, time.Now(), id)
	return err
}

// PromoteHypothesis turns a hypothesis into a finding. Rule: at least one applicability check with
// result 'applies', and at least one 'supports' evidence link whose evidence is tool-origin with a
// tool_execution_id that exists in tool_executions. The finding is created with source_status
// 'linked'; otherwise promotion is refused and nothing changes.
func (db *DB) PromoteHypothesis(id, severity string) (*Vulnerability, error) {
	h, err := db.GetHypothesis(id)
	if err != nil {
		return nil, err
	}
	if h.Status == HypothesisPromoted {
		return nil, hypRule("hypothesis is already promoted")
	}
	if h.Status == HypothesisRefuted {
		return nil, hypRule("a refuted hypothesis cannot be promoted")
	}
	var applies int
	if err := db.QueryRow(`SELECT COUNT(*) FROM applicability_checks WHERE hypothesis_id=? AND result='applies'`, id).Scan(&applies); err != nil {
		return nil, err
	}
	if applies == 0 {
		return nil, hypRule("promotion needs at least one applicability check with result 'applies'")
	}
	var supporting, execID string
	var supportRows int
	err = db.QueryRow(`SELECT COUNT(*) FROM hypothesis_evidence WHERE hypothesis_id=? AND stance='supports'`, id).Scan(&supportRows)
	if err != nil {
		return nil, err
	}
	if supportRows == 0 {
		return nil, hypRule("promotion needs at least one linked evidence row with stance 'supports'")
	}
	err = db.QueryRow(`SELECT e.id, e.tool_execution_id FROM hypothesis_evidence he
		JOIN evidence e ON e.id = he.evidence_id
		JOIN tool_executions t ON t.id = e.tool_execution_id
		WHERE he.hypothesis_id=? AND he.stance='supports' AND e.origin='tool' AND e.engagement_id=?
		  AND COALESCE(e.tool_execution_id,'') != ''
		ORDER BY e.created_at, e.id LIMIT 1`, id, h.EngagementID).Scan(&supporting, &execID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, hypRule("no supporting evidence is tool-origin with a real tool_execution_id; refusing to create a finding")
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(severity) == "" {
		severity = "info"
	}
	// Claim the hypothesis first so a concurrent promotion cannot create a second finding.
	res, err := db.Exec(`UPDATE hypotheses SET status='promoted', updated_at=? WHERE id=? AND status NOT IN ('promoted','refuted')`, time.Now(), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, hypRule("hypothesis changed during promotion")
	}
	v, err := db.CreateVulnerability(&Vulnerability{
		ConversationID: h.ConversationID,
		Title:          h.Title,
		Description:    h.Description,
		Severity:       severity,
		Evidence:       fmt.Sprintf("evidence %s (tool execution %s)", supporting, execID),
		SourceStatus:   SourceStatusLinked,
	})
	if err == nil {
		_, err = db.Exec(`UPDATE vulnerabilities SET engagement_id=? WHERE id=?`, h.EngagementID, v.ID)
	}
	if err == nil {
		_, err = db.Exec(`UPDATE hypotheses SET vulnerability_id=? WHERE id=?`, v.ID, id)
	}
	if err != nil {
		if v != nil {
			db.Exec(`DELETE FROM vulnerabilities WHERE id=?`, v.ID)
		}
		db.Exec(`UPDATE hypotheses SET status=?, vulnerability_id='' WHERE id=?`, h.Status, id)
		return nil, err
	}
	return v, nil
}
