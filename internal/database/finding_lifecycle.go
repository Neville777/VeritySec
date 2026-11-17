package database

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Lifecycle states of a finding, stored in vulnerabilities.status.
const (
	LifecycleOpen         = "open"
	LifecycleUnderReview  = "under_review"
	LifecycleConfirmed    = "confirmed"
	LifecycleRejected     = "rejected"
	LifecycleAcceptedRisk = "accepted_risk"
	LifecycleFixed        = "fixed"
	LifecycleRetestFailed = "retest_failed"
	LifecycleClosed       = "closed"
)

// LifecycleStates lists every allowed lifecycle value.
var LifecycleStates = []string{LifecycleOpen, LifecycleUnderReview, LifecycleConfirmed, LifecycleRejected,
	LifecycleAcceptedRisk, LifecycleFixed, LifecycleRetestFailed, LifecycleClosed}

// lifecycleTransitions is the single table of allowed moves: from -> set of next states.
var lifecycleTransitions = map[string][]string{
	LifecycleOpen:         {LifecycleUnderReview},
	LifecycleUnderReview:  {LifecycleConfirmed, LifecycleRejected, LifecycleAcceptedRisk},
	LifecycleConfirmed:    {LifecycleFixed},
	LifecycleFixed:        {LifecycleClosed, LifecycleRetestFailed},
	LifecycleRetestFailed: {LifecycleUnderReview},
	LifecycleRejected:     {},
	LifecycleAcceptedRisk: {},
	LifecycleClosed:       {},
}

// lifecycleReasonRequired lists the states that cannot be entered without a reason.
var lifecycleReasonRequired = map[string]bool{LifecycleConfirmed: true, LifecycleRejected: true, LifecycleAcceptedRisk: true}

// ValidLifecycle reports whether s is an allowed lifecycle value.
func ValidLifecycle(s string) bool {
	_, ok := lifecycleTransitions[s]
	return ok
}

// LifecycleTransitions returns a copy of the transition table.
func LifecycleTransitions() map[string][]string {
	out := make(map[string][]string, len(lifecycleTransitions))
	for k, v := range lifecycleTransitions {
		out[k] = append([]string{}, v...)
	}
	return out
}

// ErrLifecycleRefused is returned when a lifecycle change breaks the table or a rule.
type ErrLifecycleRefused struct{ Msg string }

func (e *ErrLifecycleRefused) Error() string { return e.Msg }

// normalizeLifecycle maps a stored status, including older values, onto a lifecycle state.
func normalizeLifecycle(s string) string {
	switch strings.TrimSpace(s) {
	case "", "open":
		return LifecycleOpen
	case "false_positive":
		return LifecycleRejected
	case "ignored":
		return LifecycleAcceptedRisk
	}
	return strings.TrimSpace(s)
}

// SetFindingLifecycle moves a finding to the next lifecycle state if the transition table and the
// rules allow it, writes an audit entry, and returns the error (its text says why it was refused).
func SetFindingLifecycle(db *DB, findingID, next, reason, actor string) error {
	findingID = strings.TrimSpace(findingID)
	next = strings.TrimSpace(next)
	reason = strings.TrimSpace(reason)
	if !ValidLifecycle(next) {
		return &ErrLifecycleRefused{Msg: fmt.Sprintf("invalid lifecycle state %q; allowed: %s", next, strings.Join(LifecycleStates, ", "))}
	}
	vuln, err := db.GetVulnerability(findingID)
	if err != nil {
		return err
	}
	cur := normalizeLifecycle(vuln.Status)
	if !ValidLifecycle(cur) {
		return &ErrLifecycleRefused{Msg: fmt.Sprintf("the finding has unrecognised status %q", vuln.Status)}
	}
	allowed := false
	for _, n := range lifecycleTransitions[cur] {
		if n == next {
			allowed = true
		}
	}
	if !allowed {
		opts := append([]string{}, lifecycleTransitions[cur]...)
		sort.Strings(opts)
		to := "none (terminal state)"
		if len(opts) > 0 {
			to = strings.Join(opts, ", ")
		}
		return &ErrLifecycleRefused{Msg: fmt.Sprintf("refused: transition %s to %s is not allowed; from %s the allowed next states are: %s", cur, next, cur, to)}
	}
	if lifecycleReasonRequired[next] && reason == "" {
		return &ErrLifecycleRefused{Msg: "refused: moving to " + next + " requires a reason"}
	}
	if next == LifecycleConfirmed {
		if c := strings.TrimSpace(vuln.Confidence); c != ConfidenceValidated && c != ConfidenceConfirmed {
			return &ErrLifecycleRefused{Msg: fmt.Sprintf("refused: confirmed requires confidence validated or confirmed, this finding is %q", vuln.Confidence)}
		}
		cs, err := db.ClaimSummary(findingID)
		if err != nil {
			return err
		}
		if cs.Total > 0 && !cs.AllSupported() {
			return &ErrLifecycleRefused{Msg: fmt.Sprintf("refused: confirmed requires every claim to be supported: %d of %d claims are not (unverified %d, disputed %d, unsupported %d)",
				cs.Total-cs.Supported, cs.Total, cs.Unverified, cs.Disputed, cs.Unsupported)}
		}
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`UPDATE vulnerabilities SET status = ?, updated_at = ? WHERE id = ?`, next, now, findingID); err != nil {
		return fmt.Errorf("failed to update lifecycle: %w", err)
	}
	detail := map[string]interface{}{"old_status": cur, "new_status": next}
	if reason != "" {
		detail["reason"] = reason
	}
	_ = db.AppendAuditLog(&AuditLog{
		ID: uuid.New().String(), CreatedAt: now, Level: "info", Category: "vulnerability",
		Action: "lifecycle_change", Result: "success", Actor: actor,
		ResourceType: "vulnerability", ResourceID: findingID,
		Message: fmt.Sprintf("Lifecycle changed from %s to %s", cur, next), Detail: detail,
	})
	return nil
}

// ReviewQueueItem is one thing a person must look at.
type ReviewQueueItem struct {
	Kind     string    `json:"kind"` // finding_under_review, finding_unverified_claims, hypothesis_stale
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Severity string    `json:"severity,omitempty"`
	Reason   string    `json:"reason"`
	Since    time.Time `json:"since"`
}

// HypothesisStaleAfter is how long a hypothesis may stay open before it enters the review queue.
const HypothesisStaleAfter = 7 * 24 * time.Hour

// ListReviewQueue returns findings under review, potential-confidence findings with an unverified
// claim, and hypotheses open for more than 7 days, for one engagement.
func ListReviewQueue(db *DB, engagementID string) ([]ReviewQueueItem, error) {
	out := []ReviewQueueItem{}
	scope := `(engagement_id = ? OR conversation_id IN (SELECT id FROM conversations WHERE engagement_id = ?))`
	rows, err := db.Query(`SELECT id, title, severity, status, COALESCE(confidence,'potential'), updated_at,
		EXISTS(SELECT 1 FROM finding_claims fc WHERE fc.vulnerability_id = vulnerabilities.id AND fc.status = 'unverified')
		FROM vulnerabilities WHERE `+scope+` ORDER BY updated_at DESC, id`, engagementID, engagementID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, title, sev, status, conf string
		var upd time.Time
		var unverified bool
		if err := rows.Scan(&id, &title, &sev, &status, &conf, &upd, &unverified); err != nil {
			rows.Close()
			return nil, err
		}
		switch {
		case status == LifecycleUnderReview:
			out = append(out, ReviewQueueItem{Kind: "finding_under_review", ID: id, Title: title, Severity: sev, Reason: "under review", Since: upd})
		case conf == ConfidencePotential && unverified:
			out = append(out, ReviewQueueItem{Kind: "finding_unverified_claims", ID: id, Title: title, Severity: sev, Reason: "potential confidence with unverified claims", Since: upd})
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	cutoff := time.Now().UTC().Add(-HypothesisStaleAfter)
	hrows, err := db.Query(`SELECT id, title, created_at FROM hypotheses WHERE engagement_id = ? AND status = ? AND created_at < ? ORDER BY created_at, id`,
		engagementID, HypothesisOpen, cutoff)
	if err != nil {
		return nil, err
	}
	defer hrows.Close()
	for hrows.Next() {
		var id, title string
		var created time.Time
		if err := hrows.Scan(&id, &title, &created); err != nil {
			return nil, err
		}
		out = append(out, ReviewQueueItem{Kind: "hypothesis_stale", ID: id, Title: title, Reason: "open for more than 7 days", Since: created})
	}
	return out, hrows.Err()
}
