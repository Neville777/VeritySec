// Package verify performs an independent review of finding claims against
// recorded evidence. Reviewers only read evidence; they never run tools or
// contact targets. The final status is decided in code (Decide) from
// structured verdicts, never from model agreement alone.
package verify

// Evidence origins.
const (
	OriginTool   = "tool"
	OriginManual = "manual"
)

// Reviewer stances.
const (
	StanceSupports     = "supports"
	StanceDisputes     = "disputes"
	StanceInsufficient = "insufficient"
)

// Decision statuses. CONFIRMED is intentionally absent: only a human sets it.
const (
	StatusConfirmable       = "CONFIRMABLE"
	StatusNeedsManualReview = "NEEDS_MANUAL_REVIEW"
	StatusInconclusive      = "INCONCLUSIVE"
	StatusRejected          = "REJECTED"
)

// Reviewer roles.
const (
	RolePrimary    = "primary-verifier"
	RoleChallenger = "challenger"
)

// EvidenceInput is one piece of evidence shown to a reviewer.
type EvidenceInput struct {
	ID              string `json:"id"`
	Origin          string `json:"origin"` // "tool" | "manual"
	ToolExecutionID string `json:"tool_execution_id,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	Excerpt         string `json:"excerpt"` // already capped, text only
}

// ClaimInput is a claim plus the evidence offered for it.
type ClaimInput struct {
	ClaimID  string          `json:"claim_id"`
	Text     string          `json:"text"`
	Evidence []EvidenceInput `json:"evidence"`
}

// ReviewerVerdict is a reviewer's structured judgement of one claim.
type ReviewerVerdict struct {
	ClaimID     string   `json:"claim_id"`
	Stance      string   `json:"stance"`
	Reason      string   `json:"reason"`
	EvidenceIDs []string `json:"evidence_ids"`
}

// Decision is the deterministic outcome.
type Decision struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}
