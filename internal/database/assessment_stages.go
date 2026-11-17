package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Assessment stage names, in the fixed order they must be worked through.
const (
	StageAuthorisation           = "AUTHORISATION"
	StageReconnaissance          = "RECONNAISSANCE"
	StageAssetDiscovery          = "ASSET_DISCOVERY"
	StageEnumeration             = "ENUMERATION"
	StageVulnerabilityAssessment = "VULNERABILITY_ASSESSMENT"
	StageFindingValidation       = "FINDING_VALIDATION"
	StageImpactAssessment        = "IMPACT_ASSESSMENT"
	StageReportGeneration        = "REPORT_GENERATION"
)

// Stage statuses.
const (
	StagePending   = "pending"
	StageRunning   = "running"
	StageCompleted = "completed"
	StageSkipped   = "skipped"
	// StageBlocked: the automatic gate gave up before the stage was recorded and the stage has no
	// tool evidence. StageNeedsReview: same, but tool evidence exists, so a person must decide.
	// Both are non-terminal: they can be started again, completed or skipped.
	StageBlocked     = "blocked"
	StageNeedsReview = "needs_review"
	// StageFailed: the stage's run ended with an error the run could not continue from (not a
	// cancellation, timeout or billing failure; those are StageInterrupted). StageInterrupted: the
	// run ended without a "done" event while this stage was running (cancelled, timed out, hit an
	// unrecoverable error, or a billing/payment failure). Both are non-terminal, recovery states:
	// they can be started again (returning to running; the prior note and reason are kept as
	// history), completed or skipped, exactly like StageBlocked/StageNeedsReview.
	StageFailed      = "failed"
	StageInterrupted = "interrupted"
)

// StageStatuses lists every stage status.
var StageStatuses = []string{
	StagePending, StageRunning, StageBlocked, StageNeedsReview, StageFailed, StageInterrupted, StageCompleted, StageSkipped,
}

// StageNudgeLimitReason is the reason recorded when the nudge gate runs out of attempts.
const StageNudgeLimitReason = "nudge limit reached; stage not recorded"

// ErrNoStageToolEvidence is the message of the conflict returned when a completion cites no tool
// evidence recorded during the stage.
const ErrNoStageToolEvidence = "no evidence from a real tool execution is linked (evidence_ids must name tool-origin evidence)"

// Stage actions.
const (
	StageActionStart    = "start"
	StageActionComplete = "complete"
	StageActionSkip     = "skip"
)

// StageDef is one entry of the fixed stage list.
type StageDef struct {
	Name  string
	Title string
}

// AssessmentStageDefs is the single definition of the stages and their order.
var AssessmentStageDefs = []StageDef{
	{StageAuthorisation, "Authorisation"},
	{StageReconnaissance, "Reconnaissance"},
	{StageAssetDiscovery, "Asset discovery"},
	{StageEnumeration, "Enumeration"},
	{StageVulnerabilityAssessment, "Vulnerability assessment"},
	{StageFindingValidation, "Finding validation"},
	{StageImpactAssessment, "Impact assessment"},
	{StageReportGeneration, "Report generation"},
}

// ErrStageUnknown is returned for a stage name that is not in the fixed list.
var ErrStageUnknown = errors.New("unknown stage")

// ErrStageInvalid is returned for a malformed request (for example a skip without a reason).
type ErrStageInvalid struct{ Msg string }

func (e *ErrStageInvalid) Error() string { return e.Msg }

// ErrStageConflict is returned when a transition is refused by the stage rules.
type ErrStageConflict struct{ Msg string }

func (e *ErrStageConflict) Error() string { return e.Msg }

func stageConflict(format string, a ...interface{}) error {
	return &ErrStageConflict{Msg: fmt.Sprintf(format, a...)}
}

// StageIndex returns the position of a stage name (case-insensitive) or -1.
func StageIndex(name string) int {
	name = strings.ToUpper(strings.TrimSpace(name))
	for i, d := range AssessmentStageDefs {
		if d.Name == name {
			return i
		}
	}
	return -1
}

// AssessmentStage is the API view of one stage of one engagement.
type AssessmentStage struct {
	Stage       string     `json:"stage"`
	Title       string     `json:"title"`
	Order       int        `json:"order"`
	Status      string     `json:"status"`
	StartedAt   *time.Time `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	Note        string     `json:"note"`
	EvidenceIDs []string   `json:"evidence_ids"`
	InitiatedBy string     `json:"initiated_by"`
	Reason      string     `json:"reason"`
}

// StageTransition is the input of a stage transition.
type StageTransition struct {
	Action      string
	EvidenceIDs []string
	Note        string
	Reason      string
	Actor       string // user ID, or "agent"
	// ConversationID and MessageID identify the run this transition happened inside, when the
	// caller knows it (the engagement_stage agent tool and the auto-start middleware do; a manual
	// HTTP transition does not). Both are optional: when set, the stage_start/stage_complete
	// checkpoint written for this transition carries them, so GET resume-plan can find it.
	ConversationID string
	MessageID      string
}

func defaultStages() []AssessmentStage {
	out := make([]AssessmentStage, len(AssessmentStageDefs))
	for i, d := range AssessmentStageDefs {
		out[i] = AssessmentStage{Stage: d.Name, Title: d.Title, Order: i + 1, Status: StagePending, EvidenceIDs: []string{}}
	}
	return out
}

type stageQuerier interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

func loadStages(q stageQuerier, engagementID string) ([]AssessmentStage, error) {
	stages := defaultStages()
	rows, err := q.Query(`SELECT stage, status, started_at, finished_at, note, evidence_ids_json, initiated_by, reason
		FROM assessment_stages WHERE engagement_id = ?`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, status, note, idsJSON, by, reason string
		var started, finished sql.NullTime
		if err := rows.Scan(&name, &status, &started, &finished, &note, &idsJSON, &by, &reason); err != nil {
			return nil, err
		}
		i := StageIndex(name)
		if i < 0 {
			continue
		}
		s := &stages[i]
		s.Status, s.Note, s.InitiatedBy, s.Reason = status, note, by, reason
		if started.Valid {
			t := started.Time.UTC()
			s.StartedAt = &t
		}
		if finished.Valid {
			t := finished.Time.UTC()
			s.FinishedAt = &t
		}
		var ids []string
		if json.Unmarshal([]byte(idsJSON), &ids) == nil && ids != nil {
			s.EvidenceIDs = ids
		}
	}
	return stages, rows.Err()
}

// ListAssessmentStages returns all stages of the engagement in order; stages without a row are pending.
func (db *DB) ListAssessmentStages(engagementID string) ([]AssessmentStage, error) {
	if _, err := db.GetEngagement(engagementID); err != nil {
		return nil, err
	}
	return loadStages(db, engagementID)
}

func isTerminalStage(status string) bool { return status == StageCompleted || status == StageSkipped }

// CurrentStage returns a pointer to the first stage that is neither completed nor skipped, or nil
// when every stage is terminal (the engagement's assessment is fully recorded).
func CurrentStage(stages []AssessmentStage) *AssessmentStage {
	for i := range stages {
		if !isTerminalStage(stages[i].Status) {
			return &stages[i]
		}
	}
	return nil
}

// firstUnfinishedBefore names the first stage before index i that is neither completed nor skipped.
func firstUnfinishedBefore(stages []AssessmentStage, i int) string {
	for j := 0; j < i; j++ {
		if !isTerminalStage(stages[j].Status) {
			return stages[j].Stage
		}
	}
	return ""
}

func scopeHasIncludedTarget(raw json.RawMessage) bool {
	var scope struct {
		Included []string `json:"included"`
	}
	if json.Unmarshal(raw, &scope) != nil {
		return false
	}
	for _, t := range scope.Included {
		if strings.TrimSpace(t) != "" {
			return true
		}
	}
	return false
}

// TransitionAssessmentStage applies the stage rules and stores the result in one transaction.
func (db *DB) TransitionAssessmentStage(engagementID, stage string, in StageTransition) (*AssessmentStage, error) {
	idx := StageIndex(stage)
	if idx < 0 {
		return nil, ErrStageUnknown
	}
	action := strings.ToLower(strings.TrimSpace(in.Action))
	switch action {
	case StageActionStart, StageActionComplete, StageActionSkip:
	default:
		return nil, &ErrStageInvalid{Msg: "action must be start, complete or skip"}
	}
	reason := strings.TrimSpace(in.Reason)
	if action == StageActionSkip && reason == "" {
		return nil, &ErrStageInvalid{Msg: "a reason is required to skip a stage"}
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	eng, err := scanEngagement(tx.QueryRow(`SELECT `+engagementColumns+` FROM engagements WHERE id = ?`, engagementID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEngagementNotFound
	} else if err != nil {
		return nil, err
	}
	stages, err := loadStages(tx, engagementID)
	if err != nil {
		return nil, err
	}
	cur := stages[idx]
	if isTerminalStage(cur.Status) {
		return nil, stageConflict("stage %s is %s and cannot be changed", cur.Stage, cur.Status)
	}
	now := time.Now().UTC()
	next := cur

	requirePrevious := func() error {
		if first := firstUnfinishedBefore(stages, idx); first != "" {
			return stageConflict("stage %s cannot start: earlier stage %s is not completed or skipped", cur.Stage, first)
		}
		return nil
	}

	switch action {
	case StageActionStart:
		switch cur.Status {
		case StagePending:
			if err := requirePrevious(); err != nil {
				return nil, err
			}
			next.Status, next.StartedAt, next.InitiatedBy = StageRunning, &now, in.Actor
		case StageBlocked, StageNeedsReview:
			// Started again: back to running; the original start time and the note are kept.
			next.Status, next.Reason, next.InitiatedBy = StageRunning, "", in.Actor
			if next.StartedAt == nil {
				next.StartedAt = &now
			}
		case StageFailed, StageInterrupted:
			// Started again: back to running. The prior status and reason are never silently
			// dropped; they are folded into the note as history before the active reason clears.
			next.Note = appendStageHistory(next.Note, cur.Status, cur.Reason)
			next.Status, next.Reason, next.InitiatedBy = StageRunning, "", in.Actor
			if next.StartedAt == nil {
				next.StartedAt = &now
			}
		default:
			return nil, stageConflict("stage %s is %s; only a pending, blocked, needs_review, failed or interrupted stage can be started", cur.Stage, cur.Status)
		}
	case StageActionComplete:
		if cur.Status == StagePending {
			if err := requirePrevious(); err != nil {
				return nil, err
			}
		}
		if open, err := openRequiredTaskTitles(tx, engagementID, cur.Stage); err != nil {
			return nil, err
		} else if len(open) > 0 {
			return nil, stageConflict("stage %s cannot be completed: required tasks still open: %s", cur.Stage, strings.Join(open, ", "))
		}
		ids := dedupeStrings(in.EvidenceIDs)
		// Every cited ID must exist in this engagement. Completion additionally needs at least one
		// cited row with origin 'tool' that was recorded during this very stage; manual uploads
		// can be cited but never satisfy it. AUTHORISATION is the one exception: it has no tool
		// work, so it needs no tool evidence and completes on the engagement's authorization note
		// and scope (it still cites at least one evidence row of this engagement, any origin).
		if len(ids) == 0 {
			if cur.Stage == StageAuthorisation {
				return nil, stageConflict("completing stage %s requires at least one evidence ID", cur.Stage)
			}
			return nil, stageConflict("stage %s cannot be completed: %s", cur.Stage, ErrNoStageToolEvidence)
		}
		toolDuringStage := 0
		for _, id := range ids {
			var owner, origin, toolExecID string
			var evStage sql.NullString
			err := tx.QueryRow(`SELECT engagement_id, origin, stage, COALESCE(tool_execution_id, '') FROM evidence WHERE id = ?`, id).Scan(&owner, &origin, &evStage, &toolExecID)
			if errors.Is(err, sql.ErrNoRows) || (err == nil && owner != engagementID) {
				return nil, stageConflict("evidence %q does not exist in this engagement", id)
			} else if err != nil {
				return nil, err
			}
			if origin == EvidenceOriginTool && strings.TrimSpace(toolExecID) != "" && evStage.Valid && evStage.String == cur.Stage {
				var n int
				var toolName string
				if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(MAX(tool_name), '') FROM tool_executions WHERE id = ? AND status = 'completed'`, toolExecID).Scan(&n, &toolName); err != nil {
					return nil, err
				}
				if n > 0 && !platformBookkeepingTool(toolName) {
					toolDuringStage++
				}
			}
		}
		if cur.Stage == StageAuthorisation {
			if strings.TrimSpace(eng.AuthorizationNote) == "" {
				return nil, stageConflict("AUTHORISATION cannot be completed: the engagement has no authorization note")
			}
			if !scopeHasIncludedTarget(eng.ScopeJSON) {
				return nil, stageConflict("AUTHORISATION cannot be completed: the engagement scope lists no included target")
			}
		} else if toolDuringStage == 0 {
			return nil, stageConflict("stage %s cannot be completed: %s", cur.Stage, ErrNoStageToolEvidence)
		}
		if cur.Status == StagePending {
			next.StartedAt, next.InitiatedBy = &now, in.Actor
		}
		next.Status, next.FinishedAt, next.EvidenceIDs, next.Note, next.Reason = StageCompleted, &now, ids, strings.TrimSpace(in.Note), ""
	case StageActionSkip:
		if cur.Status == StagePending {
			next.InitiatedBy = in.Actor
		}
		next.Status, next.FinishedAt, next.Reason = StageSkipped, &now, reason
	}
	if next.InitiatedBy == "" {
		next.InitiatedBy = in.Actor
	}
	idsJSON, _ := json.Marshal(next.EvidenceIDs)
	if _, err := tx.Exec(`INSERT INTO assessment_stages (engagement_id, stage, status, started_at, finished_at, note, evidence_ids_json, initiated_by, reason, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(engagement_id, stage) DO UPDATE SET status=excluded.status, started_at=excluded.started_at, finished_at=excluded.finished_at,
		note=excluded.note, evidence_ids_json=excluded.evidence_ids_json, initiated_by=excluded.initiated_by, reason=excluded.reason, updated_at=excluded.updated_at`,
		engagementID, next.Stage, next.Status, next.StartedAt, next.FinishedAt, next.Note, string(idsJSON), next.InitiatedBy, next.Reason, now); err != nil {
		return nil, err
	}
	// Durable checkpoint: a stage start or a stage complete, recorded in the same transaction as
	// the stage row so it can never be missing for a transition that was itself recorded. IDs only
	// (the stage name and, for a completion, the evidence IDs already cited); never tool output.
	switch action {
	case StageActionStart:
		if cur.Status != StageRunning {
			if err := writeRunCheckpoint(tx, in.MessageID, in.ConversationID, engagementID, next.Stage, CheckpointKindStageStart,
				map[string]interface{}{"stage": next.Stage}); err != nil {
				return nil, err
			}
		}
	case StageActionComplete:
		if err := writeRunCheckpoint(tx, in.MessageID, in.ConversationID, engagementID, next.Stage, CheckpointKindStageComplete,
			map[string]interface{}{"stage": next.Stage, "evidence_ids": next.EvidenceIDs}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &next, nil
}

// AnnotateAssessmentStageNote records an operational note on a stage without changing its status,
// evidence IDs or reason. It is used when automatic handling ends a run before the stage could be
// completed or skipped, so the attempt is recorded without inventing a completion. Terminal stages
// (completed or skipped) are left untouched.
func (db *DB) AnnotateAssessmentStageNote(engagementID, stage, note, initiatedBy string) error {
	idx := StageIndex(stage)
	if idx < 0 {
		return ErrStageUnknown
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM engagements WHERE id = ?`, engagementID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrEngagementNotFound
	}
	stages, err := loadStages(tx, engagementID)
	if err != nil {
		return err
	}
	cur := stages[idx]
	if isTerminalStage(cur.Status) {
		return tx.Commit()
	}
	now := time.Now().UTC()
	idsJSON, _ := json.Marshal(cur.EvidenceIDs)
	if _, err := tx.Exec(`INSERT INTO assessment_stages (engagement_id, stage, status, started_at, finished_at, note, evidence_ids_json, initiated_by, reason, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(engagement_id, stage) DO UPDATE SET note=excluded.note, initiated_by=excluded.initiated_by, updated_at=excluded.updated_at`,
		engagementID, cur.Stage, cur.Status, cur.StartedAt, cur.FinishedAt, note, string(idsJSON), initiatedBy, cur.Reason, now); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkAssessmentStageStalled is used when the nudge gate runs out of attempts. It records note on
// the stage and sets its status to needs_review when the stage has some tool evidence (a person
// must decide) or blocked otherwise, with StageNudgeLimitReason as the reason. It never completes
// or skips a stage and leaves terminal stages untouched. It returns the resulting status.
func (db *DB) MarkAssessmentStageStalled(engagementID, stage, note, initiatedBy string) (string, error) {
	idx := StageIndex(stage)
	if idx < 0 {
		return "", ErrStageUnknown
	}
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM engagements WHERE id = ?`, engagementID).Scan(&n); err != nil {
		return "", err
	}
	if n == 0 {
		return "", ErrEngagementNotFound
	}
	stages, err := loadStages(tx, engagementID)
	if err != nil {
		return "", err
	}
	cur := stages[idx]
	if isTerminalStage(cur.Status) {
		return cur.Status, tx.Commit()
	}
	var toolRows int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM evidence WHERE engagement_id = ? AND origin = ? AND stage = ?`,
		engagementID, EvidenceOriginTool, cur.Stage).Scan(&toolRows); err != nil {
		return "", err
	}
	status := StageBlocked
	if toolRows > 0 {
		status = StageNeedsReview
	}
	now := time.Now().UTC()
	idsJSON, _ := json.Marshal(cur.EvidenceIDs)
	if _, err := tx.Exec(`INSERT INTO assessment_stages (engagement_id, stage, status, started_at, finished_at, note, evidence_ids_json, initiated_by, reason, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(engagement_id, stage) DO UPDATE SET status=excluded.status, note=excluded.note, initiated_by=excluded.initiated_by, reason=excluded.reason, updated_at=excluded.updated_at`,
		engagementID, cur.Stage, status, cur.StartedAt, cur.FinishedAt, note, string(idsJSON), initiatedBy, StageNudgeLimitReason, now); err != nil {
		return "", err
	}
	return status, tx.Commit()
}

// appendStageHistory folds a previous non-terminal status and its reason into note, so a restart
// never silently drops them. A blank reason leaves note untouched.
func appendStageHistory(note, prevStatus, prevReason string) string {
	prevReason = strings.TrimSpace(prevReason)
	if prevReason == "" {
		return note
	}
	entry := "previous (" + prevStatus + "): " + prevReason
	note = strings.TrimSpace(note)
	if note == "" {
		return entry
	}
	return note + " | " + entry
}

// maxStageEndedReasonChars bounds the reason text stored for an automatic failed/interrupted mark
// (a raw error message can otherwise be arbitrarily long).
const maxStageEndedReasonChars = 2000

// MarkAssessmentStageInterrupted is used when a run ends without a "done" event (cancelled, timed
// out, hit an unrecoverable error, or a billing/payment failure) while the stage is running.
// conversationID and messageID (both optional) are stamped on the checkpoint this writes, so a
// later GET resume-plan for that run finds it. It is a no-op, returning the stage's current status
// unchanged, when the stage is not currently running (including when it is already terminal) —
// only a running stage can be interrupted by a run ending under it. initiatedBy is recorded as
// given (callers pass "system" for automatic marks).
func (db *DB) MarkAssessmentStageInterrupted(engagementID, stage, reason, note, initiatedBy, conversationID, messageID string) (string, error) {
	return db.markAssessmentStageEnded(engagementID, stage, StageInterrupted, reason, note, initiatedBy, conversationID, messageID)
}

// MarkAssessmentStageFailed is used when a stage's run ends with an error the run cannot continue
// from (not a cancellation, timeout or billing failure; see MarkAssessmentStageInterrupted for
// those). Same parameters and no-op rule as MarkAssessmentStageInterrupted.
func (db *DB) MarkAssessmentStageFailed(engagementID, stage, reason, note, initiatedBy, conversationID, messageID string) (string, error) {
	return db.markAssessmentStageEnded(engagementID, stage, StageFailed, reason, note, initiatedBy, conversationID, messageID)
}

func (db *DB) markAssessmentStageEnded(engagementID, stage, status, reason, note, initiatedBy, conversationID, messageID string) (string, error) {
	idx := StageIndex(stage)
	if idx < 0 {
		return "", ErrStageUnknown
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > maxStageEndedReasonChars {
		reason = reason[:maxStageEndedReasonChars]
	}
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM engagements WHERE id = ?`, engagementID).Scan(&n); err != nil {
		return "", err
	}
	if n == 0 {
		return "", ErrEngagementNotFound
	}
	stages, err := loadStages(tx, engagementID)
	if err != nil {
		return "", err
	}
	cur := stages[idx]
	if cur.Status != StageRunning {
		// Only a running stage can be marked failed/interrupted by a run ending; every other
		// status (including the terminal ones) is left exactly as it is.
		return cur.Status, tx.Commit()
	}
	now := time.Now().UTC()
	idsJSON, _ := json.Marshal(cur.EvidenceIDs)
	if _, err := tx.Exec(`INSERT INTO assessment_stages (engagement_id, stage, status, started_at, finished_at, note, evidence_ids_json, initiated_by, reason, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(engagement_id, stage) DO UPDATE SET status=excluded.status, note=excluded.note, initiated_by=excluded.initiated_by, reason=excluded.reason, updated_at=excluded.updated_at`,
		engagementID, cur.Stage, status, cur.StartedAt, cur.FinishedAt, note, string(idsJSON), initiatedBy, reason, now); err != nil {
		return "", err
	}
	kind := CheckpointKindStageFailed
	if status == StageInterrupted {
		kind = CheckpointKindStageInterrupted
	}
	if err := writeRunCheckpoint(tx, messageID, conversationID, engagementID, cur.Stage, kind, map[string]interface{}{"stage": cur.Stage}); err != nil {
		return "", err
	}
	return status, tx.Commit()
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ReviewStageForDiscovery is called when a new asset or new tool-origin evidence arrives for a
// stage. Only a COMPLETED stage is touched: it is set to needs_review (never reopened to running)
// with reason stored in the stage reason field, and a 'stage_review_triggered' checkpoint (IDs
// only) is written in the same transaction. Pending, running, skipped, blocked, failed,
// interrupted and needs_review stages are left unchanged. It reports whether a stage was changed.
func (db *DB) ReviewStageForDiscovery(engagementID, stage, reason string) (bool, error) {
	idx := StageIndex(stage)
	if idx < 0 {
		return false, ErrStageUnknown
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > maxStageEndedReasonChars {
		reason = reason[:maxStageEndedReasonChars]
	}
	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM engagements WHERE id = ?`, engagementID).Scan(&n); err != nil {
		return false, err
	}
	if n == 0 {
		return false, ErrEngagementNotFound
	}
	stages, err := loadStages(tx, engagementID)
	if err != nil {
		return false, err
	}
	cur := stages[idx]
	if cur.Status != StageCompleted {
		return false, nil
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(`UPDATE assessment_stages SET status = ?, reason = ?, updated_at = ? WHERE engagement_id = ? AND stage = ?`,
		StageNeedsReview, reason, now, engagementID, cur.Stage); err != nil {
		return false, err
	}
	if err := writeRunCheckpoint(tx, "", "", engagementID, cur.Stage, CheckpointKindStageReview,
		map[string]interface{}{"stage": cur.Stage, "previous_status": StageCompleted}); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// ReviewStageForNewItem resolves the stage for a new item (the given stage, or the engagement's
// current running stage when blank; no running stage means nothing happens) and marks it via
// ReviewStageForDiscovery. kind is "asset" or "evidence"; itemID is named in the reason.
func (db *DB) ReviewStageForNewItem(engagementID, stage, kind, itemID string) error {
	engagementID = strings.TrimSpace(engagementID)
	if engagementID == "" {
		return nil
	}
	stage = strings.ToUpper(strings.TrimSpace(stage))
	if stage == "" {
		stages, err := loadStages(db, engagementID)
		if err != nil {
			return err
		}
		for _, s := range stages {
			if s.Status == StageRunning {
				stage = s.Stage
				break
			}
		}
		if stage == "" {
			return nil
		}
	}
	_, err := db.ReviewStageForDiscovery(engagementID, stage, "new "+kind+" "+itemID+" recorded after this stage was completed; review needed")
	return err
}

// platformBookkeepingTool reports whether a tool only reads or writes platform records. Its output
// is not scan or analysis evidence, so it cannot satisfy stage completion.
func platformBookkeepingTool(name string) bool {
	switch strings.TrimSpace(name) {
	case "engagement_stage", "batch_task_create", "batch_task_add_task", "batch_task_remove_task", "batch_task_delete", "record_vulnerability", "create_asset", "wait_tool_execution", "get_tool_execution", "list_tool_executions", "web_search", "read_evidence":
		return true
	}
	return false
}
