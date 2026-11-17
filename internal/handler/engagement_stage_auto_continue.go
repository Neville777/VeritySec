package handler

import (
	"context"
	"strings"
	"time"

	"veritysec/internal/agent"
	"veritysec/internal/agentfinalizer"
	"veritysec/internal/audit"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/multiagent"

	"go.uber.org/zap"
)

// stageEndedReasonCancelled, stageEndedReasonTimeout and stageEndedReasonBilling are the fixed
// reasons recorded for the respective automatic INTERRUPTED causes; task 4 requires the billing
// wording exactly.
const (
	stageEndedReasonCancelled = "run cancelled"
	stageEndedReasonTimeout   = "run timed out"
	stageEndedReasonBilling   = "billing or payment error"
)

// maxStageEndedErrorChars bounds how much of a raw run error becomes the stage's reason text.
const maxStageEndedErrorChars = 500

// classifyRunEndForEngagementStage maps how a run ended to the stage status and reason that
// should be recorded for the stage that was running under it. kind is "cancelled" or "timeout"
// when the caller already knows that from the run's own cancellation/deadline handling; "" means
// the run ended with some other error (runErr), which is then checked for a billing/payment
// pattern before falling back to FAILED.
func classifyRunEndForEngagementStage(kind string, runErr error) (status, reason string) {
	switch kind {
	case "cancelled":
		return database.StageInterrupted, stageEndedReasonCancelled
	case "timeout":
		return database.StageInterrupted, stageEndedReasonTimeout
	}
	msg := ""
	if runErr != nil {
		msg = runErr.Error()
	}
	if database.IsBillingFailureText(msg) {
		return database.StageInterrupted, stageEndedReasonBilling
	}
	if msg == "" {
		return database.StageFailed, "run ended with an error"
	}
	if len(msg) > maxStageEndedErrorChars {
		msg = msg[:maxStageEndedErrorChars]
	}
	return database.StageFailed, msg
}

// markEngagementStageOnRunEnd records the FAILED/INTERRUPTED recovery state for the engagement
// stage that was running when a run ended outside the normal completion path (cancelled, timed
// out, or any other error, including a billing/payment failure). It is a no-op for a
// conversation with no engagement, or when the current stage is not running (nothing to mark —
// in particular it never touches a terminal stage). A durable checkpoint (IDs only) is written
// alongside the mark, and an audit entry records the automatic transition.
func (h *AgentHandler) markEngagementStageOnRunEnd(conversationID, assistantMessageID, kind string, runErr error) {
	if h == nil || h.db == nil {
		return
	}
	engagementID, cur := currentEngagementStageForConversation(h.db, conversationID)
	if engagementID == "" || cur == nil || cur.Status != database.StageRunning {
		return
	}
	status, reason := classifyRunEndForEngagementStage(kind, runErr)
	note := "run ended before the stage finished"
	var got string
	var err error
	if status == database.StageInterrupted {
		got, err = h.db.MarkAssessmentStageInterrupted(engagementID, cur.Stage, reason, note, "system", conversationID, assistantMessageID)
	} else {
		got, err = h.db.MarkAssessmentStageFailed(engagementID, cur.Stage, reason, note, "system", conversationID, assistantMessageID)
	}
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("engagement stage: mark on run end failed",
				zap.String("conversationId", conversationID), zap.String("engagementId", engagementID), zap.Error(err))
		}
		return
	}
	if got != status {
		// The stage was no longer running by the time this ran (a concurrent transition already
		// moved it on); nothing more to record.
		return
	}
	if h.audit != nil {
		h.audit.Record(nil, audit.Entry{
			Category: "engagement", Action: "stage_" + status, Result: "success", Actor: "system",
			Message:      "Assessment stage " + cur.Stage + ": " + status + " (" + reason + ")",
			ResourceType: "engagement", ResourceID: engagementID,
			Detail: map[string]interface{}{"stage": cur.Stage, "status": status, "reason": reason},
		})
	}
}

// engagementStageNudgeMaxAttempts caps how many times one run may be sent back around the handler
// loop to ask the model to record (complete or skip) the current assessment stage before the run
// is allowed to end without a recorded stage transition.
const engagementStageNudgeMaxAttempts = 3

const engagementStageNudgeNote = "run ended before the stage was recorded"

// shouldNudgeForEngagementStage is the exact completion-gate condition: the model's reply is
// finalizable (text, no pending tool call) and the engagement's current stage is still pending or
// running (neither completed nor skipped).
func shouldNudgeForEngagementStage(decision agentfinalizer.Decision, cur *database.AssessmentStage) bool {
	if !decision.Finalizable {
		return false
	}
	if cur == nil {
		return false
	}
	return cur.Status == database.StagePending || cur.Status == database.StageRunning
}

// currentEngagementStageForConversation returns the engagement bound to conversationID (if any)
// and its current (first non-terminal) stage. Both are empty/nil when the conversation has no
// engagement, so callers naturally no-op for engagement-less runs.
func currentEngagementStageForConversation(db *database.DB, conversationID string) (engagementID string, cur *database.AssessmentStage) {
	if db == nil {
		return "", nil
	}
	engagementID, err := db.ConversationEngagementID(conversationID)
	if err != nil || strings.TrimSpace(engagementID) == "" {
		return "", nil
	}
	stages, err := db.ListAssessmentStages(engagementID)
	if err != nil {
		return "", nil
	}
	return engagementID, database.CurrentStage(stages)
}

func engagementStageNudgeText(cur *database.AssessmentStage) string {
	return "The assessment stage \"" + cur.Title + "\" (" + cur.Stage + ") has not been recorded yet. " +
		"Continue the stage, then call the engagement_stage tool with action=\"complete\" and evidence_ids, " +
		"or action=\"skip\" with a reason, before replying with a final answer."
}

// tryAutoContinueForEngagementStage implements the completion gate: when auto_stages is on, the
// run belongs to an engagement, and the model's reply is finalizable while the current stage is
// still pending or running, the run is sent back around the handler loop (instead of ending) with
// a nudge, up to engagementStageNudgeMaxAttempts times per run. After the limit, the stage is set to
// blocked (or needs_review when it has tool evidence) with a note, never completed or skipped.
func (h *AgentHandler) tryAutoContinueForEngagementStage(
	taskCtx context.Context,
	mw *config.MultiAgentEinoMiddlewareConfig,
	conversationID string,
	result *multiagent.RunResult,
	decision agentfinalizer.Decision,
	attempt *int,
	curHistory *[]agent.ChatMessage,
	curFinalMessage *string,
	progressCallback func(eventType, message string, data interface{}),
) bool {
	if h == nil || h.db == nil || mw == nil || !mw.EngagementAutoStagesEffective() || result == nil {
		return false
	}
	engagementID, cur := currentEngagementStageForConversation(h.db, conversationID)
	if engagementID == "" || cur == nil {
		return false
	}
	if !shouldNudgeForEngagementStage(decision, cur) {
		return false
	}
	if *attempt >= engagementStageNudgeMaxAttempts {
		// Out of attempts: record the stage as blocked (no tool evidence) or needs_review (some
		// tool evidence but no completion, so a person must decide), keeping the note.
		status, err := h.db.MarkAssessmentStageStalled(engagementID, cur.Stage, engagementStageNudgeNote, "system")
		if err != nil {
			if h.logger != nil {
				h.logger.Warn("engagement stage: mark stalled failed",
					zap.String("conversationId", conversationID), zap.String("engagementId", engagementID), zap.Error(err))
			}
		} else if h.audit != nil {
			h.audit.Record(nil, audit.Entry{
				Category: "engagement", Action: "stage_" + status, Result: "success", Actor: "system",
				Message:      "Assessment stage " + cur.Stage + ": " + status + " (" + database.StageNudgeLimitReason + ")",
				ResourceType: "engagement", ResourceID: engagementID,
				Detail: map[string]interface{}{"stage": cur.Stage, "status": status, "reason": database.StageNudgeLimitReason},
			})
		}
		return false
	}

	*attempt++
	h.persistEinoAgentTraceForResume(conversationID, result)
	if hist, err := h.loadHistoryFromAgentTrace(conversationID); err == nil && len(hist) > 0 {
		*curHistory = hist
	} else {
		if h.logger != nil {
			h.logger.Warn("engagement stage nudge could not restore trace",
				zap.String("conversationId", conversationID), zap.Error(err))
		}
		return false
	}
	*curFinalMessage = engagementStageNudgeText(cur)
	if progressCallback != nil {
		progressCallback("engagement_stage_continue", "assessment stage not yet recorded; continuing…", map[string]interface{}{
			"conversationId": conversationID,
			"source":         "engagement",
			"attempt":        *attempt,
			"maxAttempts":    engagementStageNudgeMaxAttempts,
			"stage":          cur.Stage,
			"status":         cur.Status,
		})
	}
	select {
	case <-taskCtx.Done():
		return false
	case <-time.After(time.Duration(*attempt) * 400 * time.Millisecond):
		return true
	}
}
