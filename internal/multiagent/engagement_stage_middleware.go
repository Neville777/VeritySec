package multiagent

import (
	"context"
	"fmt"
	"strings"

	"veritysec/internal/database"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

// maxEngagementStageContextChars bounds the injected stage-context system message.
const maxEngagementStageContextChars = 1200

// maxEngagementStageContextEvidenceIDs is how many of the most recent evidence IDs are listed.
const maxEngagementStageContextEvidenceIDs = 20

// engagementStageMiddleware auto-starts the first assessment stage of an engagement-bound
// conversation and injects a short stage-context system message before every model call. It never
// completes or skips a stage itself: ApplyStageTransition / TransitionAssessmentStage remain the
// single source of truth for that, driven by the engagement_stage tool or the HTTP API.
//
// A fresh instance is created per run (see prependEinoAgenticMiddlewares callers), so the
// engagement lookup is cheap to repeat; this also makes the auto-start naturally idempotent across
// a run's many model calls and across continuations started by the handler-level completion gate:
// TransitionAssessmentStage refuses a second "start" once the stage is no longer pending.
type engagementStageMiddleware struct {
	*adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]
	db             *database.DB
	conversationID string
}

// newEngagementStageMiddleware returns the middleware, or nil when db is nil or conversationID is
// empty (callers should skip attaching a nil middleware).
func newEngagementStageMiddleware(db *database.DB, conversationID string) adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	conversationID = strings.TrimSpace(conversationID)
	if db == nil || conversationID == "" {
		return nil
	}
	return &engagementStageMiddleware{
		TypedBaseChatModelAgentMiddleware: &adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]{},
		db:                                db,
		conversationID:                    conversationID,
	}
}

func (w *engagementStageMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.TypedChatModelAgentState[*schema.AgenticMessage],
	mc *adk.TypedModelContext[*schema.AgenticMessage],
) (context.Context, *adk.TypedChatModelAgentState[*schema.AgenticMessage], error) {
	if w == nil || w.db == nil || state == nil {
		return ctx, state, nil
	}
	engagementID, err := w.db.ConversationEngagementID(w.conversationID)
	if err != nil || strings.TrimSpace(engagementID) == "" {
		return ctx, state, nil
	}
	stages, err := w.db.ListAssessmentStages(engagementID)
	if err != nil || len(stages) == 0 {
		return ctx, state, nil
	}

	// Auto-start: only the very first stage, only while it is still pending. A stage that is
	// already running/completed/skipped, or any later stage, is never auto-started here.
	if stages[0].Status == database.StagePending {
		messageID, _ := w.db.LatestMessageIDForConversation(w.conversationID)
		if _, startErr := w.db.TransitionAssessmentStage(engagementID, stages[0].Stage, database.StageTransition{
			Action:         database.StageActionStart,
			Actor:          "system",
			ConversationID: w.conversationID,
			MessageID:      messageID,
		}); startErr == nil {
			if refreshed, rerr := w.db.ListAssessmentStages(engagementID); rerr == nil {
				stages = refreshed
			}
		}
		// A conflict here just means another concurrent call already started it; nothing to do.
	}

	cur := database.CurrentStage(stages)
	if cur == nil {
		// Every stage is completed or skipped; nothing left to remind the model about.
		return ctx, state, nil
	}

	evidence, _ := w.db.ListEvidence(engagementID)
	msg := buildEngagementStageContextMessage(cur, evidence)
	if msg == "" {
		return ctx, state, nil
	}
	if next, nerr := database.NextPlanTask(w.db, engagementID, cur.Stage); nerr == nil && next != nil {
		msg = appendNextTaskLine(msg, next.Title)
	}
	state.Messages = append(state.Messages, schema.SystemAgenticMessage(msg))
	return ctx, state, nil
}

// stageCompletionRuleText describes, in plain words, what completes a stage. It mirrors
// TransitionAssessmentStage's rules without duplicating their enforcement.
func stageCompletionRuleText(stage string) string {
	if stage == database.StageAuthorisation {
		return "complete once the engagement has an authorization note and at least one included scope target; or skip with a reason"
	}
	return "complete by citing at least one tool evidence ID recorded during this stage (manual uploads do not count); or skip with a reason"
}

// recentEvidenceIDs returns up to maxEngagementStageContextEvidenceIDs of the most recently
// recorded evidence IDs (IDs only, no content).
func recentEvidenceIDs(evidence []*database.Evidence) []string {
	if len(evidence) > maxEngagementStageContextEvidenceIDs {
		evidence = evidence[len(evidence)-maxEngagementStageContextEvidenceIDs:]
	}
	ids := make([]string, 0, len(evidence))
	for _, e := range evidence {
		if e == nil {
			continue
		}
		ids = append(ids, e.ID)
	}
	return ids
}

// buildEngagementStageContextMessage renders the stage-context system message, kept under
// maxEngagementStageContextChars and never including evidence content, only IDs.
func buildEngagementStageContextMessage(cur *database.AssessmentStage, evidence []*database.Evidence) string {
	if cur == nil {
		return ""
	}
	ids := recentEvidenceIDs(evidence)
	build := func(idCount int) string {
		idsPart := "(none yet)"
		if idCount > 0 {
			idsPart = strings.Join(ids[len(ids)-idCount:], ", ")
		}
		return fmt.Sprintf(
			"Assessment stage: %s (%s), status: %s.\nCompletion rule: %s.\nEvidence recorded so far (IDs only, last %d): %s.\nRecord progress with the engagement_stage tool: action=\"complete\" with evidence_ids, or action=\"skip\" with a reason.",
			cur.Title, cur.Stage, cur.Status, stageCompletionRuleText(cur.Stage), idCount, idsPart,
		)
	}
	msg := build(len(ids))
	for len(msg) > maxEngagementStageContextChars && len(ids) > 0 {
		ids = ids[1:]
		msg = build(len(ids))
	}
	if len(msg) > maxEngagementStageContextChars {
		msg = msg[:maxEngagementStageContextChars]
	}
	return msg
}

// appendNextTaskLine adds one "Next plan task" line, keeping the message within the length limit.
func appendNextTaskLine(msg, title string) string {
	title = strings.Join(strings.Fields(title), " ")
	if title == "" {
		return msg
	}
	line := "\nNext plan task: " + title
	if room := maxEngagementStageContextChars - len(msg); len(line) > room {
		if room <= len("\nNext plan task: ")+3 {
			return msg
		}
		line = line[:room]
	}
	return msg + line
}
