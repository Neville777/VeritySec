package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"veritysec/internal/audit"
	"veritysec/internal/database"
	"veritysec/internal/handler"
	"veritysec/internal/mcp"
)

// conversationAndMessageForStageCheckpoint returns the current run's conversation and (best
// effort) message ID, so the checkpoint written by this transition can be found by a later
// GET resume-plan. It never fails the transition: a lookup error just leaves the IDs empty.
func conversationAndMessageForStageCheckpoint(ctx context.Context, db *database.DB) (conversationID, messageID string) {
	conversationID = mcp.MCPConversationIDFromContext(ctx)
	if conversationID == "" || db == nil {
		return conversationID, ""
	}
	messageID, _ = db.LatestMessageIDForConversation(conversationID)
	return conversationID, messageID
}

// errStageEngagementRequired is returned when engagement_id is omitted and the conversation has none.
const errStageEngagementRequired = "engagement_id is required: this conversation is not attached to an engagement"

// fillStageEngagementID makes sure args["engagement_id"] is set. When it is missing it is resolved
// from the conversation in ctx and written into args, so the authorizer and the handler agree.
func fillStageEngagementID(ctx context.Context, db *database.DB, args map[string]interface{}) error {
	if args == nil {
		return errors.New(errStageEngagementRequired)
	}
	if s, _ := args["engagement_id"].(string); strings.TrimSpace(s) != "" {
		return nil
	}
	id := ""
	if db != nil {
		if conv := mcp.MCPConversationIDFromContext(ctx); conv != "" {
			id, _ = db.ConversationEngagementID(conv)
		}
	}
	if id == "" {
		// Direct MCP calls carry the engagement in the X-Engagement-ID header.
		id = mcp.EngagementIDFromContext(ctx)
	}
	if strings.TrimSpace(id) == "" {
		return errors.New(errStageEngagementRequired)
	}
	args["engagement_id"] = id
	return nil
}

// errStageRequired is returned when no stage was given and none can be inferred.
const errStageRequired = "stage is required: no stage is running or pending in this engagement"

// fillStageDefault makes sure args["stage"] is set for the start, complete and skip actions. When it
// is missing it defaults to the engagement's running stage, else to the first pending stage in the
// fixed order. It needs args["engagement_id"] (call fillStageEngagementID first).
func fillStageDefault(db *database.DB, args map[string]interface{}) error {
	if args == nil {
		return errors.New(errStageRequired)
	}
	switch strings.ToLower(strings.TrimSpace(func() string { s, _ := args["action"].(string); return s }())) {
	case "start", "complete", "skip":
	default:
		return nil
	}
	if s, _ := args["stage"].(string); strings.TrimSpace(s) != "" {
		return nil
	}
	eng, _ := args["engagement_id"].(string)
	if db == nil || strings.TrimSpace(eng) == "" {
		return errors.New(errStageRequired)
	}
	stages, err := db.ListAssessmentStages(eng)
	if err != nil {
		return err
	}
	for _, s := range stages {
		if s.Status == database.StageRunning {
			args["stage"] = s.Stage
			return nil
		}
	}
	for _, s := range stages {
		if s.Status == database.StagePending {
			args["stage"] = s.Stage
			return nil
		}
	}
	return errors.New(errStageRequired)
}

// EngagementStageToolName is the agent tool that moves an engagement through its assessment stages.
const EngagementStageToolName = "engagement_stage"

// registerEngagementStageTools registers engagement_stage. The stage rules are enforced by the
// same code the HTTP API uses; the model cannot bypass them.
func registerEngagementStageTools(mcpServer *mcp.Server, db *database.DB, auditSvc *audit.Service) {
	textResult := func(v interface{}, isErr bool) *mcp.ToolResult {
		b, _ := json.MarshalIndent(v, "", "  ")
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(b)}}, IsError: isErr}
	}
	tool := mcp.Tool{
		Name:             EngagementStageToolName,
		Description:      "Start, complete or skip one assessment stage of an engagement. Stages run in a fixed order: AUTHORISATION, RECONNAISSANCE, ASSET_DISCOVERY, ENUMERATION, VULNERABILITY_ASSESSMENT, FINDING_VALIDATION, IMPACT_ASSESSMENT, REPORT_GENERATION. A stage can start only when the previous one is completed or skipped. Completing needs evidence_ids of evidence stored in this engagement; skipping needs a reason. Completed or skipped stages cannot be changed. Returns the stage record or an error.",
		ShortDescription: "Advance an engagement assessment stage",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"engagement_id": map[string]interface{}{"type": "string", "description": "Engagement ID. Optional: defaults to the engagement this conversation is attached to."},
				"stage":         map[string]interface{}{"type": "string", "enum": stageNames(), "description": "Stage name. Optional for start, complete and skip: defaults to the engagement's running stage, else the first pending stage."},
				"action":        map[string]interface{}{"type": "string", "enum": []string{"start", "complete", "skip", "add_task", "create_plan", "add_plan_task", "set_plan_task"}, "description": "create_plan stores a draft task plan (objective) for the stage; add_plan_task appends a task (title, rationale, depends_on positions of earlier tasks) to a draft plan; set_plan_task moves a plan task pending->running->done on an active plan (a human activates plans). add_task appends a checklist item (title, optional description, required) to a stage that is not completed or skipped."},
				"evidence_ids":  map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Evidence IDs (required for complete)."},
				"note":          map[string]interface{}{"type": "string", "description": "Optional note when completing."},
				"reason":        map[string]interface{}{"type": "string", "description": "Required when skipping."},
				"title":         map[string]interface{}{"type": "string", "description": "Checklist item title (add_task)."},
				"description":   map[string]interface{}{"type": "string", "description": "Checklist item description (add_task)."},
				"required":      map[string]interface{}{"type": "boolean", "description": "Whether the item must be done before completing the stage (add_task; default true)."},
				"objective":     map[string]interface{}{"type": "string", "description": "Plan objective (create_plan)."},
				"plan_id":       map[string]interface{}{"type": "string", "description": "Plan ID (add_plan_task)."},
				"plan_task_id":  map[string]interface{}{"type": "string", "description": "Plan task ID (set_plan_task)."},
				"rationale":     map[string]interface{}{"type": "string", "description": "Why the task is needed (add_plan_task)."},
				"depends_on":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "integer"}, "description": "Positions of earlier plan tasks this one depends on (add_plan_task)."},
				"status":        map[string]interface{}{"type": "string", "enum": []string{"running", "done"}, "description": "New plan task status (set_plan_task)."},
			},
			"required": []string{"action"},
		},
	}
	mcpServer.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		if err := fillStageEngagementID(ctx, db, args); err != nil {
			return textResult(map[string]string{"error": err.Error()}, true), nil
		}
		if err := fillStageDefault(db, args); err != nil {
			return textResult(map[string]string{"error": err.Error()}, true), nil
		}
		str := func(k string) string { s, _ := args[k].(string); return s }
		var ids []string
		if arr, ok := args["evidence_ids"].([]interface{}); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					ids = append(ids, s)
				}
			}
		}
		switch str("action") {
		case "create_plan":
			p, err := db.CreateStagePlan(str("engagement_id"), str("stage"), str("objective"), database.StageTaskByModel)
			if err != nil {
				return textResult(map[string]string{"error": err.Error()}, true), nil
			}
			return textResult(map[string]interface{}{"plan": p, "note": "draft; a human must activate it"}, false), nil
		case "add_plan_task":
			var deps []int
			if arr, ok := args["depends_on"].([]interface{}); ok {
				for _, v := range arr {
					f, ok := v.(float64)
					if !ok || f != float64(int(f)) {
						return textResult(map[string]string{"error": "depends_on must be integers"}, true), nil
					}
					deps = append(deps, int(f))
				}
			}
			t, err := db.AddPlanTask(str("plan_id"), str("title"), str("rationale"), deps)
			if err != nil {
				return textResult(map[string]string{"error": err.Error()}, true), nil
			}
			return textResult(map[string]interface{}{"plan_task": t}, false), nil
		case "set_plan_task":
			t, err := db.SetPlanTaskStatus(str("plan_task_id"), str("status"), str("reason"), database.StageTaskByModel)
			if err != nil {
				return textResult(map[string]string{"error": err.Error()}, true), nil
			}
			return textResult(map[string]interface{}{"plan_task": t}, false), nil
		}
		if str("action") == "add_task" {
			stages, err := db.ListAssessmentStages(str("engagement_id"))
			if err != nil {
				return textResult(map[string]string{"error": err.Error()}, true), nil
			}
			for _, s := range stages {
				if strings.EqualFold(s.Stage, str("stage")) && (s.Status == database.StageCompleted || s.Status == database.StageSkipped) {
					return textResult(map[string]string{"error": "stage " + s.Stage + " is " + s.Status + "; checklist items can only be added to a stage that is not completed or skipped"}, true), nil
				}
			}
			in := database.StageTaskInput{Title: str("title"), Description: str("description"), ProposedBy: database.StageTaskByModel}
			if r, ok := args["required"].(bool); ok {
				in.Required = &r
			}
			t, err := db.CreateStageTask(str("engagement_id"), str("stage"), in)
			if err != nil {
				return textResult(map[string]string{"error": err.Error()}, true), nil
			}
			return textResult(map[string]interface{}{"task": t}, false), nil
		}
		conversationID, messageID := conversationAndMessageForStageCheckpoint(ctx, db)
		st, err := handler.ApplyStageTransition(db, auditSvc, nil, str("engagement_id"), str("stage"), database.StageTransition{
			Action: str("action"), EvidenceIDs: ids, Note: str("note"), Reason: str("reason"), Actor: "agent",
			ConversationID: conversationID, MessageID: messageID,
		})
		if err != nil {
			if _, ok := handler.StageErrorStatus(err); !ok && !errors.Is(err, database.ErrEngagementNotFound) {
				return textResult(map[string]string{"error": "internal error"}, true), nil
			}
			return textResult(map[string]string{"error": err.Error()}, true), nil
		}
		return textResult(map[string]interface{}{"stage": st}, false), nil
	})
}

func stageNames() []string {
	out := make([]string, len(database.AssessmentStageDefs))
	for i, d := range database.AssessmentStageDefs {
		out[i] = d.Name
	}
	return out
}
