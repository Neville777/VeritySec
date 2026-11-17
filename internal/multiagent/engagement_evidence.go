package multiagent

import (
	"context"
	"path/filepath"
	"strings"
	"sync"

	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/einomcp"
	"veritysec/internal/observations"

	"go.uber.org/zap"
)

// maxEngagementToolEvidenceBytes bounds a single tool-result evidence item (1 MiB); larger
// results are truncated and the title notes the truncation.
const maxEngagementToolEvidenceBytes = 1 << 20

// evidenceRootFromDBPath mirrors internal/app's evidence root: a sibling "evidence" directory next
// to the conversations database file.
func evidenceRootFromDBPath(dbPath string) string {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		dbPath = "data/conversations.db"
	}
	return filepath.Join(filepath.Dir(dbPath), "evidence")
}

// newEngagementToolEvidenceRecorder returns an einomcp.ToolResultEvidenceRecorder that stores each
// tool result of an engagement-bound conversation as evidence (kind tool_output, title and
// source_tool set to the tool name), using the same EvidenceStore.Save hashing/storage rules as
// evidence created over HTTP, and appends "[evidence: <id>]" to the text shown to the model.
//
// It returns nil when db is nil, the flag is off, or conversationID is empty, so callers can pass
// the result straight to einomcp.ToolsFromDefinitionsWithEvidence without a nil check. The
// returned function itself is also nil-safe for conversations that turn out to have no engagement:
// it looks the engagement up on every call (cheap, and always current) and returns the content
// unchanged when there is none.
func newEngagementToolEvidenceRecorder(db *database.DB, appCfg *config.Config, mw *config.MultiAgentEinoMiddlewareConfig, conversationID string, logger *zap.Logger) einomcp.ToolResultEvidenceRecorder {
	if db == nil || mw == nil || !mw.EngagementAutoStagesEffective() {
		return nil
	}
	convID := strings.TrimSpace(conversationID)
	if convID == "" {
		return nil
	}
	dbPath := ""
	if appCfg != nil {
		dbPath = appCfg.Database.Path
	}
	store := &database.EvidenceStore{Root: evidenceRootFromDBPath(dbPath)}
	var seqMu sync.Mutex
	seq := 0
	nextSeq := func() int {
		seqMu.Lock()
		defer seqMu.Unlock()
		seq++
		return seq
	}
	return func(ctx context.Context, toolName, executionID, content string) string {
		engagementID, err := db.ConversationEngagementID(convID)
		if err != nil || strings.TrimSpace(engagementID) == "" {
			return content
		}
		if strings.TrimSpace(content) == "" {
			return content
		}
		// read_evidence only re-reads stored evidence; recording it again would duplicate the row,
		// and without an evidence line it is never compacted, so it cannot loop.
		if strings.TrimSpace(toolName) == "read_evidence" {
			return content
		}
		body := content
		truncated := false
		if len(body) > maxEngagementToolEvidenceBytes {
			body = body[:maxEngagementToolEvidenceBytes]
			truncated = true
		}
		title := strings.TrimSpace(toolName)
		if title == "" {
			title = "tool"
		}
		if truncated {
			title += " (truncated)"
		}
		ev := database.NewEvidenceRecord(engagementID)
		ev.Kind = database.EvidenceToolOutput
		ev.Title = title
		ev.SourceTool = toolName
		// Provenance: a tool-recorded row. ToolExecutionID stays empty (NULL) when the MCP result
		// carried no execution ID. InsertEvidence stamps the engagement's current stage.
		ev.Origin = database.EvidenceOriginTool
		ev.ToolExecutionID = strings.TrimSpace(executionID)
		rel, sum, size, err := store.Save(engagementID, ev.ID, []byte(body))
		if err != nil {
			if logger != nil {
				logger.Warn("engagement evidence: save failed", zap.String("engagementId", engagementID), zap.Error(err))
			}
			return content
		}
		ev.StoragePath, ev.SHA256, ev.SizeBytes = rel, sum, size
		if err := db.InsertEvidence(ev); err != nil {
			if logger != nil {
				logger.Warn("engagement evidence: insert failed", zap.String("engagementId", engagementID), zap.Error(err))
			}
			return content
		}
		// Durable checkpoint for this tool execution: IDs only (the execution ID this evidence
		// came from, the evidence row it produced, and the stage that was current), never the
		// tool output itself. Best-effort: a failure here never blocks recording the evidence.
		messageID, _ := db.LatestMessageIDForConversation(convID)
		if err := db.WriteRunCheckpoint(messageID, convID, engagementID, ev.Stage, database.CheckpointKindToolExecution, map[string]interface{}{
			"tool_execution_id": ev.ToolExecutionID, "evidence_id": ev.ID, "stage": ev.Stage, "sequence": nextSeq(),
		}); err != nil && logger != nil {
			logger.Warn("engagement evidence: checkpoint write failed", zap.String("engagementId", engagementID), zap.Error(err))
		}
		// Evidence creation as a run event (IDs only). Best-effort run attribution: the caller does
		// not know the run ID, so messageID is the conversation's latest message.
		db.AppendRunEventBestEffort(messageID, convID, engagementID, "evidence_created", ev.Stage, map[string]interface{}{
			"evidence_id": ev.ID, "tool_execution_id": ev.ToolExecutionID, "source_tool": toolName, "stage": ev.Stage,
		})
		return content + "\n[evidence: " + ev.ID + "]"
	}
}

// newEngagementScopeGuard returns the scope guard for the MCP bridge, or nil when db is nil or
// engagement.scope_enforcement is off. Conversations without an engagement are not checked (the
// guard looks the engagement up per call, like the evidence recorder).
func newEngagementScopeGuard(db *database.DB, mw *config.MultiAgentEinoMiddlewareConfig, conversationID string, progress func(string, string, interface{}), logger *zap.Logger) einomcp.ScopeGuard {
	if db == nil || mw == nil || !mw.EngagementScopeEnforcementEffective() {
		return nil
	}
	return einomcp.NewScopeGuard(einomcp.ScopeGuardConfig{
		Enabled:        true,
		ConversationID: conversationID,
		Source:         einomcp.NewDBScopeSource(db),
		Progress:       progress,
		Logger:         logger,

		ApprovalRequiredTools: mw.EngagementApprovalRequiredTools,
		Approvals:             einomcp.NewDBApprovalStore(db),
		ApprovalTTL:           mw.EngagementApprovalTTLEffective(),
	})
}

// recordToolObservations extracts deterministic observations from a tool output and stores them in
// one transaction. It never fails the tool run: errors are logged and an empty string is returned.
// On success it returns the model-facing block (see einomcp observation markers), or "" when there
// is nothing to show.
func recordToolObservations(db *database.DB, logger *zap.Logger, toolName, executionID, evidenceID, engagementID, body string) (block string) {
	defer func() {
		if r := recover(); r != nil {
			if logger != nil {
				logger.Warn("tool observations: extraction panicked", zap.Any("panic", r))
			}
			block = ""
		}
	}()
	if strings.TrimSpace(executionID) == "" {
		return ""
	}
	found := observations.ExtractObservations(toolName, body, observations.MaxPerExecution)
	if len(found) == 0 {
		return ""
	}
	rows := make([]database.ToolObservation, 0, len(found))
	for _, o := range found {
		rows = append(rows, database.ToolObservation{Kind: o.Kind, Subject: o.Subject, Attribute: o.Attribute, Value: o.Value})
	}
	if err := db.InsertToolObservations(executionID, evidenceID, engagementID, rows); err != nil {
		if logger != nil {
			logger.Warn("tool observations: insert failed", zap.String("engagementId", engagementID), zap.Error(err))
		}
		return ""
	}
	return einomcp.FormatObservationBlock(found)
}
