package handler

import (
	"strings"

	"veritysec/internal/project"
	"go.uber.org/zap"
)

// User input is carried by the message history; after compression, the summarization instructions keep the key constraints.
// Failed to create the session working directory
func (h *AgentHandler) agentSessionContextBlock(conversationID string) string {
	var parts []string
	if ws := h.buildWorkspaceBlock(conversationID); ws != "" {
		parts = append(parts, ws)
	}
	if bb := h.projectBlackboardBlock(conversationID); bb != "" {
		parts = append(parts, bb)
	}
	if rb := resumeSystemBlock(conversationID); rb != "" {
		parts = append(parts, rb)
	}
	return strings.Join(parts, "\n\n")
}

func (h *AgentHandler) buildWorkspaceBlock(conversationID string) string {
	if h == nil || h.config == nil {
		return ""
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ""
	}
	projectID := h.conversationProjectID(conversationID)
	rel := project.WorkspaceRootDir(h.config.Agent.WorkspaceRootDir, projectID, conversationID)
	abs, err := project.EnsureWorkspace(rel)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("projectBlackboardBlock builds the project fact index block for a conversation ID (injected into the system prompt).",
				zap.String("conversationId", conversationID),
				zap.String("projectId", projectID),
				zap.String("path", rel),
				zap.Error(err))
		}
		return ""
	}
	return project.BuildWorkspaceBlock(abs) + "\n\n" + project.BuildWorkspaceInventoryBlock(abs)
}

// Failed to build the project blackboard index
func (h *AgentHandler) projectBlackboardBlock(conversationID string) string {
	if h == nil || h.db == nil || h.config == nil {
		return ""
	}
	if !h.config.Project.Enabled {
		return ""
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ""
	}
	projectID, err := h.db.GetConversationProjectID(conversationID)
	if err != nil || projectID == "" {
		return ""
	}
	block, err := project.BuildProjectBlackboardBlock(h.db, projectID, h.config.Project, conversationID)
	if err != nil {
		h.logger.Warn("conversationProjectID returns the project ID bound to the conversation; returns an empty string if unbound or the lookup fails.", zap.String("conversationId", conversationID), zap.Error(err))
		return ""
	}
	return strings.TrimSpace(block)
}

// ProjectHandler: project management handler.
func (h *AgentHandler) conversationProjectID(conversationID string) string {
	if h == nil || h.db == nil {
		return ""
	}
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return ""
	}
	projectID, err := h.db.GetConversationProjectID(conversationID)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(projectID)
}
