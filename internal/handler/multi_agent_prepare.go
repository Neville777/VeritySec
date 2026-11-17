package handler

import (
	"fmt"
	"strings"

	"veritysec/internal/agent"
	"veritysec/internal/audit"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/mcp/builtin"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// multiAgentPrepared is the session and message preparation result of a multi-agent request before calling Eino.
type multiAgentPrepared struct {
	ConversationID     string
	CreatedNew         bool
	History            []agent.ChatMessage
	FinalMessage       string
	RoleTools          []string
	AssistantMessageID string
	UserMessageID      string
	OwnerUserID        string
}

func chatRequestAgentMode(req *ChatRequest, source string) string {
	if strings.HasPrefix(strings.TrimSpace(source), "multi_agent") {
		return config.NormalizeMultiAgentOrchestration(req.Orchestration)
	}
	return "eino_single"
}

func (h *AgentHandler) prepareMultiAgentSession(req *ChatRequest, c *gin.Context, source string) (*multiAgentPrepared, error) {
	if len(req.Attachments) > maxAttachments {
		return nil, fmt.Errorf("at most %d attachments allowed", maxAttachments)
	}

	conversationID := strings.TrimSpace(req.ConversationID)
	projectID := strings.TrimSpace(effectiveProjectID(h.config, req.ProjectID))
	webshellID := strings.TrimSpace(req.WebShellConnectionID)
	session, hasSession := security.CurrentSession(c)
	if !hasSession || !session.Permissions["chat:write"] {
		return nil, fmt.Errorf("no permission to write to the conversation")
	}
	canAccess := func(resourceType, resourceID string) bool {
		if !hasSession || h.db == nil || strings.TrimSpace(resourceID) == "" {
			return false
		}
		return h.db.UserCanAccessResource(session.UserID, session.Scope, resourceType, resourceID)
	}
	if projectID != "" && (!session.Permissions["project:read"] || !canAccess("project", projectID)) {
		return nil, fmt.Errorf("no permission to access the target project")
	}
	if webshellID != "" && (!session.Permissions["webshell:write"] || !canAccess("webshell", webshellID)) {
		return nil, fmt.Errorf("no permission to access this WebShell connection")
	}
	createdNew := false
	if conversationID == "" {
		title := safeTruncateString(req.Message, 50)
		var conv *database.Conversation
		var err error
		// No project chosen for a new chat: create one, named from the first message, and bind the chat to it.
		if projectID == "" && webshellID == "" && h.config != nil && h.config.Project.AutoCreateChatProjectsEnabled() &&
			session.Permissions["project:write"] && strings.TrimSpace(req.Message) != "" {
			if proj, perr := h.db.CreateProject(&database.Project{Name: h.autoNameProject(c.Request.Context(), req.Message), Status: "active"}); perr == nil {
				projectID = proj.ID
				_ = h.db.SetResourceOwner("project", proj.ID, session.UserID)
			}
		}
		meta := audit.ConversationCreateMetaFromGin(c, source)
		meta.ProjectID = projectID
		meta.RoleName = req.Role
		meta.AgentMode = chatRequestAgentMode(req, source)
		if webshellID != "" {
			meta.Source = source + "_webshell"
			meta.WebShellConnectionID = webshellID
			conv, err = h.db.CreateConversationWithWebshell(meta.WebShellConnectionID, title, meta)
		} else {
			conv, err = h.db.CreateConversation(title, meta)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create conversation: %w", err)
		}
		conversationID = conv.ID
		createdNew = true
		if hasSession {
			_ = h.db.SetResourceOwner("conversation", conversationID, session.UserID)
			_ = h.db.AssignResourceToUser(session.UserID, "conversation", conversationID)
		}
	} else {
		if _, err := h.db.GetConversation(conversationID); err != nil {
			return nil, fmt.Errorf("conversation not found")
		}
		if !canAccess("conversation", conversationID) {
			return nil, fmt.Errorf("no permission to access this conversation")
		}
	}
	if h.tasks != nil && h.tasks.GetTask(conversationID) != nil {
		return nil, ErrTaskAlreadyRunning
	}
	if err := h.db.SetConversationRoleName(conversationID, req.Role); err != nil {
		h.logger.Warn("failed to update conversation role", zap.String("conversationId", conversationID), zap.String("role", req.Role), zap.Error(err))
	}
	if err := h.db.SetConversationAgentMode(conversationID, chatRequestAgentMode(req, source)); err != nil {
		h.logger.Warn("failed to update conversation mode", zap.String("conversationId", conversationID), zap.String("source", source), zap.String("orchestration", req.Orchestration), zap.Error(err))
	}

	agentHistoryMessages, err := h.loadHistoryFromAgentTrace(conversationID)
	if err != nil {
		historyMessages, getErr := h.db.GetMessages(conversationID)
		if getErr != nil {
			agentHistoryMessages = []agent.ChatMessage{}
		} else {
			agentHistoryMessages = dbMessagesToAgentChatMessages(historyMessages)
		}
	}

	resolvedMessage, resolveErr := h.db.ResolveConversationPlaceholders(conversationID, req.Message)
	if resolveErr != nil {
		return nil, fmt.Errorf("failed to resolve conversation placeholder: %w", resolveErr)
	}
	req.Message = resolvedMessage
	finalMessage := req.Message
	var roleTools []string
	if webshellID != "" {
		conn, errConn := h.db.GetWebshellConnection(webshellID)
		if errConn != nil || conn == nil {
			h.logger.Warn("WebShell AI assistant: connection not found", zap.String("id", req.WebShellConnectionID), zap.Error(errConn))
			return nil, fmt.Errorf("WebShell connection not found")
		}
		webshellContext := BuildWebshellAssistantContext(conn, WebshellSkillHintMultiAgent, req.Message)
		// In WebShell mode, if a role is also specified, append the role user_prompt (the toolset is still limited to WebShell-specific tools)
		if req.Role != "" && req.Role != "default" && h.config != nil && h.config.Roles != nil {
			if role, exists := h.config.Roles[req.Role]; exists && role.Enabled && role.UserPrompt != "" {
				finalMessage = role.UserPrompt + "\n\n" + webshellContext
				h.logger.Info("WebShell + role: applying role prompt (multi-agent)", zap.String("role", req.Role))
			} else {
				finalMessage = webshellContext
			}
		} else {
			finalMessage = webshellContext
		}
		roleTools = []string{
			builtin.ToolWebshellExec,
			builtin.ToolWebshellFileList,
			builtin.ToolWebshellFileRead,
			builtin.ToolWebshellFileWrite,
			builtin.ToolRecordVulnerability,
			builtin.ToolListVulnerabilities,
			builtin.ToolGetVulnerability,
			builtin.ToolUpdateVulnerabilityStatus,
			builtin.ToolUpsertProjectFact,
			builtin.ToolGetProjectFact,
			builtin.ToolListProjectFacts,
			builtin.ToolSearchProjectFacts,
			builtin.ToolDeprecateProjectFact,
			builtin.ToolRestoreProjectFact,
			builtin.ToolListKnowledgeRiskTypes,
			builtin.ToolSearchKnowledgeBase,
		}
	} else if req.Role != "" && req.Role != "default" && h.config != nil && h.config.Roles != nil {
		if role, exists := h.config.Roles[req.Role]; exists && role.Enabled {
			if role.UserPrompt != "" {
				finalMessage = role.UserPrompt + "\n\n" + req.Message
			}
			roleTools = role.Tools
		}
	}

	retest, retestErr := h.db.GetVulnerabilityRetest(conversationID)
	if retestErr != nil {
		return nil, fmt.Errorf("failed to read retest context: %w", retestErr)
	}
	if retest != nil && len(roleTools) > 0 {
		// Retesting requires these tools even when the inherited role has an
		// older tool allowlist. MCP still enforces user and finding permissions.
		roleTools = append(append([]string(nil), roleTools...), builtin.ToolGetVulnerability, builtin.ToolUpdateVulnerabilityStatus)
	}

	finalMessage, resolveErr = h.db.ResolveConversationPlaceholders(conversationID, finalMessage)
	if resolveErr != nil {
		return nil, fmt.Errorf("failed to resolve prompt placeholder: %w", resolveErr)
	}

	var savedPaths []string
	if len(req.Attachments) > 0 {
		var aerr error
		savedPaths, aerr = saveAttachmentsToDateAndConversationDir(req.Attachments, conversationID, h.logger)
		if aerr != nil {
			return nil, fmt.Errorf("failed to save uploaded file: %w", aerr)
		}
	}
	finalMessage = appendAttachmentsToMessage(finalMessage, req.Attachments, savedPaths)

	userContent := userMessageContentForStorage(req.Message, req.Attachments, savedPaths)
	userMsgRow, uerr := h.db.AddMessage(conversationID, "user", userContent, nil)
	if uerr != nil {
		h.logger.Error("failed to save user message", zap.Error(uerr))
		return nil, fmt.Errorf("failed to save user message: %w", uerr)
	}
	if retest != nil {
		if err := h.db.SetVulnerabilityRetestPrompt(conversationID, ""); err != nil {
			h.logger.Warn("failed to clear sent retest prompt", zap.Error(err))
		}
	}
	userMessageID := ""
	if userMsgRow != nil {
		userMessageID = userMsgRow.ID
	}

	assistantMsg, aerr := h.db.AddMessage(conversationID, "assistant", "Processing...", nil)
	var assistantMessageID string
	if aerr != nil {
		h.logger.Warn("failed to create assistant message placeholder", zap.Error(aerr))
	} else if assistantMsg != nil {
		assistantMessageID = assistantMsg.ID
	}

	return &multiAgentPrepared{
		ConversationID:     conversationID,
		CreatedNew:         createdNew,
		History:            agentHistoryMessages,
		FinalMessage:       finalMessage,
		RoleTools:          roleTools,
		AssistantMessageID: assistantMessageID,
		UserMessageID:      userMessageID,
		OwnerUserID:        session.UserID,
	}, nil
}
