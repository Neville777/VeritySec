package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/einomcp"
	"veritysec/internal/mcp"
	"veritysec/internal/scope"
)

// directEngagementSource lets the scope guard treat an engagement ID as its own "conversation": the
// guard then checks that engagement's scope. Only existing engagements resolve.
type directEngagementSource struct{ db *database.DB }

func (s directEngagementSource) ConversationEngagementID(id string) (string, error) {
	if _, err := s.db.GetEngagement(id); err != nil {
		return "", err
	}
	return id, nil
}

func (s directEngagementSource) EngagementScopeJSON(id string) (json.RawMessage, error) {
	e, err := s.db.GetEngagement(id)
	if err != nil {
		return nil, err
	}
	return e.ScopeJSON, nil
}

// mcpScopeAuthorizer applies the engagement scope and approval rules to direct /api/mcp tool calls,
// the same rules the agent's tool bridge applies. A call that names a target must carry an
// X-Engagement-ID header; without one it is refused (fail closed). Calls that name no target are
// not network actions and proceed.
func mcpScopeAuthorizer(db *database.DB, cfg *config.Config) func(context.Context, string, map[string]interface{}) error {
	mw := cfg.MultiAgent.EinoMiddleware
	return func(ctx context.Context, toolName string, args map[string]interface{}) error {
		if !mw.EngagementScopeEnforcementEffective() {
			return nil
		}
		// Agent runs carry a conversation ID and are checked by the agent tool bridge, which knows the
		// conversation's engagement. This authorizer only covers direct /api/mcp calls.
		// Use typed execution origin if available, fall back to legacy boolean.
		if mcp.IsAgentExecution(ctx) {
			return nil
		}
		// Direct, background and external calls are checked against their engagement. Only agent calls
		// are left to the agent bridge. A call with no typed origin keeps the legacy direct-route test.
		if exec, ok := mcp.ExecutionContextFromContext(ctx); ok {
			if exec.Origin == mcp.OriginAgent {
				return nil
			}
		} else if !mcp.IsDirectMCPHTTP(ctx) {
			return nil
		}
		targets := scope.ExtractTargets(toolName, args)
		if len(targets) == 0 {
			// Approval applies even when a call names no target (for example a script).
			if engagementID := mcp.EngagementIDFromContext(ctx); engagementID != "" {
				if refusal := einomcp.DirectApprovalGate(einomcp.NewDBApprovalStore(db), mw.EngagementApprovalTTLEffective(), mw.EngagementApprovalRequiredTools, engagementID, toolName, nil, args); refusal != "" {
					return errors.New(refusal)
				}
			}
			return nil
		}
		engagementID := mcp.EngagementIDFromContext(ctx)
		if exec, ok := mcp.ExecutionContextFromContext(ctx); ok && strings.TrimSpace(exec.EngagementID) != "" {
			engagementID = strings.TrimSpace(exec.EngagementID)
		}
		if engagementID == "" {
			return fmt.Errorf("scope check refused: %s: a direct tool call that names a target needs an X-Engagement-ID header", targets[0])
		}
		guard := einomcp.NewScopeGuard(einomcp.ScopeGuardConfig{
			Enabled:        true,
			ConversationID: engagementID,
			Source:         directEngagementSource{db: db},
		})
		if guard == nil {
			return errors.New("scope check refused: could not evaluate the engagement scope")
		}
		if refusal := guard(ctx, toolName, args); refusal != "" {
			return errors.New(refusal)
		}
		if refusal := einomcp.DirectApprovalGate(einomcp.NewDBApprovalStore(db), mw.EngagementApprovalTTLEffective(), mw.EngagementApprovalRequiredTools, engagementID, toolName, targets, args); refusal != "" {
			return errors.New(refusal)
		}
		return nil
	}
}

// chainToolAuthorizers runs each authorizer in order and returns the first refusal.
func chainToolAuthorizers(authorizers ...func(context.Context, string, map[string]interface{}) error) func(context.Context, string, map[string]interface{}) error {
	return func(ctx context.Context, toolName string, args map[string]interface{}) error {
		for _, a := range authorizers {
			if a == nil {
				continue
			}
			if err := a(ctx, toolName, args); err != nil {
				return err
			}
		}
		return nil
	}
}
