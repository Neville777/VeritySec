package einomcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"veritysec/internal/audit"
	"veritysec/internal/database"
	"veritysec/internal/scope"

	"go.uber.org/zap"
)

// ScopeGuard is the restriction hook the MCP bridge runs before dispatching a tool call. It
// returns a non-empty refusal text to block the call; "" lets the call proceed unchanged. It can
// only refuse: it never runs a tool, sends traffic or resolves names.
type ScopeGuard func(ctx context.Context, toolName string, args map[string]interface{}) (refusal string)

// ScopeSource is the engagement lookup the guard needs. *database.DB satisfies it through
// NewDBScopeSource, using the same resolver as the evidence recorder (ConversationEngagementID).
type ScopeSource interface {
	ConversationEngagementID(conversationID string) (string, error)
	EngagementScopeJSON(engagementID string) (json.RawMessage, error)
}

type dbScopeSource struct{ db *database.DB }

// NewDBScopeSource adapts a database handle to ScopeSource.
func NewDBScopeSource(db *database.DB) ScopeSource {
	if db == nil {
		return nil
	}
	return dbScopeSource{db}
}

func (s dbScopeSource) ConversationEngagementID(id string) (string, error) {
	return s.db.ConversationEngagementID(id)
}

func (s dbScopeSource) EngagementScopeJSON(id string) (json.RawMessage, error) {
	e, err := s.db.GetEngagement(id)
	if err != nil {
		return nil, err
	}
	return e.ScopeJSON, nil
}

var scopeAuditSink atomic.Value // func(audit.Entry)

// SetScopeAuditSink registers where scope refusals are audited (the platform audit service).
func SetScopeAuditSink(fn func(audit.Entry)) { scopeAuditSink.Store(fn) }

func defaultScopeAuditSink() func(audit.Entry) {
	fn, _ := scopeAuditSink.Load().(func(audit.Entry))
	return fn
}

// ScopeGuardConfig configures NewScopeGuard.
type ScopeGuardConfig struct {
	Enabled        bool // engagement.scope_enforcement
	ConversationID string
	Source         ScopeSource
	// Progress is the run's progress callback; a "scope_refused" event is emitted through it and
	// persisted as a process-detail step by the existing progress path. May be nil.
	Progress func(eventType, message string, data interface{})
	// Audit receives one entry per refused call. Defaults to the sink set by SetScopeAuditSink.
	Audit  func(audit.Entry)
	Now    func() time.Time
	Logger *zap.Logger
	// Resolve looks a hostname up for the name-resolution check. Injectable so tests do not hit
	// DNS; nil uses the system resolver. The guard bounds each lookup to ResolveTimeout.
	Resolve        Resolver
	ResolveTimeout time.Duration // default 3s

	// ApprovalRequiredTools (engagement.approval_required_tools) lists tools that need a person's
	// approval even when every target is in scope. Empty = none. Needs Approvals.
	ApprovalRequiredTools []string
	Approvals             ApprovalStore
	ApprovalTTL           time.Duration // default 30 minutes
}

// ApprovalStore is the approval persistence the guard needs; *database.DB satisfies it through
// NewDBApprovalStore. Only argument hashes are ever passed, never arguments.
type ApprovalStore interface {
	RequestApproval(engagementID, conversationID, messageID, tool, target, argsHash string, now time.Time, ttl time.Duration) (*database.ApprovalRequest, bool, error)
	ConsumeApproval(engagementID, tool, target, argsHash string, now time.Time) (bool, error)
	LatestMessageIDForConversation(conversationID string) (string, error)
}

// NewDBApprovalStore adapts a database handle to ApprovalStore.
func NewDBApprovalStore(db *database.DB) ApprovalStore {
	if db == nil {
		return nil
	}
	return db
}

// Resolver resolves a hostname to its addresses.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// DefaultResolver uses the system resolver.
func DefaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// NewScopeGuard builds the guard, or returns nil (no check at all) when enforcement is off, there
// is no conversation or no data source. Evaluation order per call:
//
//  1. Targets are extracted from the arguments (scope.ExtractTargets). A call that names no
//     target is not a network action and proceeds unchanged.
//  2. The conversation's engagement is resolved. A conversation with NO engagement is not
//     scope-checked at all (there is no scope to enforce) and proceeds unchanged.
//  3. Every target is evaluated. Anything but IN_SCOPE refuses the whole call; if the engagement
//     or its scope cannot be loaded or parsed the call is refused (fail closed), never allowed.
func NewScopeGuard(cfg ScopeGuardConfig) ScopeGuard {
	convID := strings.TrimSpace(cfg.ConversationID)
	if !cfg.Enabled || convID == "" || cfg.Source == nil {
		return nil
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return func(ctx context.Context, toolName string, args map[string]interface{}) string {
		targets := scope.ExtractTargets(toolName, args)
		if len(targets) == 0 {
			return ""
		}
		engagementID, err := cfg.Source.ConversationEngagementID(convID)
		if err != nil {
			return refuse(cfg, toolName, "", targets[0], "engagement lookup failed: "+err.Error())
		}
		if strings.TrimSpace(engagementID) == "" {
			return ""
		}
		raw, err := cfg.Source.EngagementScopeJSON(engagementID)
		var sc *scope.Scope
		if err == nil {
			sc, err = scope.Parse(raw)
		}
		if err != nil {
			return refuse(cfg, toolName, engagementID, targets[0], "scope unavailable: "+err.Error())
		}
		resolve := cfg.Resolve
		if resolve == nil {
			resolve = DefaultResolver
		}
		timeout := cfg.ResolveTimeout
		if timeout <= 0 {
			timeout = 3 * time.Second
		}
		type answer struct {
			ips []netip.Addr
			err error
		}
		cache := map[string]answer{} // per call
		var unresolved []string
		for _, t := range targets {
			d := scope.Evaluate(sc, t, now())
			if d.Result == scope.InScope {
				if host, ok := scope.ResolvableHost(t); ok {
					a, hit := cache[host]
					if !hit {
						rctx, cancel := context.WithTimeout(ctx, timeout)
						a.ips, a.err = resolve(rctx, host)
						cancel()
						cache[host] = a
						if a.err != nil || len(a.ips) == 0 {
							unresolved = append(unresolved, host)
						}
					}
					if a.err == nil && len(a.ips) > 0 {
						d = scope.EvaluateResolved(sc, t, now(), a.ips)
					}
				}
			}
			switch d.Result {
			case scope.InScope:
				continue
			case scope.RequiresApproval:
				return refuseText(cfg, toolName, engagementID, d, "approval required: "+t)
			default:
				if len(unresolved) > 0 {
					d.Reason += "; unresolved: " + strings.Join(unresolved, ",")
				}
				return refuseText(cfg, toolName, engagementID, d, fmt.Sprintf("scope check refused: %s: %s", t, d.Reason))
			}
		}
		if len(unresolved) > 0 {
			auditUnresolved(cfg, toolName, engagementID, unresolved)
		}
		return approvalGate(cfg, now(), engagementID, toolName, targets, args)
	}
}

// approvalGate runs after every target is IN_SCOPE. A tool not listed in ApprovalRequiredTools
// proceeds. A listed tool proceeds only if an approved, unexpired, unused request matches the
// engagement, tool, target and arguments hash (consumed atomically: one approval, one call);
// otherwise a pending request is created and the call is refused without running the tool.
func approvalGate(cfg ScopeGuardConfig, now time.Time, engagementID, tool string, targets []string, args map[string]interface{}) string {
	required := false
	for _, n := range cfg.ApprovalRequiredTools {
		if strings.TrimSpace(n) == tool {
			required = true
			break
		}
	}
	if !required {
		return ""
	}
	ts := append([]string(nil), targets...)
	sort.Strings(ts)
	target := strings.Join(ts, ",")
	d := scope.Decision{Result: scope.RequiresApproval, Target: target}
	if cfg.Approvals == nil {
		d.Reason = "approval store unavailable"
		return refuseText(cfg, tool, engagementID, d, "approval required: approval store unavailable; the call was not run")
	}
	hash := database.HashApprovalArguments(args)
	ok, err := cfg.Approvals.ConsumeApproval(engagementID, tool, target, hash, now)
	if err != nil {
		d.Reason = "approval lookup failed"
		return refuseText(cfg, tool, engagementID, d, "approval required: lookup failed: "+err.Error())
	}
	if ok {
		return ""
	}
	ttl := cfg.ApprovalTTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	msgID, _ := cfg.Approvals.LatestMessageIDForConversation(cfg.ConversationID)
	req, _, err := cfg.Approvals.RequestApproval(engagementID, cfg.ConversationID, msgID, tool, target, hash, now, ttl)
	if err != nil {
		d.Reason = "approval request failed"
		return refuseText(cfg, tool, engagementID, d, "approval required: could not record the request: "+err.Error())
	}
	text := "approval required: " + req.ID + "; a person must approve it in the engagement page"
	if cfg.Progress != nil {
		cfg.Progress("approval_requested", text, map[string]interface{}{
			"toolName": tool, "target": target, "approvalId": req.ID, "engagementId": engagementID,
		})
	}
	sink := cfg.Audit
	if sink == nil {
		sink = defaultScopeAuditSink()
	}
	if sink != nil {
		sink(audit.Entry{
			Category: "engagement_scope", Action: "approval_requested", Result: "success", Actor: "agent",
			ResourceType: "engagement", ResourceID: engagementID, Message: text,
			Detail: map[string]interface{}{"tool": tool, "target": target, "approval_id": req.ID, "conversation_id": cfg.ConversationID},
		})
	}
	return text
}

// auditUnresolved records that in-scope names could not be resolved: the name decision stands, but
// the address check could not run.
func auditUnresolved(cfg ScopeGuardConfig, tool, engagementID string, hosts []string) {
	sink := cfg.Audit
	if sink == nil {
		sink = defaultScopeAuditSink()
	}
	if sink == nil {
		return
	}
	sink(audit.Entry{
		Category: "engagement_scope", Action: "scope_unresolved", Result: "success", Actor: "agent",
		ResourceType: "engagement", ResourceID: engagementID,
		Message: "in-scope name(s) could not be resolved: " + strings.Join(hosts, ","),
		Detail:  map[string]interface{}{"tool": tool, "reason": "unresolved", "hosts": hosts, "conversation_id": cfg.ConversationID},
	})
}

func refuse(cfg ScopeGuardConfig, tool, engagementID, target, reason string) string {
	return refuseText(cfg, tool, engagementID, scope.Decision{Result: scope.Unknown, Reason: reason, Target: target},
		fmt.Sprintf("scope check refused: %s: %s", target, reason))
}

// refuseText records the refusal (process-detail step via progress + audit entry) and returns the
// tool-result text. The step carries the target and reason only, never tool arguments or output.
func refuseText(cfg ScopeGuardConfig, tool, engagementID string, d scope.Decision, text string) string {
	if cfg.Progress != nil {
		cfg.Progress("scope_refused", text, map[string]interface{}{
			"toolName": tool, "target": d.Target, "reason": d.Reason, "result": string(d.Result),
			"engagementId": engagementID,
		})
	}
	sink := cfg.Audit
	if sink == nil {
		sink = defaultScopeAuditSink()
	}
	if sink != nil {
		sink(audit.Entry{
			Category: "engagement_scope", Action: "scope_refused", Result: "failure", Actor: "agent",
			ResourceType: "engagement", ResourceID: engagementID,
			Message: text,
			Detail:  map[string]interface{}{"tool": tool, "target": d.Target, "reason": d.Reason, "result": string(d.Result), "conversation_id": cfg.ConversationID},
		})
	}
	if cfg.Logger != nil {
		cfg.Logger.Warn("scope refused tool call", zap.String("tool", tool), zap.String("target", d.Target), zap.String("reason", d.Reason))
	}
	return text
}

// DirectApprovalGate applies the approval rules to a call that has no conversation (a direct MCP
// call). It returns the refusal text, or "" when the call may proceed. It uses the same approval
// store, argument hash and single-use rule as the agent path.
func DirectApprovalGate(approvals ApprovalStore, ttl time.Duration, required []string, engagementID, tool string, targets []string, args map[string]interface{}) string {
	cfg := ScopeGuardConfig{ApprovalRequiredTools: required, Approvals: approvals, ApprovalTTL: ttl}
	return approvalGate(cfg, time.Now(), engagementID, tool, targets, args)
}
