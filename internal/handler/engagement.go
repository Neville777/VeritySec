package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"veritysec/internal/audit"
	"veritysec/internal/database"
	"veritysec/internal/redact"
	"veritysec/internal/report"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// EngagementHandler serves engagements, their evidence and the multi-audience report.
// Engagement and evidence routes reuse the project:* permissions.
type EngagementHandler struct {
	db     *database.DB
	store  *database.EvidenceStore
	logger *zap.Logger
	now    func() time.Time
	audit  *audit.Service
	// approvalTTL is how long a granted approval stays usable (0 = 30 minutes).
	approvalTTL time.Duration
	// retentionDays yields evidence.retention_days (0 = keep forever).
	retentionDays func() int
	// reportRoot holds rendered report snapshots; narrativeModel yields the model used when
	// narrative=true (nil: no model, narrative is skipped with a note).
	reportRoot     string
	narrativeModel func() report.NarrativeModel
}

// SetAudit wires platform audit logging.
func (h *EngagementHandler) SetAudit(s *audit.Service) { h.audit = s }

// record writes one audit entry; it never carries evidence or report content.
func (h *EngagementHandler) record(c *gin.Context, action, message, resourceType, resourceID string, detail map[string]interface{}) {
	if h.audit != nil {
		h.audit.RecordOK(c, "engagement", action, message, resourceType, resourceID, detail)
	}
}

// NewEngagementHandler creates the handler; evidenceRoot is the directory evidence files live in.
func NewEngagementHandler(db *database.DB, evidenceRoot string, logger *zap.Logger) *EngagementHandler {
	return &EngagementHandler{db: db, store: &database.EvidenceStore{Root: evidenceRoot}, logger: logger, now: time.Now,
		reportRoot: filepath.Join(filepath.Dir(filepath.Clean(evidenceRoot)), "reports")}
}

type engagementRequest struct {
	Name              string          `json:"name"`
	Objective         string          `json:"objective"`
	Target            string          `json:"target"`
	Status            string          `json:"status"`
	ScopeJSON         json.RawMessage `json:"scope_json"`
	LimitsJSON        json.RawMessage `json:"limits_json"`
	AuthorizationNote string          `json:"authorization_note"`
	ProjectID         string          `json:"project_id"`
}

// toEngagement validates lengths and converts the request.
func (r engagementRequest) toEngagement() (*database.Engagement, error) {
	for _, f := range []struct {
		v     string
		limit int
	}{{r.Name, 200}, {r.Objective, 5000}, {r.Target, 2000}, {r.AuthorizationNote, 5000}, {string(r.ScopeJSON), 100000}, {string(r.LimitsJSON), 100000}} {
		if utf8.RuneCountInString(f.v) > f.limit {
			return nil, errors.New("a field exceeds its length limit")
		}
	}
	return &database.Engagement{
		Name: r.Name, Objective: r.Objective, Target: r.Target, Status: strings.TrimSpace(r.Status),
		ScopeJSON: r.ScopeJSON, LimitsJSON: r.LimitsJSON, AuthorizationNote: r.AuthorizationNote,
		ProjectID: strings.TrimSpace(r.ProjectID),
	}, nil
}

// canAccess applies the session's scope for the given permission to one engagement.
func (h *EngagementHandler) canAccess(c *gin.Context, permission, engagementID string) bool {
	s, ok := security.CurrentSession(c)
	if !ok {
		return false
	}
	return h.db.UserCanAccessResource(s.UserID, s.ScopeFor(permission), "engagement", engagementID)
}

// canAccessProject applies the session's scope for the given permission to one project.
func (h *EngagementHandler) canAccessProject(c *gin.Context, permission, projectID string) bool {
	s, ok := security.CurrentSession(c)
	if !ok {
		return false
	}
	return h.db.UserCanAccessResource(s.UserID, s.ScopeFor(permission), "project", projectID)
}

// writeEngagementErr maps database errors to HTTP statuses.
func (h *EngagementHandler) writeErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, database.ErrEngagementNotFound), errors.Is(err, database.ErrEvidenceNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	default:
		h.logger.Error("engagement request failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	}
}

// ListEngagements GET /api/engagements
func (h *EngagementHandler) ListEngagements(c *gin.Context) {
	status := strings.TrimSpace(c.Query("status"))
	if status != "" && !database.ValidEngagementStatus(status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}
	all, err := h.db.ListEngagements(status)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	out := make([]*database.Engagement, 0, len(all))
	for _, e := range all {
		if h.canAccess(c, "project:read", e.ID) {
			out = append(out, e)
		}
	}
	c.JSON(http.StatusOK, gin.H{"engagements": out, "total": len(out)})
}

// CreateEngagement POST /api/engagements
func (h *EngagementHandler) CreateEngagement(c *gin.Context) {
	var req engagementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	e, err := req.toEngagement()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if e.ProjectID != "" && !h.canAccessProject(c, "project:read", e.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no access to the project"})
		return
	}
	session, _ := security.CurrentSession(c)
	e.OwnerUserID = session.UserID
	created, err := h.db.CreateEngagement(e)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if session.UserID != "" {
		_ = h.db.AssignResourceToUser(session.UserID, "engagement", created.ID)
	}
	h.record(c, "create", "Create engagement", "engagement", created.ID, map[string]interface{}{"name": created.Name, "status": created.Status})
	c.JSON(http.StatusOK, created)
}

// GetEngagement GET /api/engagements/:id
func (h *EngagementHandler) GetEngagement(c *gin.Context) {
	e, err := h.db.GetEngagement(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, e)
}

// UpdateEngagement PUT /api/engagements/:id
func (h *EngagementHandler) UpdateEngagement(c *gin.Context) {
	var req engagementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	e, err := req.toEngagement()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	existing, err := h.db.GetEngagement(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	if e.ProjectID != existing.ProjectID {
		// Changing an engagement's project requires write access to both the project it is
		// leaving and the one it is joining; either side alone could not re-link evidence and
		// findings the other side owns.
		if existing.ProjectID != "" && !h.canAccessProject(c, "project:write", existing.ProjectID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "no write access to the current project"})
			return
		}
		if e.ProjectID != "" && !h.canAccessProject(c, "project:write", e.ProjectID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "no write access to the target project"})
			return
		}
	} else if e.ProjectID != "" && !h.canAccessProject(c, "project:read", e.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no access to the project"})
		return
	}
	updated, err := h.db.UpdateEngagement(c.Param("id"), e)
	if err != nil {
		if errors.Is(err, database.ErrEngagementNotFound) {
			h.writeErr(c, err)
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.record(c, "update", "Update engagement", "engagement", updated.ID, map[string]interface{}{"name": updated.Name, "status": updated.Status})
	c.JSON(http.StatusOK, updated)
}

// DeleteEngagement DELETE /api/engagements/:id. Evidence is deleted; conversations and findings are only unlinked.
func (h *EngagementHandler) DeleteEngagement(c *gin.Context) {
	paths, err := h.db.DeleteEngagement(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	h.store.Remove(paths)
	h.record(c, "delete", "Delete engagement", "engagement", c.Param("id"), map[string]interface{}{"evidence_removed": len(paths)})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// AttachConversation POST /api/engagements/:id/conversations
func (h *EngagementHandler) AttachConversation(c *gin.Context) {
	var req struct {
		ConversationID string `json:"conversation_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.ConversationID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "conversation_id is required"})
		return
	}
	session, _ := security.CurrentSession(c)
	if !h.db.UserCanAccessResource(session.UserID, session.ScopeFor("project:write"), "conversation", req.ConversationID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no access to the conversation"})
		return
	}
	if err := h.db.AttachConversationToEngagement(c.Param("id"), req.ConversationID); err != nil {
		if err.Error() == "conversation not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		h.writeErr(c, err)
		return
	}
	h.record(c, "attach_conversation", "Attach conversation to engagement", "engagement", c.Param("id"), map[string]interface{}{"conversation_id": req.ConversationID})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// evidenceInput is the parsed body of an evidence upload.
type evidenceInput struct {
	Kind, Title, SourceTool, FindingID, AssetID string
	Content                                     []byte
}

// readEvidenceInput accepts multipart (file plus form fields) or JSON (content as text).
func readEvidenceInput(c *gin.Context) (*evidenceInput, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, database.MaxEvidenceBytes+(1<<20))
	in := &evidenceInput{}
	if strings.HasPrefix(c.ContentType(), "multipart/") {
		fh, err := c.FormFile("file")
		if err != nil {
			return nil, errors.New("multipart upload needs a file field named \"file\"")
		}
		f, err := fh.Open()
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if in.Content, err = io.ReadAll(io.LimitReader(f, database.MaxEvidenceBytes+1)); err != nil {
			return nil, err
		}
		in.Kind, in.Title, in.SourceTool = c.PostForm("kind"), c.PostForm("title"), c.PostForm("source_tool")
		in.FindingID, in.AssetID = c.PostForm("finding_id"), c.PostForm("asset_id")
		for _, f := range []string{"origin", "tool_execution_id"} {
			if _, set := c.GetPostForm(f); set {
				return nil, fmt.Errorf("%s cannot be set on an upload", f)
			}
		}
		if in.Title == "" {
			in.Title = fh.Filename
		}
		return in, nil
	}
	var req struct {
		Kind       string `json:"kind"`
		Title      string `json:"title"`
		SourceTool string `json:"source_tool"`
		FindingID  string `json:"finding_id"`
		AssetID    string `json:"asset_id"`
		Content    string `json:"content"`
		// Provenance is set by the server only; a caller supplying either field is refused.
		Origin          *string `json:"origin"`
		ToolExecutionID *string `json:"tool_execution_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		return nil, err
	}
	if req.Origin != nil {
		return nil, errors.New("origin cannot be set on an upload")
	}
	if req.ToolExecutionID != nil {
		return nil, errors.New("tool_execution_id cannot be set on an upload")
	}
	return &evidenceInput{Kind: req.Kind, Title: req.Title, SourceTool: req.SourceTool, FindingID: req.FindingID, AssetID: req.AssetID, Content: []byte(req.Content)}, nil
}

// CreateEvidence POST /api/engagements/:id/evidence
func (h *EngagementHandler) CreateEvidence(c *gin.Context) {
	engagementID := c.Param("id")
	if _, err := h.db.GetEngagement(engagementID); err != nil {
		h.writeErr(c, err)
		return
	}
	in, err := readEvidenceInput(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(in.Content) == 0 || len(in.Content) > database.MaxEvidenceBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "evidence content must be between 1 byte and the size limit"})
		return
	}
	ev := database.NewEvidenceRecord(engagementID)
	ev.Kind, ev.Title, ev.SourceTool = strings.TrimSpace(in.Kind), strings.TrimSpace(in.Title), strings.TrimSpace(in.SourceTool)
	ev.FindingID, ev.AssetID = strings.TrimSpace(in.FindingID), strings.TrimSpace(in.AssetID)
	ev.Origin = database.EvidenceOriginManual // uploads are always manual; InsertEvidence fills in the stage
	if ev.Kind == "" {
		ev.Kind = database.EvidenceOther
	}
	if !database.ValidEvidenceKind(ev.Kind) || utf8.RuneCountInString(ev.Title) > 300 || utf8.RuneCountInString(ev.SourceTool) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid kind, or title/source_tool too long"})
		return
	}
	rel, sum, size, err := h.store.Save(engagementID, ev.ID, in.Content)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	ev.StoragePath, ev.SHA256, ev.SizeBytes = rel, sum, size
	if err := h.db.InsertEvidence(ev); err != nil {
		h.store.Remove([]string{rel})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.record(c, "evidence_upload", "Upload engagement evidence", "evidence", ev.ID, map[string]interface{}{
		"engagement_id": engagementID, "kind": ev.Kind, "size_bytes": ev.SizeBytes, "sha256": ev.SHA256,
	})
	c.JSON(http.StatusOK, ev)
}

// ListEvidence GET /api/engagements/:id/evidence (metadata only)
func (h *EngagementHandler) ListEvidence(c *gin.Context) {
	if _, err := h.db.GetEngagement(c.Param("id")); err != nil {
		h.writeErr(c, err)
		return
	}
	list, err := h.db.ListEvidence(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"evidence": list, "total": len(list)})
}

// GetEvidence GET /api/evidence/:id. The stored hash is verified on every read; text kinds
// return their content only when it verifies.
func (h *EngagementHandler) GetEvidence(c *gin.Context) {
	ev, err := h.db.GetEvidence(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	// There is no evidence:download_raw permission in the catalog, so raw (unredacted) content
	// requires project:write. Callers without it get a redacted copy; asking for ?raw=1
	// explicitly without it is refused with 403.
	sess, _ := security.CurrentSession(c)
	canRaw := sess.Permissions["project:write"]
	if (c.Query("raw") == "1" || c.Query("raw") == "true") && !canRaw {
		c.JSON(http.StatusForbidden, gin.H{"error": "raw evidence requires project:write", "permission": "project:write"})
		return
	}
	raw := canRaw
	data, err := h.store.Read(ev)
	switch {
	case errors.Is(err, database.ErrEvidencePurged):
		c.JSON(http.StatusGone, gin.H{"error": err.Error(), "integrity": "purged", "sha256": ev.SHA256, "evidence": ev})
		return
	case errors.Is(err, database.ErrEvidenceHashMismatch), errors.Is(err, database.ErrEvidenceMissing):
		integrity := "mismatch"
		if errors.Is(err, database.ErrEvidenceMissing) {
			integrity = "missing"
		}
		h.logger.Warn("evidence integrity failure", zap.String("evidence_id", ev.ID), zap.String("integrity", integrity))
		c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "integrity": integrity, "evidence": ev})
		return
	case err != nil:
		h.writeErr(c, err)
		return
	}
	h.record(c, "evidence_read", "Read engagement evidence", "evidence", ev.ID, map[string]interface{}{"engagement_id": ev.EngagementID, "kind": ev.Kind})
	resp := gin.H{"evidence": ev, "integrity": "verified", "content_available": false}
	if database.IsTextEvidenceKind(ev.Kind) {
		// Redaction is applied to the returned copy only; the stored bytes and the sha256 in
		// "evidence" describe the original.
		content := string(data)
		if !raw {
			var found []redact.Finding
			content, found = redact.Redact(content)
			resp["redactions"] = redact.Summary(found)
		}
		resp["content"], resp["content_available"], resp["redacted"] = content, true, !raw
	}
	c.JSON(http.StatusOK, resp)
}

// SetRetention wires evidence.retention_days.
func (h *EngagementHandler) SetRetention(f func() int) { h.retentionDays = f }

// PurgeEvidence POST /api/evidence/purge (config:write, all-scope; see rbac_middleware). Deletes
// stored evidence files older than evidence.retention_days; rows and sha256 stay. Returns counts.
func (h *EngagementHandler) PurgeEvidence(c *gin.Context) {
	days := 0
	if h.retentionDays != nil {
		days = h.retentionDays()
	}
	res, err := h.db.PurgeExpiredEvidence(h.store, days, h.now())
	if err != nil {
		h.writeErr(c, err)
		return
	}
	h.record(c, "evidence_purge", "Purged expired evidence files", "evidence", "", map[string]interface{}{"retention_days": days, "purged": res.Purged, "failed": res.Failed})
	c.JSON(http.StatusOK, res)
}

// inferAudience picks the report view. Order: explicit query parameter, then the requester's
// role (admin or owner roles, or the engagement owner, get technical), then executive. It only
// selects a template; the dataset (counts, severities, findings) is built independently.
func inferAudience(c *gin.Context, ownerUserID string) (report.Audience, string, error) {
	if raw := strings.TrimSpace(c.Query("audience")); raw != "" {
		a, err := report.ParseAudience(raw)
		return a, "query parameter", err
	}
	if s, ok := security.CurrentSession(c); ok {
		for _, r := range s.Roles {
			switch strings.ToLower(strings.TrimSpace(r)) {
			case database.RBACSystemRoleAdmin, "owner":
				return report.Technical, "role " + strings.ToLower(strings.TrimSpace(r)), nil
			}
		}
		if s.UserID != "" && s.UserID == ownerUserID {
			return report.Technical, "engagement owner", nil
		}
	}
	return report.Executive, "default", nil
}

// safeFilenamePart keeps a value usable inside a Content-Disposition filename.
func safeFilenamePart(v string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, v)
}

// GetReport GET /api/engagements/:id/report?audience=&format=&inline=1
// md and html are attachments unless inline=1; docx is always an attachment.
func (h *EngagementHandler) GetReport(c *gin.Context) {
	eng, err := h.db.GetEngagement(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	audience, reason, err := inferAudience(c, eng.OwnerUserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	format, err := report.ParseFormat(c.DefaultQuery("format", string(report.Markdown)))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ds, err := report.Build(h.db, eng.ID)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	generatedAt := h.now()
	var narrative, narrativeNote string
	wantNarrative := c.Query("narrative") == "true"
	if wantNarrative {
		narrative, narrativeNote = h.makeNarrative(c.Request.Context(), ds, audience)
	}
	body, err := report.RenderEngagementNarrative(ds, audience, format, generatedAt, narrative, narrativeNote)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	snap, err := h.storeSnapshot(c, eng.ID, audience, format, ds, body, narrative, narrativeNote, generatedAt)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.Header("X-Report-Snapshot", snap.ID)
	ctype, ext := format.ContentType()
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Report-Dataset-Hash", ds.Hash)
	c.Header("X-Report-Audience", string(audience))
	c.Header("X-Report-Audience-Reason", reason)
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	inline := format != report.DOCX && c.Query("inline") == "1"
	if !inline {
		c.Header("Content-Disposition", `attachment; filename="engagement-`+safeFilenamePart(eng.ID)+`-`+string(audience)+`.`+ext+`"`)
	}
	h.record(c, "report_generate", "Generate engagement report", "engagement", eng.ID, map[string]interface{}{
		"audience": string(audience), "audience_reason": reason, "format": string(format), "inline": inline, "dataset_hash": ds.Hash, "snapshot_id": snap.ID, "narrative": wantNarrative,
	})
	c.Data(http.StatusOK, ctype, body)
}

type joinRequest struct {
	VulnerabilityID string `json:"vulnerability_id"`
	AssetID         string `json:"asset_id"`
	Force           bool   `json:"force"`
}

// joinRecord is the shared body of the standalone finding and asset joins.
func (h *EngagementHandler) joinRecord(c *gin.Context, kind, recordID string, force bool, join func(engagementID, recordID string, force bool) error) {
	if recordID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": kind + "_id is required"})
		return
	}
	session, ok := security.CurrentSession(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	perm := map[string]string{"vulnerability": "vulnerability:write", "asset": "asset:write"}[kind]
	if !session.Permissions[perm] {
		c.JSON(http.StatusForbidden, gin.H{"error": "missing permission " + perm})
		return
	}
	engagementID := c.Param("id")
	if !h.canAccess(c, "project:write", engagementID) || !h.db.UserCanAccessResource(session.UserID, session.ScopeFor(perm), kind, recordID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no access to the engagement or the " + kind})
		return
	}
	if err := join(engagementID, recordID, force); err != nil {
		switch {
		case errors.Is(err, database.ErrOwnedByOtherEngagement):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error(), "hint": "pass force=true to move it"})
		case errors.Is(err, database.ErrRecordNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		default:
			h.writeErr(c, err)
		}
		return
	}
	h.record(c, "attach_"+kind, "Attach "+kind+" to engagement", "engagement", engagementID, map[string]interface{}{kind + "_id": recordID, "force": force})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// AttachFinding POST /api/engagements/:id/findings {vulnerability_id, force}
func (h *EngagementHandler) AttachFinding(c *gin.Context) {
	var req joinRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.joinRecord(c, "vulnerability", strings.TrimSpace(req.VulnerabilityID), req.Force, h.db.JoinFindingToEngagement)
}

// AttachAsset POST /api/engagements/:id/assets {asset_id, force}
func (h *EngagementHandler) AttachAsset(c *gin.Context) {
	var req joinRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.joinRecord(c, "asset", strings.TrimSpace(req.AssetID), req.Force, h.db.JoinAssetToEngagement)
}

// ListEngagementFindings GET /api/engagements/:id/findings.
func (h *EngagementHandler) ListEngagementFindings(c *gin.Context) {
	if _, err := h.db.GetEngagement(c.Param("id")); err != nil {
		h.writeErr(c, err)
		return
	}
	rows, err := h.db.ListEngagementFindingRows(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"findings": rows, "total": len(rows)})
}

// ListEngagementAssets GET /api/engagements/:id/assets.
func (h *EngagementHandler) ListEngagementAssets(c *gin.Context) {
	if _, err := h.db.GetEngagement(c.Param("id")); err != nil {
		h.writeErr(c, err)
		return
	}
	rows, err := h.db.ListEngagementAssetRows(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"assets": rows, "total": len(rows)})
}

// ListModelCalls GET /api/usage/calls?limit=N: recent per-call token usage with manifests.
func (h *EngagementHandler) ListModelCalls(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	rows, err := h.db.ListModelCalls(limit)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	if c.Query("format") == "csv" {
		out := make([][]string, 0, len(rows))
		for _, r := range rows {
			out = append(out, []string{r.ConversationID, strconv.Itoa(r.CallIndex), strconv.FormatInt(r.PromptTokens, 10),
				strconv.FormatInt(r.CompletionTokens, 10), strconv.FormatInt(r.CachedTokens, 10), strconv.FormatInt(r.TotalTokens, 10),
				r.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), r.ManifestJSON})
		}
		ExportModelCallsCSV(c, out)
		return
	}
	c.JSON(http.StatusOK, gin.H{"calls": rows, "total": len(rows)})
}
