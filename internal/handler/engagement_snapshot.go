package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/report"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// SetNarrativeModel wires the default model channel used by report generation with narrative=true.
func (h *EngagementHandler) SetNarrativeModel(cfg *config.Config) {
	h.narrativeModel = func() report.NarrativeModel {
		if cfg == nil {
			return nil
		}
		oa, _, _ := cfg.ResolveAIChannel(config.ResolveRouteChannel(cfg, "reporting"))
		return &channelModel{cfg: oa, label: oa.Model + " (reporting route)", logger: h.logger}
	}
}

// makeNarrative returns the narrative text, or empty text and a note when the model is missing,
// fails or times out. The report is created either way.
func (h *EngagementHandler) makeNarrative(ctx context.Context, ds *report.Dataset, a report.Audience) (text, note string) {
	var m report.NarrativeModel
	if h.narrativeModel != nil {
		m = h.narrativeModel()
	}
	text, err := report.GenerateNarrative(ctx, m, ds, a)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("report narrative failed", zap.Error(err))
		}
		return "", report.NarrativeNoteFailed
	}
	return text, ""
}

// storeSnapshot writes the rendered file (create-only) and the snapshot row. The stored dataset
// JSON is exactly the bytes that hash to ds.Hash.
func (h *EngagementHandler) storeSnapshot(c *gin.Context, engagementID string, a report.Audience, f report.Format, ds *report.Dataset, body []byte, narrative, note string, at time.Time) (*database.ReportSnapshot, error) {
	dsJSON, err := json.Marshal(ds)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(dsJSON)
	id := database.NewReportSnapshotID()
	_, ext := f.ContentType()
	rel := engagementID + "/" + id + "." + ext
	full := filepath.Join(h.reportRoot, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err = file.Write(body); err != nil {
		file.Close()
		os.Remove(full)
		return nil, err
	}
	if err = file.Close(); err != nil {
		os.Remove(full)
		return nil, err
	}
	snap := &database.ReportSnapshot{
		ID: id, EngagementID: engagementID, Format: string(f), Audience: string(a),
		DatasetJSON: string(dsJSON), DatasetSHA256: hex.EncodeToString(sum[:]), RenderedPath: rel,
		NarrativeText: narrative, NarrativeNote: note, CreatedAt: at,
	}
	if s, ok := security.CurrentSession(c); ok {
		snap.CreatedBy = s.UserID
	}
	if err := h.db.CreateReportSnapshot(snap); err != nil {
		os.Remove(full)
		return nil, err
	}
	return snap, nil
}

// ListReportSnapshots GET /api/engagements/:id/report-snapshots (metadata only, newest first).
func (h *EngagementHandler) ListReportSnapshots(c *gin.Context) {
	id := c.Param("id")
	if !h.canAccess(c, "project:read", id) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no access to the engagement"})
		return
	}
	if _, err := h.db.GetEngagement(id); err != nil {
		h.writeErr(c, err)
		return
	}
	list, err := h.db.ListReportSnapshots(id)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"snapshots": list})
}

// GetReportSnapshot GET /api/report-snapshots/:id returns the stored dataset and rendered file.
// The hash is re-checked on every read.
func (h *EngagementHandler) GetReportSnapshot(c *gin.Context) {
	snap, err := h.db.GetReportSnapshot(c.Param("id"))
	if err != nil {
		if errors.Is(err, database.ErrReportSnapshotNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		h.writeErr(c, err)
		return
	}
	if !h.canAccess(c, "project:read", snap.EngagementID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no access to the engagement"})
		return
	}
	sum := sha256.Sum256([]byte(snap.DatasetJSON))
	resp := gin.H{
		"snapshot":      snap,
		"dataset":       json.RawMessage(snap.DatasetJSON),
		"hash_verified": hex.EncodeToString(sum[:]) == snap.DatasetSHA256,
	}
	format, perr := report.ParseFormat(snap.Format)
	if perr == nil {
		ctype, _ := format.ContentType()
		resp["rendered_content_type"] = ctype
		data, rerr := os.ReadFile(filepath.Join(h.reportRoot, filepath.FromSlash(snap.RenderedPath)))
		switch {
		case rerr != nil:
			resp["rendered_available"] = false
		case format == report.DOCX:
			resp["rendered_available"], resp["rendered_base64"] = true, base64.StdEncoding.EncodeToString(data)
		default:
			resp["rendered_available"], resp["rendered"] = true, string(data)
		}
	}
	c.Header("X-Content-Type-Options", "nosniff")
	c.JSON(http.StatusOK, resp)
}
