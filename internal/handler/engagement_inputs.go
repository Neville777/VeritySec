package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"veritysec/internal/database"
	"veritysec/internal/inputs"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const maxIndicatorsPerInput = 500

// inputsRoot is the data directory (parent of the evidence directory); Store puts files under
// <root>/inputs/<engagement>/.
func (h *EngagementHandler) inputsRoot() string { return filepath.Dir(filepath.Clean(h.store.Root)) }

func (h *EngagementHandler) requireInputPerm(c *gin.Context, permission string) bool {
	s, ok := security.CurrentSession(c)
	if !ok || !s.Permissions[permission] {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "permission": permission})
		return false
	}
	if !h.canAccess(c, permission, c.Param("id")) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return false
	}
	return true
}

// UploadInput POST /api/engagements/:id/inputs (multipart field "file"). The bytes are
// recorded unchanged; only text content is scanned for URLs/hosts/IPs. Nothing is executed,
// fetched, opened or decompressed, and indicators are stored as discovered / not authorized.
func (h *EngagementHandler) UploadInput(c *gin.Context) {
	if !h.requireInputPerm(c, "project:write") {
		return
	}
	engagementID := c.Param("id")
	if _, err := h.db.GetEngagement(engagementID); err != nil {
		h.writeErr(c, err)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, inputs.MaxContentBytes+(1<<20))
	fh, err := c.FormFile("file")
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds the 25 MB limit"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart field \"file\" is required"})
		return
	}
	if fh.Size > inputs.MaxContentBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds the 25 MB limit"})
		return
	}
	f, err := fh.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read upload"})
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, inputs.MaxContentBytes+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read upload"})
		return
	}
	if len(data) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is empty"})
		return
	}
	if len(data) > inputs.MaxContentBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds the 25 MB limit"})
		return
	}
	rec, err := inputs.Store(h.inputsRoot(), engagementID, data, fh.Filename)
	if err != nil {
		switch {
		case errors.Is(err, inputs.ErrTooLarge):
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Error()})
		case errors.Is(err, inputs.ErrBadID):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid engagement id"})
		default:
			h.logger.Error("input store failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
		return
	}
	det := inputs.Detect(data, fh.Filename)
	notes := append([]string{}, det.Reasons...)
	ocrText := ""

	var inds []database.InputIndicator
	switch rec.DetectedKind {
	case inputs.KindTextUTF8, inputs.KindTextLogLike, inputs.KindSourceCode:
		for _, ind := range inputs.ExtractIndicators(string(data), maxIndicatorsPerInput) {
			inds = append(inds, database.NewInputIndicator(ind.Kind, ind.Value, ind.Offset))
		}
	}
	switch {
	case inputs.IsImageKind(rec.DetectedKind):
		text, oerr := inputs.OCR(rec.StoragePath)
		switch {
		case errors.Is(oerr, inputs.ErrOCRUnavailable):
			notes = append(notes, "ocr: unavailable (tesseract not on PATH)")
		case oerr != nil:
			notes = append(notes, "ocr: failed")
			h.logger.Warn("input OCR failed", zap.Error(oerr))
		default:
			ocrText = text
			notes = append(notes, "ocr: ok")
			for _, ind := range inputs.ExtractIndicators(text, maxIndicatorsPerInput) {
				inds = append(inds, database.NewInputIndicator(ind.Kind, ind.Value, ind.Offset))
			}
		}
	case rec.DetectedKind == inputs.KindPcap || rec.DetectedKind == inputs.KindPcapng:
		if pi, perr := inputs.ParsePcap(data); perr == nil {
			notes = append(notes, "pcap: format="+pi.Format, "pcap: packet_count="+strconv.Itoa(pi.PacketCount),
				"pcap: link_type="+strconv.Itoa(pi.LinkType))
			if pi.Truncated {
				notes = append(notes, "pcap: truncated")
			}
		} else {
			notes = append(notes, "pcap: header unreadable")
		}
	}
	reasons, _ := json.Marshal(notes)
	sess, _ := security.CurrentSession(c)
	in := &database.EngagementInput{
		ID: rec.ID, EngagementID: engagementID, OriginalName: rec.OriginalName, DetectedKind: string(rec.DetectedKind),
		MIME: rec.MIME, SHA256: rec.SHA256, Size: rec.Size, StoragePath: rec.StoragePath, Confidence: det.Confidence,
		Reasons: reasons, OCRText: ocrText, CreatedBy: sess.UserID, CreatedAt: rec.CreatedAt,
	}
	if err := h.db.InsertEngagementInput(in, inds); err != nil {
		_ = removeStoredInput(rec.StoragePath)
		h.logger.Error("input insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	h.record(c, "input_upload", "Upload engagement input", "engagement_input", in.ID, map[string]interface{}{
		"engagement_id": engagementID, "detected_kind": in.DetectedKind, "size_bytes": in.Size,
	})
	if oerr := h.db.InsertInputObservations(in.ID, engagementID, buildInputObservations(det, inds, data, rec.DetectedKind, len(ocrText))); oerr != nil {
		h.logger.Warn("input observations not stored", zap.String("input_id", in.ID), zap.Error(oerr))
	}
	stored, err := h.db.ListInputIndicators(engagementID, in.ID)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"input": in, "indicators": stored})
}

func obsJSON(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

// buildInputObservations turns detection results into factual observations. Data holds counts
// and short labels only; no file text and no indicator values.
func buildInputObservations(det inputs.Detection, inds []database.InputIndicator, data []byte, kind inputs.Kind, ocrChars int) []database.InputObservation {
	var obs []database.InputObservation
	obs = append(obs, database.InputObservation{
		Kind:    "file_type",
		Summary: "Detected " + string(det.Kind) + " (" + det.MIME + ") at " + strconv.Itoa(int(det.Confidence*100)) + "% confidence",
		Data:    obsJSON(map[string]interface{}{"kind": string(det.Kind), "mime": det.MIME, "confidence": det.Confidence, "reasons": det.Reasons}),
	})
	counts := map[string]int{}
	for _, ind := range inds {
		counts[ind.Kind]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, strconv.Itoa(counts[k])+" "+k)
	}
	sum := "No indicators found"
	if len(parts) > 0 {
		sum = strings.Join(parts, ", ") + " (" + strconv.Itoa(len(inds)) + " total)"
	}
	obs = append(obs, database.InputObservation{Kind: "indicator_summary", Summary: sum,
		Data: obsJSON(map[string]interface{}{"total": len(inds), "counts": counts})})
	for _, r := range det.Reasons {
		if strings.HasPrefix(r, "mismatch:") {
			obs = append(obs, database.InputObservation{Kind: "mismatch", Summary: r,
				Data: obsJSON(map[string]interface{}{"detected_kind": string(det.Kind)})})
		}
	}
	if kind == inputs.KindPcap || kind == inputs.KindPcapng {
		if pi, err := inputs.ParsePcap(data); err == nil {
			ports := pi.TopDstPorts
			if len(ports) > 5 {
				ports = ports[:5]
			}
			obs = append(obs, database.InputObservation{Kind: "pcap_summary",
				Summary: strconv.Itoa(pi.PacketCount) + " packets, " + strconv.Itoa(len(pi.ProtocolCounts)) + " protocols",
				Data: obsJSON(map[string]interface{}{"format": pi.Format, "packet_count": pi.PacketCount,
					"protocol_counts": pi.ProtocolCounts, "top_ports": ports, "truncated": pi.Truncated, "partial": pi.Partial})})
		}
	}
	if ocrChars > 0 {
		obs = append(obs, database.InputObservation{Kind: "ocr_text", Summary: strconv.Itoa(ocrChars) + " characters of OCR text",
			Data: obsJSON(map[string]interface{}{"char_count": ocrChars})})
	}
	return obs
}

// ListInputObservations GET /api/engagements/:id/inputs/:inputId/observations
func (h *EngagementHandler) ListInputObservations(c *gin.Context) {
	if !h.requireInputPerm(c, "project:read") {
		return
	}
	in, err := h.db.GetEngagementInput(c.Param("id"), c.Param("inputId"))
	if err != nil {
		if errors.Is(err, database.ErrInputNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		h.writeErr(c, err)
		return
	}
	obs, err := h.db.ListInputObservations(in.ID)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"observations": obs, "total": len(obs)})
}

// removeStoredInput deletes a file this handler just created (rollback only).
func removeStoredInput(p string) error {
	if p == "" || !strings.HasSuffix(p, ".bin") {
		return nil
	}
	return os.Remove(p)
}

// ListInputs GET /api/engagements/:id/inputs
func (h *EngagementHandler) ListInputs(c *gin.Context) {
	if !h.requireInputPerm(c, "project:read") {
		return
	}
	if _, err := h.db.GetEngagement(c.Param("id")); err != nil {
		h.writeErr(c, err)
		return
	}
	list, err := h.db.ListEngagementInputs(c.Param("id"))
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"inputs": list, "total": len(list)})
}

// ListInputIndicators GET /api/engagements/:id/inputs/:inputId/indicators
func (h *EngagementHandler) ListInputIndicators(c *gin.Context) {
	if !h.requireInputPerm(c, "project:read") {
		return
	}
	in, err := h.db.GetEngagementInput(c.Param("id"), c.Param("inputId"))
	if err != nil {
		if errors.Is(err, database.ErrInputNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		h.writeErr(c, err)
		return
	}
	inds, err := h.db.ListInputIndicators(in.EngagementID, in.ID)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"input": in, "indicators": inds, "total": len(inds)})
}

// AuthorizeInputIndicator POST /api/input-indicators/:id/authorize. The scope engine decides:
// only IN_SCOPE marks the indicator authorized. This is a human/API action, never a model call.
func (h *EngagementHandler) AuthorizeInputIndicator(c *gin.Context) {
	s, ok := security.CurrentSession(c)
	if !ok || !s.Permissions["project:write"] {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "permission": "project:write"})
		return
	}
	id := c.Param("id")
	eid, err := h.db.InputIndicatorEngagementID(id)
	if err != nil {
		if errors.Is(err, database.ErrIndicatorNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		h.writeErr(c, err)
		return
	}
	if !h.canAccess(c, "project:write", eid) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	d, ind, err := h.db.AuthorizeIndicatorViaScope(id)
	if err != nil {
		h.writeErr(c, err)
		return
	}
	h.record(c, "input_indicator_authorize", "Authorize input indicator by scope", "input_indicator", id, map[string]interface{}{
		"engagement_id": eid, "decision": string(d.Result), "authorized": ind.Authorized,
	})
	c.JSON(http.StatusOK, gin.H{"decision": d.Result, "reason": d.Reason, "indicator": ind})
}
