package handler

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// writeCSV sends rows as a CSV attachment with the given file name.
func writeCSV(c *gin.Context, filename string, header []string, rows [][]string) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w := csv.NewWriter(c.Writer)
	_ = w.Write(header)
	for _, r := range rows {
		_ = w.Write(r)
	}
	w.Flush()
}

// ExportEngagementCSV GET /api/engagements/:id/export?kind=findings|assets|evidence.
// The rows come from the same queries as the on-screen lists, so the file matches what the page shows.
func (h *EngagementHandler) ExportEngagementCSV(c *gin.Context) {
	id := c.Param("id")
	if _, err := h.db.GetEngagement(id); err != nil {
		h.writeErr(c, err)
		return
	}
	kind := c.DefaultQuery("kind", "findings")
	switch kind {
	case "findings":
		list, err := h.db.ListEngagementFindingRows(id)
		if err != nil {
			h.writeErr(c, err)
			return
		}
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			rows = append(rows, []string{f.ID, f.Title, f.Severity, f.Status, f.ConversationID})
		}
		writeCSV(c, fmt.Sprintf("engagement-%s-findings.csv", id), []string{"id", "title", "severity", "status", "conversation_id"}, rows)
	case "assets":
		list, err := h.db.ListEngagementAssetRows(id)
		if err != nil {
			h.writeErr(c, err)
			return
		}
		rows := make([][]string, 0, len(list))
		for _, a := range list {
			rows = append(rows, []string{a.ID, a.Host, a.IP, strconv.Itoa(a.Port), a.Domain, a.Protocol, a.Title})
		}
		writeCSV(c, fmt.Sprintf("engagement-%s-assets.csv", id), []string{"id", "host", "ip", "port", "domain", "protocol", "title"}, rows)
	case "evidence":
		list, err := h.db.ListEvidence(id)
		if err != nil {
			h.writeErr(c, err)
			return
		}
		rows := make([][]string, 0, len(list))
		for _, e := range list {
			rows = append(rows, []string{e.ID, e.Kind, e.Title, e.SHA256, strconv.FormatInt(e.SizeBytes, 10), e.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), e.Origin, e.Stage})
		}
		writeCSV(c, fmt.Sprintf("engagement-%s-evidence.csv", id), []string{"id", "kind", "title", "sha256", "size_bytes", "created_at", "origin", "stage"}, rows)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "kind must be findings, assets or evidence"})
	}
}

// ExportModelCallsCSV writes the per-call usage rows as CSV.
func ExportModelCallsCSV(c *gin.Context, rows [][]string) {
	writeCSV(c, "model-calls.csv", []string{"conversation_id", "call_index", "prompt_tokens", "completion_tokens", "cached_tokens", "total_tokens", "created_at", "manifest_json"}, rows)
}
