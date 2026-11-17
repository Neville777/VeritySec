package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"veritysec/internal/database"
	"veritysec/internal/mcp"
)

// ReadEvidenceToolName is the agent tool that reads a section of stored engagement evidence.
const ReadEvidenceToolName = "read_evidence"

// readEvidenceMaxChars caps the text returned by one read_evidence call.
const readEvidenceMaxChars = 8000

// registerReadEvidenceTool registers read_evidence. It reads through the same EvidenceStore (with
// sha256 verification) as the HTTP API, and only for evidence of the engagement the calling
// conversation is attached to.
func registerReadEvidenceTool(mcpServer *mcp.Server, db *database.DB, evidenceRoot string) {
	store := &database.EvidenceStore{Root: evidenceRoot}
	result := func(v interface{}, isErr bool) *mcp.ToolResult {
		b, _ := json.MarshalIndent(v, "", "  ")
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(b)}}, IsError: isErr}
	}
	fail := func(msg string) *mcp.ToolResult { return result(map[string]string{"error": msg}, true) }
	tool := mcp.Tool{
		Name:             ReadEvidenceToolName,
		Description:      "Read a section of stored evidence (for example a large tool output that was compacted) from the engagement this conversation is attached to. Select by line range (start_line, end_line; 1-based, inclusive) or by character range (offset, length). At most 8000 characters are returned per call; the result says whether more remains.",
		ShortDescription: "Read a section of stored evidence",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"evidence_id": map[string]interface{}{"type": "string", "description": "Evidence ID, as shown in the compact result or the [evidence: <id>] line."},
				"start_line":  map[string]interface{}{"type": "integer", "description": "First line to return (1-based). Use with end_line."},
				"end_line":    map[string]interface{}{"type": "integer", "description": "Last line to return (inclusive)."},
				"offset":      map[string]interface{}{"type": "integer", "description": "Character offset to start from (default 0). Used when start_line is not given."},
				"length":      map[string]interface{}{"type": "integer", "description": "Number of characters to return (default and maximum 8000)."},
			},
			"required": []string{"evidence_id"},
		},
	}
	mcpServer.RegisterTool(tool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		id, _ := args["evidence_id"].(string)
		id = strings.TrimSpace(id)
		if id == "" {
			return fail("evidence_id is required"), nil
		}
		engagementID := ""
		if db != nil {
			if conv := mcp.MCPConversationIDFromContext(ctx); conv != "" {
				engagementID, _ = db.ConversationEngagementID(conv)
			}
		}
		if db == nil || strings.TrimSpace(engagementID) == "" {
			return fail(errStageEngagementRequired), nil
		}
		ev, err := db.GetEvidence(id)
		if err != nil || ev.EngagementID != engagementID {
			// Same message for "missing" and "other engagement" so IDs cannot be probed.
			return fail("evidence not found in this engagement"), nil
		}
		if !database.IsTextEvidenceKind(ev.Kind) {
			return fail("evidence kind " + ev.Kind + " is not text and cannot be read inline"), nil
		}
		data, err := store.Read(ev)
		if err != nil {
			if errors.Is(err, database.ErrEvidenceHashMismatch) || errors.Is(err, database.ErrEvidenceMissing) || errors.Is(err, database.ErrEvidencePurged) {
				return fail(err.Error()), nil
			}
			return fail("internal error"), nil
		}
		text := []rune(string(data))
		num := func(k string) (int, bool) {
			f, ok := args[k].(float64)
			return int(f), ok
		}
		start, end := 0, 0
		if sl, ok := num("start_line"); ok && sl >= 1 {
			lines := strings.Split(string(data), "\n")
			el, ok := num("end_line")
			if !ok || el < sl {
				el = sl + 199
			}
			if sl > len(lines) {
				return fail(fmt.Sprintf("start_line %d is past the end (%d lines)", sl, len(lines))), nil
			}
			if el > len(lines) {
				el = len(lines)
			}
			// character offsets of the line range
			pos := 0
			for i := 0; i < sl-1; i++ {
				pos += len([]rune(lines[i])) + 1
			}
			start = pos
			end = pos
			for i := sl - 1; i < el; i++ {
				end += len([]rune(lines[i])) + 1
			}
			if end > len(text) {
				end = len(text)
			}
		} else {
			off, _ := num("offset")
			if off < 0 {
				off = 0
			}
			if off > len(text) {
				off = len(text)
			}
			n, ok := num("length")
			if !ok || n <= 0 || n > readEvidenceMaxChars {
				n = readEvidenceMaxChars
			}
			start, end = off, off+n
			if end > len(text) {
				end = len(text)
			}
		}
		truncated := false
		if end-start > readEvidenceMaxChars {
			end = start + readEvidenceMaxChars
			truncated = true
		}
		return result(map[string]interface{}{
			"evidence_id": ev.ID, "title": ev.Title, "total_chars": len(text),
			"offset": start, "returned_chars": end - start,
			"more_after": end < len(text), "range_capped": truncated,
			"content": string(text[start:end]),
		}, false), nil
	})
}
