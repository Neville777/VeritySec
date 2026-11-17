package handler

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"veritysec/internal/database"
)

const (
	runSummaryThinTextLen = 300
	runSummaryMaxChars    = 1500
	runSummaryMaxErrChars = 120
	runSummaryHeading     = "What was done"
)

var runSummaryTargetKeys = []string{"target", "url", "host", "domain", "ip"}

// runSummaryForMessage builds a short markdown block describing the tool executions of this
// run: counts by status plus one line per tool (name, status, first target-like argument and,
// for failures, the first 120 characters of the error). It never includes tool output.
// Executions are taken from mcpExecutionIDs when given, otherwise from the conversation's
// executions that started at or after the assistant message was created (the run window).
// It returns "" when no tools ran.
func runSummaryForMessage(db *database.DB, conversationID, assistantMessageID string, mcpExecutionIDs []string) string {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return ""
	}
	type row struct{ name, status, args, errText string }
	var rows []row

	query := `SELECT tool_name, status, COALESCE(arguments, ''), COALESCE(error, '') FROM tool_executions WHERE conversation_id = ?`
	qargs := []interface{}{conversationID}
	if len(mcpExecutionIDs) > 0 {
		ph := make([]string, 0, len(mcpExecutionIDs))
		for _, id := range mcpExecutionIDs {
			ph = append(ph, "?")
			qargs = append(qargs, id)
		}
		query += ` AND id IN (` + strings.Join(ph, ",") + `)`
	} else {
		var started time.Time
		if err := db.QueryRow(`SELECT created_at FROM messages WHERE id = ? AND conversation_id = ?`, assistantMessageID, conversationID).Scan(&started); err != nil {
			return ""
		}
		query += ` AND start_time >= ?`
		qargs = append(qargs, started)
	}
	query += ` ORDER BY start_time ASC, id ASC LIMIT 500`

	rs, err := db.Query(query, qargs...)
	if err != nil {
		return ""
	}
	defer rs.Close()
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.name, &r.status, &r.args, &r.errText); err != nil {
			return ""
		}
		rows = append(rows, r)
	}
	if rs.Err() != nil || len(rows) == 0 {
		return ""
	}

	var completed, failed, cancelled int
	for _, r := range rows {
		switch strings.ToLower(r.status) {
		case "completed":
			completed++
		case "failed":
			failed++
		case "cancelled", "canceled":
			cancelled++
		}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("%d tool calls: %d completed, %d failed, %d cancelled\n", len(rows), completed, failed, cancelled))
	// Reserve room for the heading and an "and N more" line.
	budget := runSummaryMaxChars - len(runSummaryHeading) - 8 - 40
	for i, r := range rows {
		line := "- " + r.name + " (" + r.status + ")"
		if t := runSummaryTarget(r.args); t != "" {
			line += " " + t
		}
		if e := strings.TrimSpace(r.errText); e != "" && strings.ToLower(r.status) != "completed" {
			line += ": " + runSummaryTruncate(e, runSummaryMaxErrChars)
		}
		line = runSummaryTruncate(strings.ReplaceAll(line, "\n", " "), 260) + "\n"
		if b.Len()+len(line) > budget {
			b.WriteString(fmt.Sprintf("- and %d more\n", len(rows)-i))
			break
		}
		b.WriteString(line)
	}
	return strings.TrimRight(b.String(), "\n")
}

func runSummaryTruncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// runSummaryTarget returns the first target-like argument value (target, url, host, domain, ip).
func runSummaryTarget(argsJSON string) string {
	argsJSON = strings.TrimSpace(argsJSON)
	if argsJSON == "" {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(argsJSON), &m); err != nil {
		return ""
	}
	for _, k := range runSummaryTargetKeys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return runSummaryTruncate(strings.TrimSpace(v), 120)
		}
	}
	return ""
}

// runSummaryNeeded reports whether the final text is thin or a status-only line.
func runSummaryNeeded(text string) bool {
	t := strings.TrimSpace(text)
	if len([]rune(t)) < runSummaryThinTextLen {
		return true
	}
	if strings.HasPrefix(t, "Final reply") || strings.Contains(t, "Retrying") ||
		(strings.Contains(t, "Took ") && strings.Contains(t, "Expand details")) {
		return true
	}
	return false
}

// appendRunSummary returns text with the "What was done" block appended when the rule matches
// and the run executed tools; otherwise it returns text unchanged.
func appendRunSummary(db *database.DB, conversationID, assistantMessageID string, mcpExecutionIDs []string, text string) string {
	if !runSummaryNeeded(text) || strings.Contains(text, "## "+runSummaryHeading) {
		return text
	}
	block := runSummaryForMessage(db, conversationID, assistantMessageID, mcpExecutionIDs)
	if block == "" {
		return text
	}
	return strings.TrimRight(text, " \n") + "\n\n## " + runSummaryHeading + "\n" + block
}
