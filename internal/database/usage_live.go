package database

import (
	"database/sql"
	"strings"
	"time"
)

// LiveUsageTotals holds summed token counters.
type LiveUsageTotals struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	CachedTokens     int64 `json:"cached_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// LiveModelUsage is one model's token totals over all recorded time.
type LiveModelUsage struct {
	Model string `json:"model"`
	LiveUsageTotals
}

// LiveUsage is the raw usage snapshot behind GET /api/usage/live.
type LiveUsage struct {
	SinceStart      LiveUsageTotals
	Today           LiveUsageTotals
	CallsSinceStart LiveUsageTotals
	CallsToday      LiveUsageTotals
	Models          []LiveModelUsage
	Newest          string
}

func sumUsage(db *DB, table string, since time.Time) (LiveUsageTotals, error) {
	var t LiveUsageTotals
	err := db.QueryRow(`SELECT COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0),
		COALESCE(SUM(cached_tokens),0), COALESCE(SUM(total_tokens),0) FROM `+table+` WHERE created_at >= ?`, since).
		Scan(&t.PromptTokens, &t.CompletionTokens, &t.CachedTokens, &t.TotalTokens)
	return t, err
}

// GetLiveUsage sums model_token_usage and model_call_usage since serverStart and since local midnight,
// and returns per-model totals (model_token_usage, all time within the table).
func (db *DB) GetLiveUsage(serverStart time.Time) (*LiveUsage, error) {
	if err := db.ensureModelCallUsage(); err != nil {
		return nil, err
	}
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	out := &LiveUsage{Models: []LiveModelUsage{}}
	var err error
	if out.SinceStart, err = sumUsage(db, "model_token_usage", serverStart); err != nil {
		return nil, err
	}
	if out.Today, err = sumUsage(db, "model_token_usage", midnight); err != nil {
		return nil, err
	}
	if out.CallsSinceStart, err = sumUsage(db, "model_call_usage", serverStart); err != nil {
		return nil, err
	}
	if out.CallsToday, err = sumUsage(db, "model_call_usage", midnight); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT COALESCE(NULLIF(TRIM(model), ''), 'unknown'), COALESCE(SUM(prompt_tokens),0),
		COALESCE(SUM(completion_tokens),0), COALESCE(SUM(cached_tokens),0), COALESCE(SUM(total_tokens),0)
		FROM model_token_usage GROUP BY 1 ORDER BY SUM(total_tokens) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m LiveModelUsage
		if err := rows.Scan(&m.Model, &m.PromptTokens, &m.CompletionTokens, &m.CachedTokens, &m.TotalTokens); err != nil {
			return nil, err
		}
		out.Models = append(out.Models, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var a, b sql.NullString
	if err := db.QueryRow(`SELECT (SELECT MAX(created_at) FROM model_token_usage), (SELECT MAX(created_at) FROM model_call_usage)`).Scan(&a, &b); err != nil {
		return nil, err
	}
	out.Newest = newerTimeString(a.String, b.String)
	return out, nil
}

func parseUsageTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func newerTimeString(a, b string) string {
	ta, oka := parseUsageTime(a)
	tb, okb := parseUsageTime(b)
	switch {
	case oka && okb:
		if tb.After(ta) {
			return tb.UTC().Format(time.RFC3339)
		}
		return ta.UTC().Format(time.RFC3339)
	case oka:
		return ta.UTC().Format(time.RFC3339)
	case okb:
		return tb.UTC().Format(time.RFC3339)
	}
	return ""
}
