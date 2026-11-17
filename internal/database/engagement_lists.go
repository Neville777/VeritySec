package database

import (
	"database/sql"
	"time"
)

// EngagementFindingRow is one finding shown on an engagement, whether linked directly or through its conversation.
type EngagementFindingRow struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	ConversationID string `json:"conversation_id"`
}

// ListEngagementFindings returns findings linked to the engagement directly or through an attached conversation.
func (db *DB) ListEngagementFindingRows(engagementID string) ([]EngagementFindingRow, error) {
	rows, err := db.Query(`SELECT id, title, severity, status, COALESCE(conversation_id, '')
		FROM vulnerabilities
		WHERE engagement_id = ? OR conversation_id IN (SELECT id FROM conversations WHERE engagement_id = ?)
		ORDER BY id`, engagementID, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EngagementFindingRow{}
	for rows.Next() {
		var r EngagementFindingRow
		if err := rows.Scan(&r.ID, &r.Title, &r.Severity, &r.Status, &r.ConversationID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EngagementAssetRow is one asset linked to an engagement.
type EngagementAssetRow struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	Title    string `json:"title"`
}

// ListEngagementAssets returns assets linked to the engagement.
func (db *DB) ListEngagementAssetRows(engagementID string) ([]EngagementAssetRow, error) {
	rows, err := db.Query(`SELECT id, host, ip, port, domain, protocol, title FROM assets
		WHERE engagement_id = ? ORDER BY host, port`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EngagementAssetRow{}
	for rows.Next() {
		var r EngagementAssetRow
		if err := rows.Scan(&r.ID, &r.Host, &r.IP, &r.Port, &r.Domain, &r.Protocol, &r.Title); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ModelCallRow is one recorded model call, newest first in ListModelCalls.
type ModelCallRow struct {
	ConversationID   string    `json:"conversation_id"`
	CallIndex        int       `json:"call_index"`
	PromptTokens     int64     `json:"prompt_tokens"`
	CompletionTokens int64     `json:"completion_tokens"`
	CachedTokens     int64     `json:"cached_tokens"`
	TotalTokens      int64     `json:"total_tokens"`
	ManifestJSON     string    `json:"manifest_json,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// ListModelCalls returns the most recent per-call usage records.
func (db *DB) ListModelCalls(limit int) ([]ModelCallRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if err := db.ensureModelCallUsage(); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT conversation_id, call_index, prompt_tokens, completion_tokens,
		cached_tokens, total_tokens, COALESCE(manifest_json, ''), created_at
		FROM model_call_usage ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ModelCallRow{}
	for rows.Next() {
		var r ModelCallRow
		var created sql.NullTime
		if err := rows.Scan(&r.ConversationID, &r.CallIndex, &r.PromptTokens, &r.CompletionTokens,
			&r.CachedTokens, &r.TotalTokens, &r.ManifestJSON, &created); err != nil {
			return nil, err
		}
		r.CreatedAt = created.Time
		out = append(out, r)
	}
	return out, rows.Err()
}
