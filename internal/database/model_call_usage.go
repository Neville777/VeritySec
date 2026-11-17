package database

import (
	"database/sql"
	"sync"
	"time"

	"github.com/cloudwego/eino/schema"
)

var modelCallUsageReady sync.Map // *DB -> struct{}

// ensureModelCallUsage creates the per-call usage table on first use. It is kept out of the main
// schema file so it can be added without touching the shared application schema.
func (db *DB) ensureModelCallUsage() error {
	if _, ok := modelCallUsageReady.Load(db); ok {
		return nil
	}
	var err error
	{
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS model_call_usage (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			conversation_id TEXT NOT NULL,
			call_index INTEGER NOT NULL,
			prompt_tokens INTEGER NOT NULL DEFAULT 0,
			completion_tokens INTEGER NOT NULL DEFAULT 0,
			cached_tokens INTEGER NOT NULL DEFAULT 0,
			total_tokens INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL
		)`)
		if err == nil {
			_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_model_call_usage_conversation ON model_call_usage(conversation_id)`)
		}
		if err == nil {
			err = db.ensureModelCallUsageManifestColumn()
		}
		if err == nil {
			err = db.ensureModelCallUsageCostColumn()
		}
	}
	if err == nil {
		modelCallUsageReady.Store(db, struct{}{})
	}
	return err
}

// ensureModelCallUsageManifestColumn adds the nullable manifest_json column when it is missing.
func (db *DB) ensureModelCallUsageManifestColumn() error {
	rows, err := db.Query(`PRAGMA table_info(model_call_usage)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "manifest_json" {
			found = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = db.Exec(`ALTER TABLE model_call_usage ADD COLUMN manifest_json TEXT`)
	return err
}

// ensureModelCallUsageCostColumn adds the nullable cost_usd column (provider-reported USD cost) when missing.
func (db *DB) ensureModelCallUsageCostColumn() error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('model_call_usage') WHERE name='cost_usd'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err := db.Exec(`ALTER TABLE model_call_usage ADD COLUMN cost_usd REAL`)
	return err
}

// RecordModelCallUsage stores the token counts reported by the provider for one model call.
func (db *DB) RecordModelCallUsage(conversationID string, callIndex int, usage *schema.TokenUsage, manifestJSON string) error {
	return db.RecordModelCallUsageCost(conversationID, callIndex, usage, manifestJSON, nil)
}

// RecordModelCallUsageCost is RecordModelCallUsage plus the provider-reported USD cost (nil stores NULL).
func (db *DB) RecordModelCallUsageCost(conversationID string, callIndex int, usage *schema.TokenUsage, manifestJSON string, costUSD *float64) error {
	if db == nil || usage == nil {
		return nil
	}
	if err := db.ensureModelCallUsage(); err != nil {
		return err
	}
	total := usage.TotalTokens
	if total == 0 {
		total = usage.PromptTokens + usage.CompletionTokens
	}
	var cached sql.NullInt64
	cached.Int64 = int64(usage.PromptTokenDetails.CachedTokens)
	cached.Valid = true
	_, err := db.Exec(`INSERT INTO model_call_usage
		(conversation_id, call_index, prompt_tokens, completion_tokens, cached_tokens, total_tokens, created_at, manifest_json, cost_usd)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		conversationID, callIndex, usage.PromptTokens, usage.CompletionTokens, cached.Int64, total, time.Now(), nullIfEmpty(manifestJSON), costUSD)
	return err
}
