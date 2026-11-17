package database

import (
	"database/sql"
	"time"
)

// SetOpenRouterKeyUsage stores the latest key-level total spend reported by OpenRouter.
func (db *DB) SetOpenRouterKeyUsage(usageUSD float64, checkedAt time.Time) error {
	_, err := db.Exec(`INSERT INTO openrouter_key_usage (id, usage_usd, checked_at) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET usage_usd = excluded.usage_usd, checked_at = excluded.checked_at`, usageUSD, checkedAt)
	return err
}

// GetOpenRouterKeyUsage returns the stored key-level spend, or nil values when none was stored yet.
func (db *DB) GetOpenRouterKeyUsage() (usageUSD *float64, checkedAt *time.Time, err error) {
	var u sql.NullFloat64
	var c sql.NullTime
	err = db.QueryRow(`SELECT usage_usd, checked_at FROM openrouter_key_usage WHERE id = 1`).Scan(&u, &c)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if u.Valid {
		usageUSD = &u.Float64
	}
	if c.Valid {
		checkedAt = &c.Time
	}
	return usageUSD, checkedAt, nil
}

// SumModelCallCost sums the provider-reported cost_usd of model_call_usage rows created at or after since.
func (db *DB) SumModelCallCost(since time.Time) (float64, error) {
	if err := db.ensureModelCallUsage(); err != nil {
		return 0, err
	}
	var v float64
	err := db.QueryRow(`SELECT COALESCE(SUM(cost_usd),0) FROM model_call_usage WHERE created_at >= ?`, since).Scan(&v)
	return v, err
}
