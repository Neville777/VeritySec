package database

import (
	"os"
	"time"
)

// PurgeResult counts what PurgeExpiredEvidence did.
type PurgeResult struct {
	RetentionDays int `json:"retention_days"`
	Purged        int `json:"purged"`
	AlreadyGone   int `json:"already_missing"` // row expired but the file was already absent; row still marked
	Failed        int `json:"failed"`
}

// PurgeExpiredEvidence deletes stored evidence FILES older than retentionDays and marks their
// rows storage_deleted=1. The rows themselves, including the original sha256 and size, are
// kept so the integrity history remains. retentionDays <= 0 means keep forever and does
// nothing. It is never run automatically.
func (db *DB) PurgeExpiredEvidence(store *EvidenceStore, retentionDays int, now time.Time) (PurgeResult, error) {
	res := PurgeResult{RetentionDays: retentionDays}
	if retentionDays <= 0 || store == nil {
		return res, nil
	}
	cutoff := now.UTC().AddDate(0, 0, -retentionDays)
	rows, err := db.Query(`SELECT id, storage_path FROM evidence WHERE COALESCE(storage_deleted, 0) = 0 AND created_at < ?`, cutoff)
	if err != nil {
		return res, err
	}
	type item struct{ id, path string }
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.path); err != nil {
			rows.Close()
			return res, err
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return res, err
	}
	rows.Close()
	for _, it := range items {
		full, err := store.resolve(it.path)
		if err != nil {
			res.Failed++
			continue
		}
		if err := os.Remove(full); err != nil {
			if os.IsNotExist(err) {
				res.AlreadyGone++
			} else {
				res.Failed++
				continue
			}
		} else {
			res.Purged++
		}
		if _, err := db.Exec(`UPDATE evidence SET storage_deleted = 1 WHERE id = ?`, it.id); err != nil {
			return res, err
		}
	}
	return res, nil
}
