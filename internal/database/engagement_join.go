package database

import (
	"database/sql"
	"errors"
)

// ErrRecordNotFound is returned when the finding or asset to join does not exist.
var ErrRecordNotFound = errors.New("record not found")

// ErrOwnedByOtherEngagement is returned when a record already belongs to a different engagement
// and the caller did not ask to move it.
var ErrOwnedByOtherEngagement = errors.New("record already belongs to another engagement")

// JoinFindingToEngagement sets engagement_id on a standalone finding. A finding that already
// belongs to another engagement (directly or through its conversation) is left untouched unless
// force is true. Joining the same engagement again is a no-op.
func (db *DB) JoinFindingToEngagement(engagementID, vulnerabilityID string, force bool) error {
	return db.joinRecord("vulnerabilities", engagementID, vulnerabilityID, force,
		`SELECT COALESCE(v.engagement_id, ''), COALESCE((SELECT c.engagement_id FROM conversations c WHERE c.id = v.conversation_id), '')
		 FROM vulnerabilities v WHERE v.id = ?`)
}

// JoinAssetToEngagement sets engagement_id on an asset, with the same ownership rule as findings.
func (db *DB) JoinAssetToEngagement(engagementID, assetID string, force bool) error {
	return db.joinRecord("assets", engagementID, assetID, force,
		`SELECT COALESCE(engagement_id, ''), '' FROM assets WHERE id = ?`)
}

func (db *DB) joinRecord(table, engagementID, recordID string, force bool, ownerQuery string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM engagements WHERE id = ?`, engagementID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrEngagementNotFound
	}
	var direct, viaConversation string
	if err := tx.QueryRow(ownerQuery, recordID).Scan(&direct, &viaConversation); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRecordNotFound
		}
		return err
	}
	if !force {
		for _, owner := range []string{direct, viaConversation} {
			if owner != "" && owner != engagementID {
				return ErrOwnedByOtherEngagement
			}
		}
	}
	if _, err := tx.Exec(`UPDATE `+table+` SET engagement_id = ? WHERE id = ?`, engagementID, recordID); err != nil {
		return err
	}
	return tx.Commit()
}
