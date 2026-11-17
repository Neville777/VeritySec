package database

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type UserAPIKey struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	Provider     string `json:"provider"`
	EncryptedKey string `json:"-"`
	Label        string `json:"label"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

func (db *DB) UpsertUserAPIKey(userID, provider, encryptedKey, label string) (*UserAPIKey, error) {
	now := time.Now().Format(time.RFC3339)
	id := uuid.New().String()

	_, err := db.Exec(`
		INSERT INTO user_api_keys (id, user_id, provider, encrypted_key, label, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, provider) DO UPDATE SET
			encrypted_key = excluded.encrypted_key,
			label = excluded.label,
			updated_at = excluded.updated_at
	`, id, userID, provider, encryptedKey, label, now, now)
	if err != nil {
		return nil, fmt.Errorf("upsert user api key: %w", err)
	}

	return db.GetUserAPIKey(userID, provider)
}

func (db *DB) GetUserAPIKey(userID, provider string) (*UserAPIKey, error) {
	var k UserAPIKey
	err := db.QueryRow(`
		SELECT id, user_id, provider, encrypted_key, label, created_at, updated_at
		FROM user_api_keys WHERE user_id = ? AND provider = ?
	`, userID, provider).Scan(&k.ID, &k.UserID, &k.Provider, &k.EncryptedKey, &k.Label, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (db *DB) ListUserAPIKeys(userID string) ([]UserAPIKey, error) {
	rows, err := db.Query(`
		SELECT id, user_id, provider, label, created_at, updated_at
		FROM user_api_keys WHERE user_id = ? ORDER BY provider ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []UserAPIKey
	for rows.Next() {
		var k UserAPIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Provider, &k.Label, &k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (db *DB) DeleteUserAPIKey(userID, provider string) error {
	_, err := db.Exec(`DELETE FROM user_api_keys WHERE user_id = ? AND provider = ?`, userID, provider)
	return err
}
