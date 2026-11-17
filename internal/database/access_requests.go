package database

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type AccessRequest struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Email      string  `json:"email"`
	Reason     string  `json:"reason"`
	Status     string  `json:"status"`
	ReviewedBy string  `json:"reviewed_by,omitempty"`
	ReviewedAt *string `json:"reviewed_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

func (db *DB) CreateAccessRequest(name, email, reason string) (*AccessRequest, error) {
	id := uuid.New().String()
	now := time.Now().Format(time.RFC3339)

	var existing int
	_ = db.QueryRow(`SELECT COUNT(*) FROM access_requests WHERE email = ? AND status = 'pending'`, email).Scan(&existing)
	if existing > 0 {
		return nil, fmt.Errorf("a pending request for this email already exists")
	}

	_, err := db.Exec(`
		INSERT INTO access_requests (id, name, email, reason, status, created_at)
		VALUES (?, ?, ?, ?, 'pending', ?)
	`, id, name, email, reason, now)
	if err != nil {
		return nil, fmt.Errorf("create access request: %w", err)
	}

	return &AccessRequest{ID: id, Name: name, Email: email, Reason: reason, Status: "pending", CreatedAt: now}, nil
}

func (db *DB) ListAccessRequests(status string) ([]AccessRequest, error) {
	query := `SELECT id, name, email, reason, status, reviewed_by, reviewed_at, created_at FROM access_requests`
	var args []interface{}
	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []AccessRequest
	for rows.Next() {
		var r AccessRequest
		if err := rows.Scan(&r.ID, &r.Name, &r.Email, &r.Reason, &r.Status, &r.ReviewedBy, &r.ReviewedAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		requests = append(requests, r)
	}
	return requests, nil
}

func (db *DB) GetAccessRequest(id string) (*AccessRequest, error) {
	var r AccessRequest
	err := db.QueryRow(`
		SELECT id, name, email, reason, status, reviewed_by, reviewed_at, created_at
		FROM access_requests WHERE id = ?
	`, id).Scan(&r.ID, &r.Name, &r.Email, &r.Reason, &r.Status, &r.ReviewedBy, &r.ReviewedAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (db *DB) ReviewAccessRequest(id, reviewerID, status string) error {
	if status != "approved" && status != "rejected" {
		return fmt.Errorf("invalid status: must be approved or rejected")
	}
	now := time.Now().Format(time.RFC3339)
	result, err := db.Exec(`
		UPDATE access_requests SET status = ?, reviewed_by = ?, reviewed_at = ?
		WHERE id = ? AND status = 'pending'
	`, status, reviewerID, now, id)
	if err != nil {
		return fmt.Errorf("review access request: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("request not found or already reviewed")
	}
	return nil
}
