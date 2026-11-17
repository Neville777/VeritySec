package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Approval request statuses.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalDenied   = "denied"
	ApprovalExpired  = "expired"
)

var (
	ErrApprovalNotFound = errors.New("approval request not found")
	ErrApprovalDecided  = errors.New("approval request is not pending")
	ErrApprovalExpired  = errors.New("approval request has expired")
)

// ApprovalRequest is a person-approval record for one risky, in-scope tool call. It stores a
// SHA-256 of the arguments, never the arguments themselves.
type ApprovalRequest struct {
	ID             string     `json:"id"`
	EngagementID   string     `json:"engagement_id"`
	ConversationID string     `json:"conversation_id"`
	MessageID      string     `json:"message_id"`
	ToolName       string     `json:"tool_name"`
	Target         string     `json:"target"`
	ArgumentsHash  string     `json:"arguments_hash"`
	Status         string     `json:"status"`
	RequestedAt    time.Time  `json:"requested_at"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	DecidedBy      string     `json:"decided_by"`
	DecisionReason string     `json:"decision_reason"`
	ExpiresAt      time.Time  `json:"expires_at"`
	UsedAt         *time.Time `json:"used_at,omitempty"`
}

// HashApprovalArguments returns the hex SHA-256 of the canonical JSON of the arguments (map keys
// are emitted sorted by encoding/json, so equal arguments hash equally).
func HashApprovalArguments(args map[string]interface{}) string {
	b, err := json.Marshal(args)
	if err != nil {
		b = []byte("unmarshalable")
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

const approvalCols = `id, engagement_id, conversation_id, message_id, tool_name, target, arguments_hash, status,
	requested_at, decided_at, decided_by, decision_reason, expires_at, used_at`


func scanApproval(r rowScanner) (*ApprovalRequest, error) {
	var a ApprovalRequest
	var req, exp string
	var dec, used sql.NullString
	if err := r.Scan(&a.ID, &a.EngagementID, &a.ConversationID, &a.MessageID, &a.ToolName, &a.Target, &a.ArgumentsHash,
		&a.Status, &req, &dec, &a.DecidedBy, &a.DecisionReason, &exp, &used); err != nil {
		return nil, err
	}
	a.RequestedAt, _ = ParseRFC3339Time(req)
	a.ExpiresAt, _ = ParseRFC3339Time(exp)
	if dec.Valid {
		t, _ := ParseRFC3339Time(dec.String)
		a.DecidedAt = &t
	}
	if used.Valid {
		t, _ := ParseRFC3339Time(used.String)
		a.UsedAt = &t
	}
	return &a, nil
}

// RequestApproval returns the existing pending, unexpired request for the same engagement, tool,
// target and arguments hash, or creates one. created reports whether a new row was made.
func (db *DB) RequestApproval(engagementID, conversationID, messageID, tool, target, argsHash string, now time.Time, ttl time.Duration) (*ApprovalRequest, bool, error) {
	row := db.QueryRow(`SELECT `+approvalCols+` FROM approval_requests
		WHERE engagement_id=? AND tool_name=? AND target=? AND arguments_hash=? AND status='pending'
		AND strftime('%s', expires_at) > strftime('%s', ?) ORDER BY requested_at DESC LIMIT 1`,
		engagementID, tool, target, argsHash, formatSQLiteUTC(now))
	if a, err := scanApproval(row); err == nil {
		return a, false, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	a := &ApprovalRequest{ID: uuid.New().String(), EngagementID: engagementID, ConversationID: conversationID, MessageID: messageID,
		ToolName: tool, Target: target, ArgumentsHash: argsHash, Status: ApprovalPending, RequestedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC()}
	_, err := db.Exec(`INSERT INTO approval_requests (id, engagement_id, conversation_id, message_id, tool_name, target, arguments_hash, status, requested_at, expires_at)
		VALUES (?,?,?,?,?,?,?, 'pending', ?, ?)`, a.ID, engagementID, conversationID, messageID, tool, target, argsHash,
		formatSQLiteUTC(a.RequestedAt), formatSQLiteUTC(a.ExpiresAt))
	if err != nil {
		return nil, false, err
	}
	return a, true, nil
}

// ConsumeApproval atomically marks one matching approved, unexpired, unused request as used and
// reports whether one was found. Each approval is usable once.
func (db *DB) ConsumeApproval(engagementID, tool, target, argsHash string, now time.Time) (bool, error) {
	ts := formatSQLiteUTC(now)
	res, err := db.Exec(`UPDATE approval_requests SET used_at=? WHERE id = (
		SELECT id FROM approval_requests WHERE engagement_id=? AND tool_name=? AND target=? AND arguments_hash=?
		AND status='approved' AND used_at IS NULL AND strftime('%s', expires_at) > strftime('%s', ?)
		ORDER BY decided_at LIMIT 1) AND used_at IS NULL`, ts, engagementID, tool, target, argsHash, ts)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// GetApprovalRequest loads one request.
func (db *DB) GetApprovalRequest(id string) (*ApprovalRequest, error) {
	a, err := scanApproval(db.QueryRow(`SELECT `+approvalCols+` FROM approval_requests WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrApprovalNotFound
	}
	return a, err
}

// ApprovalRequestEngagementID returns the engagement a request belongs to.
func (db *DB) ApprovalRequestEngagementID(id string) (string, error) {
	a, err := db.GetApprovalRequest(id)
	if err != nil {
		return "", err
	}
	return a.EngagementID, nil
}

// ListApprovalRequests lists an engagement's requests, pending first, then newest first.
func (db *DB) ListApprovalRequests(engagementID string) ([]ApprovalRequest, error) {
	rows, err := db.Query(`SELECT `+approvalCols+` FROM approval_requests WHERE engagement_id=?
		ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, requested_at DESC LIMIT 500`, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ApprovalRequest{}
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// DecideApproval records a person's decision on a pending request. Approving restarts the
// validity window (expires_at = now + ttl). A pending request past its expiry becomes 'expired'
// and ErrApprovalExpired is returned.
func (db *DB) DecideApproval(id string, approve bool, by, reason string, now time.Time, ttl time.Duration) (*ApprovalRequest, error) {
	a, err := db.GetApprovalRequest(id)
	if err != nil {
		return nil, err
	}
	if a.Status != ApprovalPending {
		return nil, ErrApprovalDecided
	}
	ts := formatSQLiteUTC(now)
	if !now.Before(a.ExpiresAt) {
		_, _ = db.Exec(`UPDATE approval_requests SET status='expired' WHERE id=? AND status='pending'`, id)
		return nil, ErrApprovalExpired
	}
	status, exp := ApprovalDenied, a.ExpiresAt
	if approve {
		status, exp = ApprovalApproved, now.Add(ttl)
	}
	res, err := db.Exec(`UPDATE approval_requests SET status=?, decided_at=?, decided_by=?, decision_reason=?, expires_at=?
		WHERE id=? AND status='pending'`, status, ts, by, reason, formatSQLiteUTC(exp), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrApprovalDecided
	}
	return db.GetApprovalRequest(id)
}
