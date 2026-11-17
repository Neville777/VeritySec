package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrVerificationNotFound is returned when a finding has no verification record.
var ErrVerificationNotFound = errors.New("verification not found")

// FindingVerification is one independent review of a finding's claims. Verdicts are stored as
// the JSON the verify package produced. Status is never CONFIRMED: only a person sets that.
type FindingVerification struct {
	ID                 string          `json:"id"`
	VulnerabilityID    string          `json:"vulnerability_id"`
	Status             string          `json:"status"`
	Reasons            []string        `json:"reasons"`
	PrimaryVerdicts    json.RawMessage `json:"primary_verdicts"`
	ChallengerVerdicts json.RawMessage `json:"challenger_verdicts"`
	PrimaryModel       string          `json:"primary_model"`
	ChallengerModel    string          `json:"challenger_model"`
	CreatedAt          time.Time       `json:"created_at"`
}

func jsonOrEmptyArray(raw json.RawMessage) string {
	if len(strings.TrimSpace(string(raw))) == 0 || !json.Valid(raw) {
		return "[]"
	}
	return string(raw)
}

// InsertFindingVerification stores a record. ID and CreatedAt are filled when empty.
func (db *DB) InsertFindingVerification(v *FindingVerification) error {
	if strings.TrimSpace(v.VulnerabilityID) == "" || strings.TrimSpace(v.Status) == "" {
		return errors.New("vulnerability_id and status are required")
	}
	if v.ID == "" {
		v.ID = uuid.New().String()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	if v.Reasons == nil {
		v.Reasons = []string{}
	}
	reasons, err := json.Marshal(v.Reasons)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO finding_verifications
		(id, vulnerability_id, status, reasons, primary_verdicts, challenger_verdicts, primary_model, challenger_model, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.VulnerabilityID, v.Status, string(reasons), jsonOrEmptyArray(v.PrimaryVerdicts), jsonOrEmptyArray(v.ChallengerVerdicts),
		v.PrimaryModel, v.ChallengerModel, v.CreatedAt)
	return err
}

// LatestFindingVerification returns the newest record for a finding, or ErrVerificationNotFound.
func (db *DB) LatestFindingVerification(findingID string) (*FindingVerification, error) {
	var v FindingVerification
	var reasons, pv, cv string
	err := db.QueryRow(`SELECT id, vulnerability_id, status, reasons, primary_verdicts, challenger_verdicts, primary_model, challenger_model, created_at
		FROM finding_verifications WHERE vulnerability_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`, findingID).
		Scan(&v.ID, &v.VulnerabilityID, &v.Status, &reasons, &pv, &cv, &v.PrimaryModel, &v.ChallengerModel, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVerificationNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(reasons), &v.Reasons); err != nil || v.Reasons == nil {
		v.Reasons = []string{}
	}
	v.PrimaryVerdicts = json.RawMessage(pv)
	v.ChallengerVerdicts = json.RawMessage(cv)
	return &v, nil
}

// VerifierActor is the audit actor of confidence changes made from a verification.
const VerifierActor = "verifier"

// RaiseConfidenceFromVerification raises a finding to "validated" after a CONFIRMABLE decision.
// It goes through SetVulnerabilityConfidence, so every existing rule (tool evidence, reason,
// project:write, all claims supported) still applies; a refusal is returned as
// *ErrConfidenceRefused. It never writes "confirmed" and never lowers a level: when the finding
// is already validated or confirmed it changes nothing and returns raised=false. The caller must
// have verified that the requesting user holds project:write.
func (db *DB) RaiseConfidenceFromVerification(findingID, verificationID, requestedBy string) (raised bool, err error) {
	vuln, err := db.GetVulnerability(findingID)
	if err != nil {
		return false, err
	}
	cur, ok := confidenceRank(strings.TrimSpace(vuln.Confidence))
	if !ok {
		cur = 0
	}
	target, _ := confidenceRank(ConfidenceValidated)
	if cur >= target {
		return false, nil
	}
	reason := "verifier: CONFIRMABLE decision, verification " + verificationID
	if requestedBy != "" {
		reason += ", requested by " + requestedBy
	}
	if _, err := db.SetVulnerabilityConfidence(SetVulnerabilityConfidenceParams{
		FindingID: findingID, Confidence: ConfidenceValidated, Reason: reason,
		ActorUserID: VerifierActor, ActorHasProjectWrite: true,
	}); err != nil {
		return false, err
	}
	return true, nil
}
