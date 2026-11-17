package database

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Relation types and confidence levels of the asset relationship graph. Confidence records
// provenance: an AI inference ("inferred") never becomes a fact by itself.
const (
	RelResolvesTo      = "RESOLVES_TO"
	RelHostsService    = "HOSTS_SERVICE"
	RelRunsTechnology  = "RUNS_TECHNOLOGY"
	RelSubdomainOf     = "SUBDOMAIN_OF"
	RelExposesPort     = "EXPOSES_PORT"
	RelConnectsTo      = "CONNECTS_TO"
	ConfInferred       = "inferred"
	ConfObserved       = "observed"
	ConfManual         = "manual"
	ConfVerified       = "verified"
	assetGraphToolUser = "tool"
)

var (
	ErrRelationshipNotFound = errors.New("asset relationship not found")
	// ErrRelationshipRule is wrapped by every refusal of a confidence rule (HTTP 400/403 material).
	ErrRelationshipRule = errors.New("asset relationship rule violated")
)

func relationshipRuleErrorf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrRelationshipRule, fmt.Sprintf(format, args...))
}

// ValidRelationType reports whether t is a supported relation type.
func ValidRelationType(t string) bool {
	switch t {
	case RelResolvesTo, RelHostsService, RelRunsTechnology, RelSubdomainOf, RelExposesPort, RelConnectsTo:
		return true
	}
	return false
}

func assetRelConfidenceRank(c string) int {
	switch c {
	case ConfInferred:
		return 0
	case ConfObserved:
		return 1
	case ConfManual:
		return 2
	case ConfVerified:
		return 3
	}
	return -1
}

// AssetRelationship is one provenance-carrying edge between two assets of an engagement.
type AssetRelationship struct {
	ID              string    `json:"id"`
	EngagementID    string    `json:"engagement_id"`
	FromAssetID     string    `json:"from_asset_id"`
	ToAssetID       string    `json:"to_asset_id"`
	RelationType    string    `json:"relation_type"`
	Confidence      string    `json:"confidence"`
	EvidenceID      string    `json:"evidence_id,omitempty"`
	ToolExecutionID string    `json:"tool_execution_id,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
}

// AssetRelationshipInput describes one requested edge. Human is true only for a person acting
// over HTTP; CanVerify is true only when that person holds project:write. Tools set neither.
type AssetRelationshipInput struct {
	EngagementID    string
	FromAssetID     string
	ToAssetID       string
	RelationType    string
	Confidence      string
	EvidenceID      string
	ToolExecutionID string
	Reason          string
	CreatedBy       string
	Human           bool
	CanVerify       bool
}

const assetRelColumns = `id, engagement_id, from_asset_id, to_asset_id, relation_type, confidence, COALESCE(evidence_id,''), COALESCE(tool_execution_id,''), reason, created_by, created_at`

func scanAssetRelationship(r rowScanner) (*AssetRelationship, error) {
	var a AssetRelationship
	if err := r.Scan(&a.ID, &a.EngagementID, &a.FromAssetID, &a.ToAssetID, &a.RelationType, &a.Confidence,
		&a.EvidenceID, &a.ToolExecutionID, &a.Reason, &a.CreatedBy, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

// GetAssetRelationship loads one edge.
func (db *DB) GetAssetRelationship(id string) (*AssetRelationship, error) {
	a, err := scanAssetRelationship(db.QueryRow(`SELECT `+assetRelColumns+` FROM asset_relationships WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRelationshipNotFound
	}
	return a, err
}

// AssetRelationshipEngagementID returns the engagement an edge belongs to.
func (db *DB) AssetRelationshipEngagementID(id string) (string, error) {
	var e string
	err := db.QueryRow(`SELECT engagement_id FROM asset_relationships WHERE id = ?`, id).Scan(&e)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrRelationshipNotFound
	}
	return e, err
}

func (db *DB) assetInEngagement(engagementID, assetID string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE id = ? AND engagement_id = ?`, assetID, engagementID).Scan(&n)
	return n > 0, err
}

// UpsertAssetRelationship creates an edge or changes the confidence of an existing one.
//
// Rules:
//   - both assets must belong to the engagement; relation type and confidence must be valid;
//   - verified needs a non-empty Reason and CanVerify (project:write);
//   - observed needs EvidenceID or ToolExecutionID, and an EvidenceID must belong to the engagement;
//   - manual needs a human;
//   - on an existing edge, raising confidence is allowed; lowering it needs a human.
func (db *DB) UpsertAssetRelationship(in AssetRelationshipInput) (*AssetRelationship, error) {
	in.EngagementID, in.FromAssetID, in.ToAssetID = strings.TrimSpace(in.EngagementID), strings.TrimSpace(in.FromAssetID), strings.TrimSpace(in.ToAssetID)
	in.RelationType, in.Confidence = strings.TrimSpace(in.RelationType), strings.TrimSpace(in.Confidence)
	in.EvidenceID, in.ToolExecutionID, in.Reason = strings.TrimSpace(in.EvidenceID), strings.TrimSpace(in.ToolExecutionID), strings.TrimSpace(in.Reason)
	if !ValidRelationType(in.RelationType) {
		return nil, relationshipRuleErrorf("invalid relation_type %q", in.RelationType)
	}
	newRank := assetRelConfidenceRank(in.Confidence)
	if newRank < 0 {
		return nil, relationshipRuleErrorf("invalid confidence %q", in.Confidence)
	}
	if in.FromAssetID == "" || in.ToAssetID == "" || in.FromAssetID == in.ToAssetID {
		return nil, relationshipRuleErrorf("from_asset_id and to_asset_id must be two different assets")
	}
	switch in.Confidence {
	case ConfVerified:
		if in.Reason == "" {
			return nil, relationshipRuleErrorf("verified requires a non-empty reason")
		}
		if !in.CanVerify {
			return nil, relationshipRuleErrorf("verified requires project:write")
		}
	case ConfObserved:
		if in.EvidenceID == "" && in.ToolExecutionID == "" {
			return nil, relationshipRuleErrorf("observed requires evidence_id or tool_execution_id")
		}
	case ConfManual:
		if !in.Human {
			return nil, relationshipRuleErrorf("manual confidence can only be set by a person")
		}
	}
	if _, err := db.GetEngagement(in.EngagementID); err != nil {
		return nil, err
	}
	if in.EvidenceID != "" {
		eid, err := db.EvidenceEngagementID(in.EvidenceID)
		if err != nil {
			if errors.Is(err, ErrEvidenceNotFound) {
				return nil, relationshipRuleErrorf("evidence %s does not exist", in.EvidenceID)
			}
			return nil, err
		}
		if eid != in.EngagementID {
			return nil, relationshipRuleErrorf("evidence %s does not belong to this engagement", in.EvidenceID)
		}
	}
	for _, id := range []string{in.FromAssetID, in.ToAssetID} {
		ok, err := db.assetInEngagement(in.EngagementID, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, relationshipRuleErrorf("asset %s does not belong to this engagement", id)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	existing, err := scanAssetRelationship(tx.QueryRow(`SELECT `+assetRelColumns+` FROM asset_relationships
		WHERE engagement_id = ? AND from_asset_id = ? AND to_asset_id = ? AND relation_type = ?`,
		in.EngagementID, in.FromAssetID, in.ToAssetID, in.RelationType))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		id := uuid.NewString()
		if _, err := tx.Exec(`INSERT INTO asset_relationships
			(id, engagement_id, from_asset_id, to_asset_id, relation_type, confidence, evidence_id, tool_execution_id, reason, created_by, created_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`, id, in.EngagementID, in.FromAssetID, in.ToAssetID, in.RelationType, in.Confidence,
			nullIfEmpty(in.EvidenceID), nullIfEmpty(in.ToolExecutionID), in.Reason, in.CreatedBy, time.Now().UTC()); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return db.GetAssetRelationship(id)
	case err != nil:
		return nil, err
	}
	oldRank := assetRelConfidenceRank(existing.Confidence)
	if newRank < oldRank && !in.Human {
		return nil, relationshipRuleErrorf("confidence cannot be downgraded from %s to %s except by a person", existing.Confidence, in.Confidence)
	}
	if newRank == oldRank && in.Confidence != ConfVerified {
		// Same level: keep the original provenance, only fill what was missing.
		if existing.EvidenceID != "" || in.EvidenceID == "" {
			if existing.ToolExecutionID != "" || in.ToolExecutionID == "" {
				return existing, nil
			}
		}
	}
	evID, execID, reason := in.EvidenceID, in.ToolExecutionID, in.Reason
	if newRank == oldRank {
		if existing.EvidenceID != "" {
			evID = existing.EvidenceID
		}
		if existing.ToolExecutionID != "" {
			execID = existing.ToolExecutionID
		}
		if reason == "" {
			reason = existing.Reason
		}
	}
	if _, err := tx.Exec(`UPDATE asset_relationships SET confidence = ?, evidence_id = ?, tool_execution_id = ?, reason = ? WHERE id = ?`,
		in.Confidence, nullIfEmpty(evID), nullIfEmpty(execID), reason, existing.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetAssetRelationship(existing.ID)
}

// UpdateAssetRelationshipConfidence changes the confidence of an existing edge under the same rules.
func (db *DB) UpdateAssetRelationshipConfidence(id string, in AssetRelationshipInput) (*AssetRelationship, error) {
	cur, err := db.GetAssetRelationship(id)
	if err != nil {
		return nil, err
	}
	in.EngagementID, in.FromAssetID, in.ToAssetID, in.RelationType = cur.EngagementID, cur.FromAssetID, cur.ToAssetID, cur.RelationType
	return db.UpsertAssetRelationship(in)
}

// AssetGraphNode is one asset of an engagement graph.
type AssetGraphNode struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	Title    string `json:"title"`
}

// AssetGraph is the node/edge view of one engagement's assets.
type AssetGraph struct {
	Nodes []AssetGraphNode    `json:"nodes"`
	Edges []AssetRelationship `json:"edges"`
}

// ListAssetGraph returns the engagement's assets and the edges between them. Edges whose
// endpoints are not both assets of the engagement are never returned.
func (db *DB) ListAssetGraph(engagementID string) (*AssetGraph, error) {
	g := &AssetGraph{Nodes: []AssetGraphNode{}, Edges: []AssetRelationship{}}
	rows, err := db.Query(`SELECT id, host, ip, port, domain, protocol, title FROM assets WHERE engagement_id = ? ORDER BY host, port, id`, engagementID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n AssetGraphNode
		if err := rows.Scan(&n.ID, &n.Host, &n.IP, &n.Port, &n.Domain, &n.Protocol, &n.Title); err != nil {
			rows.Close()
			return nil, err
		}
		g.Nodes = append(g.Nodes, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	erows, err := db.Query(`SELECT `+assetRelColumns+` FROM asset_relationships r WHERE engagement_id = ?
		AND from_asset_id IN (SELECT id FROM assets WHERE engagement_id = r.engagement_id)
		AND to_asset_id IN (SELECT id FROM assets WHERE engagement_id = r.engagement_id)
		ORDER BY relation_type, created_at, id`, engagementID)
	if err != nil {
		return nil, err
	}
	defer erows.Close()
	for erows.Next() {
		e, err := scanAssetRelationship(erows)
		if err != nil {
			return nil, err
		}
		g.Edges = append(g.Edges, *e)
	}
	return g, erows.Err()
}

// RecordObservedAssetEdges is the hook for the tool asset-save path. For a saved asset that
// belongs to an engagement it records, with the tool execution as provenance:
//   - RESOLVES_TO between a hostname asset and an IP-only asset of the engagement with the same IP;
//   - SUBDOMAIN_OF from a hostname asset to a domain asset whose name it ends with.
//
// Nothing is recorded without a tool execution ID (there would be no provenance) and nothing is
// ever created in the assets table. Best effort: failures are returned but the asset is saved.
func (db *DB) RecordObservedAssetEdges(assetID, toolExecutionID string) error {
	toolExecutionID = strings.TrimSpace(toolExecutionID)
	if assetID == "" || toolExecutionID == "" {
		return nil
	}
	var eng, host, ip, domain string
	err := db.QueryRow(`SELECT COALESCE(engagement_id,''), host, ip, domain FROM assets WHERE id = ?`, assetID).Scan(&eng, &host, &ip, &domain)
	if err != nil || eng == "" {
		return nil
	}
	name := assetHostname(domain, host)
	nameIsHost := name != "" && net.ParseIP(name) == nil
	ip = strings.TrimSpace(ip)
	add := func(from, to, rel string) error {
		_, err := db.UpsertAssetRelationship(AssetRelationshipInput{EngagementID: eng, FromAssetID: from, ToAssetID: to,
			RelationType: rel, Confidence: ConfObserved, ToolExecutionID: toolExecutionID, CreatedBy: assetGraphToolUser})
		return err
	}
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// IP-only means: no hostname, or the host field merely repeats the IP.
	ipOnly := `(host = '' OR host = ip) AND domain = ''`
	if nameIsHost && net.ParseIP(ip) != nil {
		rows, err := db.Query(`SELECT id FROM assets WHERE engagement_id = ? AND ip = ? AND id <> ? AND `+ipOnly, eng, ip, assetID)
		if err == nil {
			var ids []string
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
			for _, id := range ids {
				keep(add(assetID, id, RelResolvesTo))
			}
		}
	} else if net.ParseIP(ip) != nil && (name == "" || name == ip) {
		rows, err := db.Query(`SELECT id FROM assets WHERE engagement_id = ? AND ip = ? AND id <> ? AND host <> '' AND host <> ip`, eng, ip, assetID)
		if err == nil {
			var ids []string
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
			for _, id := range ids {
				keep(add(id, assetID, RelResolvesTo))
			}
		}
	}
	if nameIsHost {
		rows, err := db.Query(`SELECT id, host, domain FROM assets WHERE engagement_id = ? AND id <> ? AND (domain <> '' OR (ip = '' AND host <> ''))`, eng, assetID)
		if err == nil {
			type cand struct{ id, host, domain string }
			var cs []cand
			for rows.Next() {
				var c cand
				if rows.Scan(&c.id, &c.host, &c.domain) == nil {
					cs = append(cs, c)
				}
			}
			rows.Close()
			for _, c := range cs {
				// A domain asset carries the domain field, or a bare hostname with no IP semantics.
				d := assetHostname(c.domain, c.host)
				if d == "" || d == name || net.ParseIP(d) != nil {
					continue
				}
				if strings.HasSuffix(name, "."+d) {
					keep(add(assetID, c.id, RelSubdomainOf))
				}
			}
		}
	}
	return firstErr
}

// assetHostname is the lower-case name an asset is known by: its domain, else its host with any
// URL scheme, port and trailing dot removed.
func assetHostname(domain, host string) string {
	n := strings.TrimSpace(domain)
	if n == "" {
		n = strings.TrimSpace(host)
		if strings.Contains(n, "://") {
			if u, err := url.Parse(n); err == nil {
				n = u.Hostname()
			}
		}
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(n, "[]"), "."))
}
