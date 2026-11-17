package project

import (
	"veritysec/internal/database"
)

// ApplyFactOutgoingLinks replaces the outgoing edges of a fact (no change when links is nil).
func ApplyFactOutgoingLinks(db *database.DB, projectID, sourceFactKey, sourceConversationID string, links []database.ProjectFactEdgeInput) error {
	if links == nil {
		return nil
	}
	return db.ReplaceOutgoingProjectFactEdges(projectID, sourceFactKey, sourceConversationID, links)
}

// ResolveFactLinkInputs merges the links array and links_text (array takes precedence).
func ResolveFactLinkInputs(links []database.ProjectFactEdgeFromInput, linksText string) ([]database.ProjectFactEdgeFromInput, error) {
	if len(links) > 0 {
		return links, nil
	}
	return ParseFactLinksText(linksText)
}

// ApplyFactIncomingLinks replaces the incoming edges of a fact (no change when links is nil).
func ApplyFactIncomingLinks(db *database.DB, projectID, targetFactKey string, links []database.ProjectFactEdgeFromInput) error {
	if links == nil {
		return nil
	}
	return db.ReplaceIncomingProjectFactEdges(projectID, targetFactKey, links)
}

// PersistFactIncomingLinks writes incoming edges and optionally syncs the current fact's body related section.
func PersistFactIncomingLinks(db *database.DB, projectID, targetFactKey string, links []database.ProjectFactEdgeFromInput, syncBody bool) error {
	if links == nil {
		return nil
	}
	if err := ApplyFactIncomingLinks(db, projectID, targetFactKey, links); err != nil {
		return err
	}
	if !syncBody {
		return nil
	}
	f, err := db.GetProjectFactByKey(projectID, targetFactKey)
	if err != nil {
		return nil
	}
	in, err := db.ListIncomingProjectFactEdges(projectID, targetFactKey)
	if err != nil {
		return err
	}
	f.Body = SyncBodyLinksSection(f.Body, in)
	_, err = db.UpsertProjectFact(f)
	return err
}

// PersistFactLinksFromParsed writes the parsed links (parsed nil means no change).
func PersistFactLinksFromParsed(db *database.DB, projectID, factKey, sourceConversationID string, parsed *ParsedFactLinks, syncBody bool) error {
	if parsed == nil || parsed.Incoming == nil {
		return nil
	}
	return PersistFactIncomingLinks(db, projectID, factKey, parsed.Incoming, syncBody)
}

// PersistFactOutgoingLinks writes outgoing edges (low-level API for graph wiring; for body sync use PersistFactIncomingLinks).
func PersistFactOutgoingLinks(db *database.DB, projectID, sourceFactKey, sourceConversationID string, links []database.ProjectFactEdgeInput, syncBody bool) error {
	if links == nil {
		return nil
	}
	return ApplyFactOutgoingLinks(db, projectID, sourceFactKey, sourceConversationID, links)
}

// LinkCountMap incoming/outgoing edge counts for each fact in the project.
type LinkCountMap map[string]LinkCounts

// LinkCounts incoming/outgoing edge counts for a single fact.
type LinkCounts struct {
	Outgoing int `json:"outgoing"`
	Incoming int `json:"incoming"`
}

// LoadProjectFactLinkCounts batch-loads edge counts.
func LoadProjectFactLinkCounts(db *database.DB, projectID string) (LinkCountMap, error) {
	edges, err := db.ListProjectFactEdgesByProject(projectID)
	if err != nil {
		return nil, err
	}
	m := LinkCountMap{}
	for _, e := range edges {
		c := m[e.SourceFactKey]
		c.Outgoing++
		m[e.SourceFactKey] = c
		c = m[e.TargetFactKey]
		c.Incoming++
		m[e.TargetFactKey] = c
	}
	return m, nil
}
