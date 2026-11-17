package database

import (
	"time"
)

// WorkspaceConversation is one conversation row on the project workspace.
type WorkspaceConversation struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
}

// WorkspaceFinding is one finding row on the project workspace.
type WorkspaceFinding struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	ConversationID string `json:"conversation_id"`
}

// WorkspaceAsset is one asset row on the project workspace.
type WorkspaceAsset struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	Title    string `json:"title"`
}

// WorkspaceEngagement is one engagement row on the project workspace.
type WorkspaceEngagement struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Target string `json:"target"`
}

// WorkspaceEvidence is one evidence row on the project workspace.
type WorkspaceEvidence struct {
	ID           string    `json:"id"`
	EngagementID string    `json:"engagement_id"`
	Kind         string    `json:"kind"`
	Title        string    `json:"title"`
	SHA256       string    `json:"sha256"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
}

// WorkspaceFileArtifact is one chat_upload_artifacts row on the project workspace, before the
// handler resolves its display name and size from disk.
type WorkspaceFileArtifact struct {
	RelativePath   string    `json:"relative_path"`
	ConversationID string    `json:"conversation_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// WorkspaceBatchQueue is one batch task queue row on the project workspace.
type WorkspaceBatchQueue struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

// ProjectWorkspaceCounts holds the full (unfiltered-by-page) counts of a project's records.
type ProjectWorkspaceCounts struct {
	Conversations int `json:"conversations"`
	Findings      int `json:"findings"`
	Assets        int `json:"assets"`
	Engagements   int `json:"engagements"`
	Evidence      int `json:"evidence"`
	Files         int `json:"files"`
	Facts         int `json:"facts"`
	BatchQueues   int `json:"batch_queues"`
	Reports       int `json:"reports"`
}

// workspaceListLimit caps every list on the project workspace endpoint.
const workspaceListLimit = 500

// ProjectWorkspaceEngagements returns the project's engagements the caller may read, newest
// first, capped at workspaceListLimit, plus the full count of accessible engagements.
func (db *DB) ProjectWorkspaceEngagements(projectID, userID, scope string) ([]WorkspaceEngagement, int, error) {
	rows, err := db.Query(`SELECT id, name, status, target FROM engagements WHERE project_id = ? ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	all := []WorkspaceEngagement{}
	for rows.Next() {
		var e WorkspaceEngagement
		if err := rows.Scan(&e.ID, &e.Name, &e.Status, &e.Target); err != nil {
			return nil, 0, err
		}
		all = append(all, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	accessible := make([]WorkspaceEngagement, 0, len(all))
	for _, e := range all {
		if db.UserCanAccessResource(userID, scope, "engagement", e.ID) {
			accessible = append(accessible, e)
		}
	}
	out := accessible
	if len(out) > workspaceListLimit {
		out = out[:workspaceListLimit]
	}
	return out, len(accessible), nil
}

// ProjectWorkspaceConversations returns the project's conversations the caller may read, newest
// first (by created_at), capped at workspaceListLimit, plus the full count.
func (db *DB) ProjectWorkspaceConversations(projectID, userID, scope string) ([]WorkspaceConversation, int, error) {
	total, err := db.CountConversationsForAccess("", projectID, userID, scope)
	if err != nil {
		return nil, 0, err
	}
	convs, err := db.ListConversationsForAccess(workspaceListLimit, 0, "", "created_at", projectID, userID, scope)
	if err != nil {
		return nil, 0, err
	}
	out := make([]WorkspaceConversation, 0, len(convs))
	for _, c := range convs {
		out = append(out, WorkspaceConversation{ID: c.ID, Title: c.Title, CreatedAt: c.CreatedAt})
	}
	return out, total, nil
}

// ProjectWorkspaceFindings returns findings owned by the project directly, through a conversation
// in the project, or through an engagement in the project. Findings follow their parent project's
// access rather than being filtered individually, matching the other project-scoped list endpoints.
func (db *DB) ProjectWorkspaceFindings(projectID string) ([]WorkspaceFinding, int, error) {
	const where = `WHERE project_id = ?
		OR conversation_id IN (SELECT id FROM conversations WHERE project_id = ?)
		OR engagement_id IN (SELECT id FROM engagements WHERE project_id = ?)`
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities `+where, projectID, projectID, projectID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`SELECT id, title, severity, status, COALESCE(conversation_id, '') FROM vulnerabilities `+where+` ORDER BY created_at DESC LIMIT ?`,
		projectID, projectID, projectID, workspaceListLimit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []WorkspaceFinding{}
	for rows.Next() {
		var f WorkspaceFinding
		if err := rows.Scan(&f.ID, &f.Title, &f.Severity, &f.Status, &f.ConversationID); err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}

// ProjectWorkspaceAssets returns assets owned by the project directly or through an engagement
// in the project.
func (db *DB) ProjectWorkspaceAssets(projectID string) ([]WorkspaceAsset, int, error) {
	const where = `WHERE project_id = ? OR engagement_id IN (SELECT id FROM engagements WHERE project_id = ?)`
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets `+where, projectID, projectID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`SELECT id, host, ip, port, domain, protocol, title FROM assets `+where+` ORDER BY created_at DESC LIMIT ?`,
		projectID, projectID, workspaceListLimit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []WorkspaceAsset{}
	for rows.Next() {
		var a WorkspaceAsset
		if err := rows.Scan(&a.ID, &a.Host, &a.IP, &a.Port, &a.Domain, &a.Protocol, &a.Title); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// ProjectWorkspaceEvidence returns evidence of the project's engagements that the caller may
// read. Evidence inherits access from its engagement, matching the resourceAllowed check used
// for GET /api/evidence/:id.
func (db *DB) ProjectWorkspaceEvidence(projectID, userID, scope string) ([]WorkspaceEvidence, int, error) {
	rows, err := db.Query(`SELECT id, engagement_id, kind, title, sha256, size_bytes, created_at FROM evidence
		WHERE engagement_id IN (SELECT id FROM engagements WHERE project_id = ?) ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	all := []WorkspaceEvidence{}
	for rows.Next() {
		var e WorkspaceEvidence
		if err := rows.Scan(&e.ID, &e.EngagementID, &e.Kind, &e.Title, &e.SHA256, &e.SizeBytes, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		all = append(all, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	accessible := make([]WorkspaceEvidence, 0, len(all))
	for _, e := range all {
		if db.UserCanAccessResource(userID, scope, "engagement", e.EngagementID) {
			accessible = append(accessible, e)
		}
	}
	out := accessible
	if len(out) > workspaceListLimit {
		out = out[:workspaceListLimit]
	}
	return out, len(accessible), nil
}

// ProjectWorkspaceFiles returns chat_upload_artifacts rows whose conversation belongs to the
// project and the caller may read (access inherits from the conversation).
func (db *DB) ProjectWorkspaceFiles(projectID, userID, scope string) ([]WorkspaceFileArtifact, int, error) {
	rows, err := db.Query(`SELECT relative_path, conversation_id, created_at FROM chat_upload_artifacts
		WHERE conversation_id IN (SELECT id FROM conversations WHERE project_id = ?) ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	all := []WorkspaceFileArtifact{}
	for rows.Next() {
		var f WorkspaceFileArtifact
		if err := rows.Scan(&f.RelativePath, &f.ConversationID, &f.CreatedAt); err != nil {
			return nil, 0, err
		}
		all = append(all, f)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	accessible := make([]WorkspaceFileArtifact, 0, len(all))
	for _, f := range all {
		if db.UserCanAccessResource(userID, scope, "conversation", f.ConversationID) {
			accessible = append(accessible, f)
		}
	}
	out := accessible
	if len(out) > workspaceListLimit {
		out = out[:workspaceListLimit]
	}
	return out, len(accessible), nil
}

// ProjectWorkspaceBatchQueues returns the project's batch task queues.
func (db *DB) ProjectWorkspaceBatchQueues(projectID string) ([]WorkspaceBatchQueue, int, error) {
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM batch_task_queues WHERE project_id = ?`, projectID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`SELECT id, COALESCE(title, ''), status FROM batch_task_queues WHERE project_id = ? ORDER BY created_at DESC LIMIT ?`,
		projectID, workspaceListLimit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []WorkspaceBatchQueue{}
	for rows.Next() {
		var q WorkspaceBatchQueue
		if err := rows.Scan(&q.ID, &q.Title, &q.Status); err != nil {
			return nil, 0, err
		}
		out = append(out, q)
	}
	return out, total, rows.Err()
}

// ProjectWorkspaceFactCount counts the project's non-deprecated facts.
func (db *DB) ProjectWorkspaceFactCount(projectID string) (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM project_facts WHERE project_id = ? AND confidence != 'deprecated'`, projectID).Scan(&n)
	return n, err
}
