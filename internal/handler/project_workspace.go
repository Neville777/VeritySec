package handler

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
)

// workspaceFile is one entry of the project workspace's "files" list.
//
// Path carries the same value the chat-uploads download/content routes expect as their "path"
// query parameter (chat_upload_artifacts.relative_path), i.e. exactly what
// web/static/js/chat-files.js sends via downloadChatFile(f.relativePath, ...). ID carries the
// same value so a reader that only knows the generic "id" field still gets a working reference.
type workspaceFile struct {
	ID             string    `json:"id"`
	Path           string    `json:"path"`
	Name           string    `json:"name"`
	SizeBytes      int64     `json:"size_bytes"`
	ConversationID string    `json:"conversation_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// workspaceReportDownload is one renderable report format for one audience.
type workspaceReportDownload struct {
	Audience string `json:"audience"`
	Format   string `json:"format"`
	Path     string `json:"path"`
}

// workspaceReport is the set of report downloads available for one of the project's engagements.
type workspaceReport struct {
	EngagementID   string                    `json:"engagement_id"`
	EngagementName string                    `json:"engagement_name"`
	Downloads      []workspaceReportDownload `json:"downloads"`
}

var workspaceReportAudiences = []string{"executive", "technical", "developer"}
var workspaceReportFormats = []string{"md", "html", "docx"}

// buildWorkspaceReports lists the six download paths for each engagement, without generating
// any report content.
func buildWorkspaceReports(engagements []database.WorkspaceEngagement) []workspaceReport {
	out := make([]workspaceReport, 0, len(engagements))
	for _, e := range engagements {
		downloads := make([]workspaceReportDownload, 0, len(workspaceReportAudiences)*len(workspaceReportFormats))
		for _, audience := range workspaceReportAudiences {
			for _, format := range workspaceReportFormats {
				downloads = append(downloads, workspaceReportDownload{
					Audience: audience,
					Format:   format,
					Path:     fmt.Sprintf("/api/engagements/%s/report?audience=%s&format=%s", e.ID, audience, format),
				})
			}
		}
		out = append(out, workspaceReport{EngagementID: e.ID, EngagementName: e.Name, Downloads: downloads})
	}
	return out
}

// chatUploadsAbsRoot mirrors ChatUploadsHandler.absRoot: chat_upload_artifacts.relative_path is
// resolved under <cwd>/chat_uploads.
func chatUploadsAbsRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(cwd, chatUploadsRootDirName))
}

// buildWorkspaceFiles resolves each artifact's display name and on-disk size. A file that is
// missing or outside the uploads root is still listed, with size 0, so a stale row never hides
// the rest of the list.
func buildWorkspaceFiles(artifacts []database.WorkspaceFileArtifact) []workspaceFile {
	root, rootErr := chatUploadsAbsRoot()
	out := make([]workspaceFile, 0, len(artifacts))
	for _, a := range artifacts {
		var size int64
		if rootErr == nil {
			if full, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(a.RelativePath))); err == nil {
				if st, err := os.Stat(full); err == nil && !st.IsDir() {
					size = st.Size()
				}
			}
		}
		out = append(out, workspaceFile{
			ID:             a.RelativePath,
			Path:           a.RelativePath,
			Name:           filepath.Base(a.RelativePath),
			SizeBytes:      size,
			ConversationID: a.ConversationID,
			CreatedAt:      a.CreatedAt,
		})
	}
	return out
}

// GetProjectWorkspace GET /api/projects/:id/workspace returns everything the project owns:
// its conversations, findings, assets, engagements, evidence, files, batch queues and the
// report download paths for each engagement, scoped to what the caller may read.
func (h *ProjectHandler) GetProjectWorkspace(c *gin.Context) {
	id := c.Param("id")
	session, _ := security.CurrentSession(c)
	scope := session.ScopeFor("project:read")

	p, err := h.db.GetProject(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}
	if !h.db.UserCanAccessResource(session.UserID, scope, "project", id) {
		// Do not distinguish "exists but you cannot see it" from "does not exist".
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	engagements, engagementCount, err := h.db.ProjectWorkspaceEngagements(id, session.UserID, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	conversations, conversationCount, err := h.db.ProjectWorkspaceConversations(id, session.UserID, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	findings, findingCount, err := h.db.ProjectWorkspaceFindings(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	assets, assetCount, err := h.db.ProjectWorkspaceAssets(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	evidence, evidenceCount, err := h.db.ProjectWorkspaceEvidence(id, session.UserID, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fileArtifacts, fileCount, err := h.db.ProjectWorkspaceFiles(id, session.UserID, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	batchQueues, batchQueueCount, err := h.db.ProjectWorkspaceBatchQueues(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	factCount, err := h.db.ProjectWorkspaceFactCount(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	counts := database.ProjectWorkspaceCounts{
		Conversations: conversationCount,
		Findings:      findingCount,
		Assets:        assetCount,
		Engagements:   engagementCount,
		Evidence:      evidenceCount,
		Files:         fileCount,
		Facts:         factCount,
		BatchQueues:   batchQueueCount,
		Reports:       engagementCount, // one report entry per accessible engagement
	}

	c.JSON(http.StatusOK, gin.H{
		"project":       p,
		"counts":        counts,
		"conversations": conversations,
		"findings":      findings,
		"assets":        assets,
		"engagements":   engagements,
		"evidence":      evidence,
		"files":         buildWorkspaceFiles(fileArtifacts),
		"batch_queues":  batchQueues,
		"reports":       buildWorkspaceReports(engagements),
	})
}
