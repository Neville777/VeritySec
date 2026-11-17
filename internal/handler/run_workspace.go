package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"veritysec/internal/database"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RunHandler serves the read-only run workspace: data and read endpoints only.
type RunHandler struct {
	db     *database.DB
	logger *zap.Logger
}

// NewRunHandler creates the handler.
func NewRunHandler(db *database.DB, logger *zap.Logger) *RunHandler {
	return &RunHandler{db: db, logger: logger}
}

// GetRunWorkspace GET /api/runs/:messageId/workspace.
//
// Access uses the same check the chat endpoints use for message-scoped resources
// (db.UserCanAccessMessage, scoped to the chat:read permission). A message the caller cannot
// read, or that does not exist, both come back as 404 so neither case leaks which is true.
func (h *RunHandler) GetRunWorkspace(c *gin.Context) {
	messageID := c.Param("messageId")

	session, ok := security.CurrentSession(c)
	if !ok || !h.db.UserCanAccessMessage(session.UserID, session.ScopeFor("chat:read"), messageID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}

	ws, err := h.db.GetRunWorkspace(messageID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
			return
		}
		h.logger.Error("failed to build run workspace", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ws)
}

// GetResumePlan GET /api/runs/:messageId/resume-plan.
//
// Read-only: it reports what resuming this run would mean (the last completed stage, the stage
// to resume, which tool executions completed and must not be repeated, and which started without
// a completion record and so must not be silently re-run) without running or resuming anything.
// Access uses the same message-scoped check as GetRunWorkspace.
func (h *RunHandler) GetResumePlan(c *gin.Context) {
	messageID := c.Param("messageId")

	session, ok := security.CurrentSession(c)
	if !ok || !h.db.UserCanAccessMessage(session.UserID, session.ScopeFor("chat:read"), messageID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}

	plan, err := h.db.ResumePlan(messageID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
			return
		}
		h.logger.Error("failed to build resume plan", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// GetRunEvents GET /api/runs/:messageId/events?after_seq=N&limit=500.
//
// Returns the persisted run events with seq > after_seq in order, plus next_seq (the seq to pass
// as after_seq next time). Access is the same as GetRunWorkspace: chat:read on the message's
// conversation; unreadable or unknown messages are both 404.
func (h *RunHandler) GetRunEvents(c *gin.Context) {
	messageID := c.Param("messageId")
	session, ok := security.CurrentSession(c)
	if !ok || !h.db.UserCanAccessMessage(session.UserID, session.ScopeFor("chat:read"), messageID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "run not found"})
		return
	}
	afterSeq, _ := strconv.ParseInt(c.Query("after_seq"), 10, 64)
	if afterSeq < 0 {
		afterSeq = 0
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	events, err := h.db.ListRunEvents(messageID, afterSeq, limit)
	if err != nil {
		h.logger.Error("failed to list run events", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	next := afterSeq
	if n := len(events); n > 0 {
		next = events[n-1].Seq
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "next_seq": next})
}
