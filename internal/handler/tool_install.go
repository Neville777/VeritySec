package handler

import (
	"net/http"
	"time"

	"veritysec/internal/authctx"
	"veritysec/internal/events"
	"veritysec/internal/toolinstall"
	"veritysec/internal/toolrisk"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// ListToolInstalls returns the install inventory: which tools are present and how each is installed.
func ListToolInstalls(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"tools": toolinstall.Inventory()})
}

// StartToolInstall starts an install or uninstall for a tool in the fixed install table.
func StartToolInstall(c *gin.Context) {
	var req struct {
		Command string `json:"command" binding:"required"`
		Action  string `json:"action" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	job, err := toolinstall.Start(req.Command, req.Action)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, job)
}

// GetToolInstallJob returns the status and output of an install job.
func GetToolInstallJob(c *gin.Context) {
	job, ok := toolinstall.GetJob(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}
	c.JSON(http.StatusOK, job)
}

// ListToolRisk checks every installed tool in the install table for known vulnerabilities (OSV),
// CVSS scores, and CISA KEV membership.
func ListToolRisk(c *gin.Context) {
	var commands []string
	for _, row := range toolinstall.Inventory() {
		if row.Installed {
			commands = append(commands, row.Command)
		}
	}
	reports := toolrisk.AssessAll(c.Request.Context(), commands)
	c.JSON(http.StatusOK, gin.H{"reports": reports})
}

var eventsUpgrader = websocket.Upgrader{} // same-origin check; the route itself is behind login

// EventsWS streams real-time events to the browser. Each client only receives events it is allowed to see.
func EventsWS(c *gin.Context) {
	principal, ok := authctx.PrincipalFromContext(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	conn, err := eventsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	ch, cancel := events.Subscribe(principal.UserID, principal.Permissions)
	defer cancel()

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ping.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-closed:
			return
		}
	}
}
