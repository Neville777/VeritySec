package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"veritysec/internal/audit"
	"veritysec/internal/database"
	emailpkg "veritysec/internal/email"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type AccessRequestHandler struct {
	db     *database.DB
	logger *zap.Logger
	audit  *audit.Service
	email  *emailpkg.Service
}

func NewAccessRequestHandler(db *database.DB, logger *zap.Logger) *AccessRequestHandler {
	return &AccessRequestHandler{db: db, logger: logger}
}

func (h *AccessRequestHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

func (h *AccessRequestHandler) SetEmailService(s *emailpkg.Service) {
	h.email = s
}

type submitAccessRequest struct {
	Name   string `json:"name" binding:"required"`
	Email  string `json:"email" binding:"required"`
	Reason string `json:"reason"`
}

func (h *AccessRequestHandler) Submit(c *gin.Context) {
	var req submitAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Reason = strings.TrimSpace(req.Reason)

	if req.Name == "" || req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and email are required"})
		return
	}

	request, err := h.db.CreateAccessRequest(req.Name, req.Email, req.Reason)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Your access request has been submitted. You will receive an email when it is reviewed.",
		"request": request,
	})
}

func (h *AccessRequestHandler) List(c *gin.Context) {
	status := strings.TrimSpace(c.Query("status"))
	requests, err := h.db.ListAccessRequests(status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if requests == nil {
		requests = []database.AccessRequest{}
	}
	c.JSON(http.StatusOK, gin.H{"requests": requests})
}

type reviewRequest struct {
	Status string `json:"status" binding:"required"`
	Role   string `json:"role"`
}

func (h *AccessRequestHandler) Review(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	session, _ := security.CurrentSession(c)

	var req reviewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	accessReq, err := h.db.GetAccessRequest(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}

	if err := h.db.ReviewAccessRequest(id, session.UserID, req.Status); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.audit != nil {
		h.audit.RecordOK(c, "rbac", "review_access_request", "Review access request", "access_request", id, map[string]interface{}{
			"status": req.Status,
			"email":  accessReq.Email,
		})
	}

	if req.Status == "approved" {
		password := generatePassword(16)
		username := sanitizeUsername(accessReq.Name)

		roleID := req.Role
		if roleID == "" {
			roleID = "operator"
		}

		hash, err := security.HashPassword(password)
		if err != nil {
			h.logger.Error("failed to hash password for approved user", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
			return
		}

		user, err := h.db.CreateRBACUser(username, accessReq.Name, hash, true, []string{roleID})
		if err != nil {
			h.logger.Error("failed to create user from access request", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user: " + err.Error()})
			return
		}

		if h.email != nil && h.email.Enabled() {
			if err := h.email.SendWelcome(accessReq.Email, username, password); err != nil {
				h.logger.Warn("failed to send welcome email to approved user", zap.String("email", accessReq.Email), zap.Error(err))
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"message":  "approved",
			"user":     user,
			"username": username,
			"password": password,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "rejected"})
}

func generatePassword(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

func sanitizeUsername(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.ReplaceAll(name, " ", ".")
	var clean []byte
	for _, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			clean = append(clean, c)
		}
	}
	if len(clean) == 0 {
		return "user"
	}
	if len(clean) > 32 {
		clean = clean[:32]
	}
	return string(clean)
}
