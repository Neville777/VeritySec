package handler

import (
	"net/http"
	"strings"

	"veritysec/internal/database"
	"veritysec/internal/email"
	"veritysec/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type BYOKHandler struct {
	db               *database.DB
	logger           *zap.Logger
	encryptionSecret string
}

func NewBYOKHandler(db *database.DB, logger *zap.Logger, encryptionSecret string) *BYOKHandler {
	return &BYOKHandler{db: db, logger: logger, encryptionSecret: encryptionSecret}
}

type upsertKeyRequest struct {
	Provider string `json:"provider" binding:"required"`
	APIKey   string `json:"api_key" binding:"required"`
	Label    string `json:"label"`
}

func (h *BYOKHandler) UpsertKey(c *gin.Context) {
	session, _ := security.CurrentSession(c)
	if session.UserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	var req upsertKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Provider = strings.TrimSpace(strings.ToLower(req.Provider))
	validProviders := map[string]bool{
		"openai": true, "openrouter": true, "anthropic": true,
		"google": true, "deepseek": true, "custom": true,
	}
	if !validProviders[req.Provider] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider; use: openai, openrouter, anthropic, google, deepseek, custom"})
		return
	}

	encrypted, err := email.EncryptValue(req.APIKey, h.encryptionSecret)
	if err != nil {
		h.logger.Error("failed to encrypt api key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
		return
	}

	key, err := h.db.UpsertUserAPIKey(session.UserID, req.Provider, encrypted, req.Label)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"key": gin.H{
			"id":       key.ID,
			"provider": key.Provider,
			"label":    key.Label,
			"masked":   maskKey(req.APIKey),
		},
	})
}

func (h *BYOKHandler) ListKeys(c *gin.Context) {
	session, _ := security.CurrentSession(c)
	if session.UserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	keys, err := h.db.ListUserAPIKeys(session.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	out := make([]gin.H, 0, len(keys))
	for _, k := range keys {
		out = append(out, gin.H{
			"id":         k.ID,
			"provider":   k.Provider,
			"label":      k.Label,
			"created_at": k.CreatedAt,
			"updated_at": k.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"keys": out})
}

func (h *BYOKHandler) DeleteKey(c *gin.Context) {
	session, _ := security.CurrentSession(c)
	if session.UserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	provider := strings.TrimSpace(c.Param("provider"))
	if err := h.db.DeleteUserAPIKey(session.UserID, provider); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (h *BYOKHandler) ResolveKey(userID, provider string) (string, error) {
	key, err := h.db.GetUserAPIKey(userID, provider)
	if err != nil {
		return "", err
	}
	return email.DecryptValue(key.EncryptedKey, h.encryptionSecret)
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}
