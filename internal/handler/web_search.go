package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"veritysec/internal/websearch"

	"github.com/gin-gonic/gin"
)

// providerView is what the settings page sees. The key itself is never returned.
type providerView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	NeedKey   bool   `json:"needKey"`
	Enabled   bool   `json:"enabled"`
	Order     int    `json:"order"`
	Hint      string `json:"hint"`
	HasKey    bool   `json:"hasKey"`
	KeyMasked string `json:"keyMasked"`
}

// ListWebSearchProviders returns the providers in order, with keys masked.
func ListWebSearchProviders(store *websearch.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		out := []providerView{}
		for _, p := range store.List() {
			out = append(out, providerView{
				ID: p.ID, Name: p.Name, NeedKey: p.NeedKey, Enabled: p.Enabled, Order: p.Order,
				Hint: p.Hint, HasKey: p.Key != "", KeyMasked: p.MaskedKey(),
			})
		}
		c.JSON(http.StatusOK, gin.H{"providers": out})
	}
}

// UpdateWebSearchProvider changes a provider's key, enabled flag, or order. An empty key keeps the stored one.
func UpdateWebSearchProvider(store *websearch.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Key     *string `json:"key"`
			Enabled *bool   `json:"enabled"`
			Order   *int    `json:"order"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := store.Update(c.Param("id"), req.Key, req.Enabled, req.Order); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

// TestWebSearchProvider runs one small query through a provider and reports whether it works.
func TestWebSearchProvider(store *websearch.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
		defer cancel()
		if err := store.Test(ctx, c.Param("id")); err != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": strings.TrimSpace(err.Error())})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}
