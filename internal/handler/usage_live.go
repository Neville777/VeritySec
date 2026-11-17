package handler

import (
	"net/http"
	"strings"
	"time"

	"veritysec/internal/config"

	"github.com/gin-gonic/gin"
)

var usageServerStart = time.Now()

var liveUsageAIConfig func() config.AIConfig

// SetLiveUsageAIConfig supplies the (hot-reloadable) AI config used for pricing.
func (h *EngagementHandler) SetLiveUsageAIConfig(f func() config.AIConfig) { liveUsageAIConfig = f }

type liveModelOut struct {
	Model            string   `json:"model"`
	PromptTokens     int64    `json:"prompt_tokens"`
	CompletionTokens int64    `json:"completion_tokens"`
	CachedTokens     int64    `json:"cached_tokens"`
	TotalTokens      int64    `json:"total_tokens"`
	PriceSet         bool     `json:"price_set"`
	Note             string   `json:"note,omitempty"`
	CostUSD          *float64 `json:"cost_usd"`
}

// Get returns token totals, per-model cost and KSh conversion.
func (h *EngagementHandler) GetLiveUsage(c *gin.Context) {
	u, err := h.db.GetLiveUsage(usageServerStart)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ai := config.AIConfig{}
	if liveUsageAIConfig != nil {
		ai = liveUsageAIConfig()
	}
	models := make([]liveModelOut, 0, len(u.Models))
	totalUSD := 0.0
	for _, m := range u.Models {
		o := liveModelOut{Model: m.Model, PromptTokens: m.PromptTokens, CompletionTokens: m.CompletionTokens,
			CachedTokens: m.CachedTokens, TotalTokens: m.TotalTokens}
		p, ok := ai.Pricing[m.Model]
		if !ok {
			p, ok = ai.Pricing[strings.TrimSpace(m.Model)]
		}
		if ok {
			uncached := m.PromptTokens - m.CachedTokens
			if uncached < 0 {
				uncached = 0
			}
			// no separate cache price: cached tokens are billed at the input price
			cost := (float64(uncached)+float64(m.CachedTokens))*p.InputUSDPerMillion/1e6 +
				float64(m.CompletionTokens)*p.OutputUSDPerMillion/1e6
			o.PriceSet = true
			o.CostUSD = &cost
			totalUSD += cost
		} else {
			o.Note = "no price set"
		}
		models = append(models, o)
	}
	var ksh *float64
	rateSet := ai.KesPerUSD > 0
	if rateSet {
		v := totalUSD * ai.KesPerUSD
		ksh = &v
	}
	newest := any(nil)
	if u.Newest != "" {
		newest = u.Newest
	}
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	costSince, _ := h.db.SumModelCallCost(usageServerStart)
	costToday, _ := h.db.SumModelCallCost(midnight)
	var orSpent any
	var orChecked any
	if v, t, err := h.db.GetOpenRouterKeyUsage(); err == nil {
		if v != nil {
			orSpent = *v
		}
		if t != nil {
			orChecked = t.UTC().Format(time.RFC3339)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"cost_usd_recorded":     gin.H{"since_start": costSince, "today": costToday},
		"openrouter_spent_usd":  orSpent,
		"openrouter_checked_at": orChecked,
		"server_started_at":     usageServerStart.UTC().Format(time.RFC3339),
		"since_start":           u.SinceStart,
		"today":                 u.Today,
		"calls_since_start":     u.CallsSinceStart,
		"calls_today":           u.CallsToday,
		"models":                models,
		"total_usd":             totalUSD,
		"total_usdt":            totalUSD,
		"kes_per_usd":           ai.KesPerUSD,
		"rate_set":              rateSet,
		"total_ksh":             ksh,
		"newest_usage_at":       newest,
	})
}
