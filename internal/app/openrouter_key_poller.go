package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"veritysec/internal/config"
	"veritysec/internal/database"

	"go.uber.org/zap"
)

const openRouterKeyURL = "https://openrouter.ai/api/v1/auth/key"

// openRouterAPIKey returns the api_key of the first channel whose base_url host is openrouter.ai.
func openRouterAPIKey(ai config.AIConfig) string {
	names := make([]string, 0, len(ai.Channels))
	for name := range ai.Channels {
		names = append(names, name)
	}
	// deterministic: default channel first, then the rest by name
	pick := func(ch config.AIChannelConfig) string {
		u, err := url.Parse(strings.TrimSpace(ch.BaseURL))
		if err == nil && strings.EqualFold(u.Hostname(), "openrouter.ai") && strings.TrimSpace(ch.APIKey) != "" {
			return strings.TrimSpace(ch.APIKey)
		}
		return ""
	}
	if ch, ok := ai.Channels[ai.DefaultChannel]; ok {
		if k := pick(ch); k != "" {
			return k
		}
	}
	best := ""
	bestName := ""
	for _, name := range names {
		if k := pick(ai.Channels[name]); k != "" && (bestName == "" || name < bestName) {
			best, bestName = k, name
		}
	}
	return best
}

func fetchOpenRouterKeyUsage(ctx context.Context, client *http.Client, apiKey string) (float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openRouterKeyURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Usage *float64 `json:"usage"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode response: %w", err)
	}
	if body.Data.Usage == nil {
		return 0, fmt.Errorf("response has no data.usage")
	}
	return *body.Data.Usage, nil
}

// startOpenRouterKeyPoller checks the OpenRouter key's total spend every 60 seconds while an
// openrouter.ai channel is configured. Errors are logged (never the key) and the last value is kept.
func startOpenRouterKeyPoller(db *database.DB, aiConfig func() config.AIConfig, logger *zap.Logger) {
	go func() {
		client := &http.Client{Timeout: 20 * time.Second}
		poll := func() {
			key := openRouterAPIKey(aiConfig())
			if key == "" {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			spent, err := fetchOpenRouterKeyUsage(ctx, client, key)
			if err != nil {
				logger.Warn("openrouter key usage check failed", zap.Error(err))
				return
			}
			if err := db.SetOpenRouterKeyUsage(spent, time.Now()); err != nil {
				logger.Warn("failed to store openrouter key usage", zap.Error(err))
			}
		}
		poll()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			poll()
		}
	}()
}
