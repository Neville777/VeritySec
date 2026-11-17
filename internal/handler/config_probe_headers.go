package handler

import (
	"veritysec/internal/config"
	"fmt"
	"strings"
)

// resolveProbeHeaders restores only explicitly scoped, same-target secrets.
// Missing/ambiguous markers fail before any outbound HTTP request is made.
func (h *ConfigHandler) resolveProbeHeaders(req TestOpenAIRequest) (map[string]string, error) {
	needsStored := false
	seen := map[string]bool{}
	for name, value := range req.Headers {
		key := strings.ToLower(strings.TrimSpace(name))
		if seen[key] {
			return nil, fmt.Errorf("duplicate header name")
		}
		seen[key] = true
		if strings.Contains(value, maskedSecret) {
			needsStored = true
		}
	}
	if !needsStored {
		return config.ExpandHeaderMap(req.Headers), nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.config == nil {
		return nil, fmt.Errorf("no saved header credential")
	}
	var stored config.OpenAIConfig
	switch {
	case req.ChannelID != "":
		ch, ok := h.config.AI.Channels[req.ChannelID]
		if !ok {
			return nil, fmt.Errorf("unknown channel; cannot restore header credential")
		}
		stored = ch.ToOpenAIConfig()
		if req.CredentialScope == "hitlAudit" {
			stored = h.config.Hitl.AuditModelEffective(stored)
		} else if req.CredentialScope != "" && req.CredentialScope != "openai" {
			return nil, fmt.Errorf("header credential scope mismatch")
		}
	case req.CredentialScope == "hitlAudit":
		stored = h.config.Hitl.AuditModelEffective(h.config.OpenAI)
	case req.CredentialScope == "openai":
		stored = h.config.OpenAI
	default:
		return nil, fmt.Errorf("specify the channel or model credential scope to restore headers")
	}
	if probeHeaderProvider(req.Provider) != probeHeaderProvider(stored.Provider) || probeHeaderURL(req.Provider, req.BaseURL) != probeHeaderURL(stored.Provider, stored.BaseURL) || strings.TrimSpace(req.APIKey) != strings.TrimSpace(stored.APIKey) {
		return nil, fmt.Errorf("model identity or address has changed; please re-enter header credentials")
	}
	out := make(map[string]string, len(req.Headers))
	for name, value := range req.Headers {
		if strings.Contains(value, maskedSecret) {
			if value != maskedSecret {
				return nil, fmt.Errorf("invalid header credential placeholder")
			}
			found := ""
			count := 0
			for savedName, savedValue := range stored.Headers {
				if strings.EqualFold(strings.TrimSpace(savedName), strings.TrimSpace(name)) {
					found = savedValue
					count++
				}
			}
			if count != 1 || strings.TrimSpace(found) == "" || strings.Contains(found, maskedSecret) {
				return nil, fmt.Errorf("no unique saved header credential")
			}
			value = found
		}
		out[name] = value
	}
	return config.ExpandHeaderMap(out), nil
}
func probeHeaderProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return "openai"
	}
	return provider
}
func probeHeaderURL(provider, raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		if probeHeaderProvider(provider) == "claude" {
			return "https://api.anthropic.com"
		}
		return "https://api.openai.com/v1"
	}
	return raw
}
