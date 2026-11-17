package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

	"veritysec/internal/mcp"
	"veritysec/internal/websearch"
)

// registerWebTools gives the agent web search, page fetching and (when enabled) a headless browser.
func registerWebTools(mcpServer *mcp.Server, store *websearch.Store) {
	textResult := func(v interface{}, isErr bool) *mcp.ToolResult {
		b, _ := json.MarshalIndent(v, "", "  ")
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: string(b)}}, IsError: isErr}
	}

	searchTool := mcp.Tool{
		Name:             "web_search",
		Description:      "Search the web for current information. Providers are tried in the order set in Settings → Web search; if one fails, the next is used. Results include dates where the provider gives them. Use this for anything recent (news, new CVEs, current versions) and check dates against today's date.",
		ShortDescription: "Search the web",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query":       map[string]interface{}{"type": "string", "description": "Search query."},
				"max_results": map[string]interface{}{"type": "integer", "description": "How many results to return (1-20, default 8)."},
			},
			"required": []string{"query"},
		},
	}
	mcpServer.RegisterTool(searchTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		query, _ := args["query"].(string)
		n := 8
		if v, ok := args["max_results"].(float64); ok {
			n = int(v)
		}
		results, provider, attempts, err := websearch.Search(ctx, store, query, n)
		if err != nil {
			return textResult(map[string]interface{}{"error": err.Error(), "attempts": attempts}, true), nil
		}
		return textResult(map[string]interface{}{"provider": provider, "results": results, "failedProviders": attempts}, false), nil
	})

	fetchTool := mcp.Tool{
		Name:             "web_fetch",
		Description:      "Fetch a public web page and return its readable text. Internal and private addresses are refused. Use after web_search to read a result.",
		ShortDescription: "Fetch a web page's text",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{"type": "string", "description": "Public http or https URL."},
			},
			"required": []string{"url"},
		},
	}
	mcpServer.RegisterTool(fetchTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		raw, _ := args["url"].(string)
		status, text, err := websearch.Fetch(ctx, strings.TrimSpace(raw))
		if err != nil {
			return textResult(fmt.Sprintf("fetch failed: %v", err), true), nil
		}
		return textResult(map[string]interface{}{"status": status, "text": text}, false), nil
	})

	browseTool := mcp.Tool{
		Name:             "web_browse",
		Description:      "Load a public page in a headless Chrome browser, run its JavaScript, and return the rendered text. Only available when the headless browser is turned on in Settings → Web search.",
		ShortDescription: "Load a page with JavaScript",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"url": map[string]interface{}{"type": "string", "description": "Public http or https URL."},
			},
			"required": []string{"url"},
		},
	}
	mcpServer.RegisterTool(browseTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		enabled := false
		for _, p := range store.List() {
			if p.ID == "browser" {
				enabled = p.Enabled
			}
		}
		if !enabled {
			return textResult("the headless browser is turned off; enable it in Settings → Web search", true), nil
		}
		raw, _ := args["url"].(string)
		text, err := websearch.Browse(ctx, strings.TrimSpace(raw))
		if err != nil {
			return textResult(fmt.Sprintf("browse failed: %v", err), true), nil
		}
		return textResult(map[string]interface{}{"text": text}, false), nil
	})

	registerOptionalWebTools(mcpServer, store, textResult)
}

// providerState returns the provider's key and whether it is enabled and configured.
func providerState(store *websearch.Store, id string) (key string, ready bool) {
	for _, p := range store.List() {
		if p.ID == id {
			return p.Key, p.Configured()
		}
	}
	return "", false
}

var urlToolSchema = map[string]interface{}{
	"type": "object",
	"properties": map[string]interface{}{
		"url": map[string]interface{}{"type": "string", "description": "Public http or https URL."},
	},
	"required": []string{"url"},
}

// registerOptionalWebTools adds web_firecrawl_scrape and web_playwright_fetch, each only when its
// provider is enabled (and, for Firecrawl, has a key). Both take a "url" argument, which the
// engagement scope guard checks like any other url argument. The handlers re-check the setting
// on every call, so turning a provider off stops the tool at once; turning one on registers the
// tool the next time tools are registered (config apply or restart).
func registerOptionalWebTools(mcpServer *mcp.Server, store *websearch.Store, textResult func(interface{}, bool) *mcp.ToolResult) {
	if _, ready := providerState(store, "firecrawl"); ready {
		mcpServer.RegisterTool(mcp.Tool{
			Name:             "web_firecrawl_scrape",
			Description:      "Scrape a public page through the Firecrawl API and return it as markdown. The URL is sent to Firecrawl's servers. Internal and private addresses are refused. Only available when Firecrawl is enabled with an API key in Settings → Web search.",
			ShortDescription: "Scrape a page with Firecrawl",
			InputSchema:      urlToolSchema,
		}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
			key, ready := providerState(store, "firecrawl")
			if !ready {
				return textResult("Firecrawl is turned off or has no API key; configure it in Settings → Web search", true), nil
			}
			raw, _ := args["url"].(string)
			text, err := websearch.Firecrawl(ctx, key, strings.TrimSpace(raw))
			if err != nil {
				return textResult(fmt.Sprintf("firecrawl failed: %v", err), true), nil
			}
			return textResult(map[string]interface{}{"markdown": text}, false), nil
		})
	}
	if _, ready := providerState(store, "playwright"); ready {
		mcpServer.RegisterTool(mcp.Tool{
			Name:             "web_playwright_fetch",
			Description:      "Load a public page in Playwright's headless Chromium, run its JavaScript, and return the rendered text. Every request the page makes is checked and internal addresses are blocked; downloads are off. Only available when Playwright is enabled in Settings → Web search.",
			ShortDescription: "Load a page with Playwright",
			InputSchema:      urlToolSchema,
		}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
			if _, ready := providerState(store, "playwright"); !ready {
				return textResult("Playwright is turned off; enable it in Settings → Web search", true), nil
			}
			raw, _ := args["url"].(string)
			text, err := websearch.PlaywrightFetch(ctx, strings.TrimSpace(raw))
			if err != nil {
				return textResult(fmt.Sprintf("playwright failed: %v", err), true), nil
			}
			return textResult(map[string]interface{}{"text": text}, false), nil
		})
	}
}

var (
	webSearchOnce  sync.Once
	webSearchStore *websearch.Store
)

// getWebSearchStore loads the provider settings under data/ once and shares them. A bad file falls back to the defaults and logs why.
func getWebSearchStore() *websearch.Store {
	webSearchOnce.Do(func() {
		store, err := websearch.NewStore("data/web-search-providers.json")
		if err != nil {
			log.Printf("web search settings unreadable, using defaults: %v", err)
			store, _ = websearch.NewStore("")
		}
		webSearchStore = store
	})
	return webSearchStore
}
