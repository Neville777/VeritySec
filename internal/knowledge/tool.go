package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"veritysec/internal/mcp"
	"veritysec/internal/mcp/builtin"

	"go.uber.org/zap"
)

// RegisterKnowledgeTool registers the knowledge retrieval tools with the MCP server
func RegisterKnowledgeTool(
	mcpServer *mcp.Server,
	retriever *Retriever,
	manager *Manager,
	logger *zap.Logger,
) {
	// register the first tool: list all available risk types
	listRiskTypesTool := mcp.Tool{
		Name:             builtin.ToolListKnowledgeRiskTypes,
		Description:      "List all available risk types (risk_type) in the knowledge base. Before searching the knowledge base, call this tool to get the available risk types, then use the correct risk type for precise search; this greatly reduces retrieval time and improves accuracy.",
		ShortDescription: "List all available risk types in the knowledge base",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
			"required":   []string{},
		},
	}

	listRiskTypesHandler := func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		categories, err := manager.GetCategories()
		if err != nil {
			logger.Error("failed to get risk type list", zap.Error(err))
			return &mcp.ToolResult{
				Content: []mcp.Content{
					{
						Type: "text",
						Text: fmt.Sprintf("failed to get risk type list: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		if len(categories) == 0 {
			return &mcp.ToolResult{
				Content: []mcp.Content{
					{
						Type: "text",
						Text: "No risk types in the knowledge base yet.",
					},
				},
			}, nil
		}

		var resultText strings.Builder
		resultText.WriteString(fmt.Sprintf("The knowledge base has %d risk types:\n\n", len(categories)))
		for i, category := range categories {
			resultText.WriteString(fmt.Sprintf("%d. %s\n", i+1, category))
		}
		resultText.WriteString("\nTip: when calling the " + builtin.ToolSearchKnowledgeBase + " tool, you can use one of the risk types above as the risk_type parameter to narrow the search scope and improve retrieval efficiency.")

		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: resultText.String(),
				},
			},
		}, nil
	}

	mcpServer.RegisterTool(listRiskTypesTool, listRiskTypesHandler)
	logger.Debug("risk type list tool registered", zap.String("toolName", listRiskTypesTool.Name))

	// register the second tool: search the knowledge base (original functionality retained)
	searchTool := mcp.Tool{
		Name:             builtin.ToolSearchKnowledgeBase,
		Description:      "Search the knowledge base for relevant security knowledge. Use this tool when you need security knowledge about specific vulnerability types, attack techniques, detection methods, etc. The tool is based on vector embeddings and cosine similarity retrieval (consistent with Eino retriever semantics). Suggestion: before searching, call " + builtin.ToolListKnowledgeRiskTypes + " to get the available risk types, then use the correct risk_type parameter for precise search; this greatly reduces retrieval time.",
		ShortDescription: "Search security knowledge in the knowledge base (vector semantic retrieval)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "search query, describing the security knowledge topic you want to learn about",
				},
				"risk_type": map[string]interface{}{
					"type":        "string",
					"description": "Optional: specify the risk type (e.g. SQL injection, XSS, file upload). It is recommended to call " + builtin.ToolListKnowledgeRiskTypes + " first to get the list of available risk types, then use the correct risk type for precise search; this greatly reduces retrieval time. If not specified, all types are searched.",
				},
			},
			"required": []string{"query"},
		},
	}

	searchHandler := func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		query, ok := args["query"].(string)
		if !ok || query == "" {
			return &mcp.ToolResult{
				Content: []mcp.Content{
					{
						Type: "text",
						Text: "error: query parameter cannot be empty",
					},
				},
				IsError: true,
			}, nil
		}

		riskType := ""
		if rt, ok := args["risk_type"].(string); ok && rt != "" {
			riskType = rt
		}

		logger.Info("performing knowledge base retrieval",
			zap.String("query", query),
			zap.String("riskType", riskType),
		)

		// retrieval goes through Retriever.Search -> VectorEinoRetriever (Eino retriever semantics).
		searchReq := &SearchRequest{
			Query:    query,
			RiskType: riskType,
			TopK:     5,
		}

		results, err := retriever.Search(ctx, searchReq)
		if err != nil {
			logger.Error("knowledge base retrieval failed", zap.Error(err))
			return &mcp.ToolResult{
				Content: []mcp.Content{
					{
						Type: "text",
						Text: fmt.Sprintf("retrieval failed: %v", err),
					},
				},
				IsError: true,
			}, nil
		}

		if len(results) == 0 {
			return &mcp.ToolResult{
				Content: []mcp.Content{
					{
						Type: "text",
						Text: fmt.Sprintf("No knowledge related to query '%s' was found. Suggestions:\n1. Try different keywords\n2. Check whether the risk type is correct\n3. Confirm whether the knowledge base contains relevant content", query),
					},
				},
			}, nil
		}

		// format results
		var resultText strings.Builder

		// sort by cosine similarity (Score) in descending order
		sort.Slice(results, func(i, j int) bool {
			return results[i].Score > results[j].Score
		})

		// group results by document to better present context
		type itemGroup struct {
			itemID   string
			results  []*RetrievalResult
			maxScore float64 // highest similarity of this document chunk
		}
		itemGroups := make([]*itemGroup, 0)
		itemMap := make(map[string]*itemGroup)

		for _, result := range results {
			itemID := result.Item.ID
			group, exists := itemMap[itemID]
			if !exists {
				group = &itemGroup{
					itemID:   itemID,
					results:  make([]*RetrievalResult, 0),
					maxScore: result.Score,
				}
				itemMap[itemID] = group
				itemGroups = append(itemGroups, group)
			}
			group.results = append(group.results, result)
			if result.Score > group.maxScore {
				group.maxScore = result.Score
			}
		}

		// sort by the highest similarity within each document
		sort.Slice(itemGroups, func(i, j int) bool {
			return itemGroups[i].maxScore > itemGroups[j].maxScore
		})

		// collect retrieved knowledge item IDs (for logging)
		retrievedItemIDs := make([]string, 0, len(itemGroups))

		resultText.WriteString(fmt.Sprintf("found %d relevant knowledge fragments:\n\n", len(results)))

		resultIndex := 1
		for _, group := range itemGroups {
			itemResults := group.results
			mainResult := itemResults[0]
			maxScore := mainResult.Score
			for _, result := range itemResults {
				if result.Score > maxScore {
					maxScore = result.Score
					mainResult = result
				}
			}

			// sort by chunk_index to keep the logical reading order (original document order)
			sort.Slice(itemResults, func(i, j int) bool {
				return itemResults[i].Chunk.ChunkIndex < itemResults[j].Chunk.ChunkIndex
			})

			resultText.WriteString(fmt.Sprintf("--- result %d (similarity: %.2f%%) ---\n",
				resultIndex, mainResult.Similarity*100))
			resultText.WriteString(fmt.Sprintf("source: [%s] %s (ID: %s)\n", mainResult.Item.Category, mainResult.Item.Title, mainResult.Item.ID))

			// display all chunks in logical order (including the main result and expanded chunks)
			if len(itemResults) == 1 {
				// only one chunk: display directly
				resultText.WriteString(fmt.Sprintf("content fragment:\n%s\n", mainResult.Chunk.ChunkText))
			} else {
				// multiple chunks: display in logical order
				resultText.WriteString("content fragments (in document order):\n")
				for i, result := range itemResults {
					// mark the main result
					marker := ""
					if result.Chunk.ID == mainResult.Chunk.ID {
						marker = " [main match]"
					}
					resultText.WriteString(fmt.Sprintf("  [fragment %d%s]\n%s\n", i+1, marker, result.Chunk.ChunkText))
				}
			}
			resultText.WriteString("\n")

			if !contains(retrievedItemIDs, group.itemID) {
				retrievedItemIDs = append(retrievedItemIDs, group.itemID)
			}
			resultIndex++
		}

		// append metadata at the end of the result (JSON format, used to extract knowledge item IDs)
		// use a special marker to avoid affecting the AI's reading of the result
		if len(retrievedItemIDs) > 0 {
			metadataJSON, _ := json.Marshal(map[string]interface{}{
				"_metadata": map[string]interface{}{
					"retrievedItemIDs": retrievedItemIDs,
				},
			})
			resultText.WriteString(fmt.Sprintf("\n<!-- METADATA: %s -->", string(metadataJSON)))
		}

		// record retrieval log (asynchronous, non-blocking)
		// note: there is no conversationID or messageID here; they must be recorded at the Agent level
		// the actual log recording should be done in the Agent's progressCallback

		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: resultText.String(),
				},
			},
		}, nil
	}

	mcpServer.RegisterTool(searchTool, searchHandler)
	logger.Debug("knowledge retrieval tool registered", zap.String("toolName", searchTool.Name))
}

// contains checks whether a slice contains an element
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetRetrievalMetadata extracts retrieval metadata from a tool call (for logging)
func GetRetrievalMetadata(args map[string]interface{}) (query string, riskType string) {
	if q, ok := args["query"].(string); ok {
		query = q
	}
	if rt, ok := args["risk_type"].(string); ok {
		riskType = rt
	}
	return
}

// FormatRetrievalResults formats retrieval results as a string (for logging)
func FormatRetrievalResults(results []*RetrievalResult) string {
	if len(results) == 0 {
		return "no relevant results found"
	}

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("retrieved %d results:\n", len(results)))

	itemIDs := make(map[string]bool)
	for i, result := range results {
		builder.WriteString(fmt.Sprintf("%d. [%s] %s (similarity: %.2f%%)\n",
			i+1, result.Item.Category, result.Item.Title, result.Similarity*100))
		itemIDs[result.Item.ID] = true
	}

	// return the knowledge item ID list (JSON format)
	ids := make([]string, 0, len(itemIDs))
	for id := range itemIDs {
		ids = append(ids, id)
	}
	idsJSON, _ := json.Marshal(ids)
	builder.WriteString(fmt.Sprintf("\nretrieved knowledge item IDs: %s", string(idsJSON)))

	return builder.String()
}
