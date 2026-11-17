package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"veritysec/internal/agents"
	"veritysec/internal/audit"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/knowledge"
	"veritysec/internal/llm"
	"veritysec/internal/mcp"
	"veritysec/internal/mcp/builtin"
	"veritysec/internal/openai"
	"veritysec/internal/security"
	"veritysec/internal/toolguard"
	"veritysec/internal/typesafe"

	"github.com/cloudwego/eino/schema"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// KnowledgeToolRegistrar is the knowledge base tool registrar interface
type KnowledgeToolRegistrar func() error

// VulnerabilityToolRegistrar is the vulnerability tool registrar interface
type VulnerabilityToolRegistrar func() error

// WebshellToolRegistrar is the WebShell tool registrar interface (re-registered on ApplyConfig)
type WebshellToolRegistrar func() error

// SkillsToolRegistrar is the Skills tool registrar interface
type SkillsToolRegistrar func() error

// BatchTaskToolRegistrar is the batch task MCP tool registrar (re-registered on ApplyConfig)
type BatchTaskToolRegistrar func() error

// C2ToolRegistrar is the C2 MCP tool registrar (called after ClearTools on ApplyConfig)
type C2ToolRegistrar func() error

// C2Runtime starts or stops the C2 subsystem according to the configuration on ApplyConfig (implemented by internal/app.App)
type C2Runtime interface {
	ReconcileC2AfterConfigApply() error
}

// RetrieverUpdater is the retriever update interface
type RetrieverUpdater interface {
	UpdateConfig(config *knowledge.RetrievalConfig)
}

// KnowledgeInitializer is the knowledge base initializer interface
type KnowledgeInitializer func() (*KnowledgeHandler, error)

// AppUpdater is the App update interface (used to update knowledge base components in the App)
type AppUpdater interface {
	UpdateKnowledgeComponents(handler *KnowledgeHandler, manager interface{}, retriever interface{}, indexer interface{})
}

// RobotRestarter restarts robot connections (used to restart DingTalk/Feishu long connections after configuration is applied)
type RobotRestarter interface {
	RestartRobotConnections()
}

// ConfigHandler is the configuration handler
type ConfigHandler struct {
	configPath                 string
	config                     *config.Config
	mcpServer                  *mcp.Server
	executor                   *security.Executor
	agent                      AgentUpdater               // Agent interface, used to update Agent configuration
	attackChainHandler         AttackChainUpdater         // attack chain handler interface, used to update configuration
	externalMCPMgr             *mcp.ExternalMCPManager    // external MCP manager
	knowledgeToolRegistrar     KnowledgeToolRegistrar     // knowledge base tool registrar (optional)
	vulnerabilityToolRegistrar VulnerabilityToolRegistrar // vulnerability tool registrar (optional)
	webshellToolRegistrar      WebshellToolRegistrar      // WebShell tool registrar (optional)
	skillsToolRegistrar        SkillsToolRegistrar        // Skills tool registrar (optional)
	batchTaskToolRegistrar     BatchTaskToolRegistrar     // batch task MCP tools (optional)
	c2ToolRegistrar            C2ToolRegistrar            // C2 MCP tools (optional)
	c2Runtime                  C2Runtime                  // C2 start/stop (optional)
	retrieverUpdater           RetrieverUpdater           // retriever updater (optional)
	knowledgeInitializer       KnowledgeInitializer       // knowledge base initializer (optional)
	appUpdater                 AppUpdater                 // App updater (optional)
	robotRestarter             RobotRestarter             // robot connection restarter (optional); restarts DingTalk/Feishu on ApplyConfig
	audit                      *audit.Service
	db                         *database.DB
	logger                     *zap.Logger
	mu                         sync.RWMutex
	toolGuard                  *toolguard.Manager
	toolGuardRevision          string                  // protected by mu; advanced only after a successful save
	lastEmbeddingConfig        *config.EmbeddingConfig // previous embedding model configuration (used to detect changes)
}

func (h *ConfigHandler) SetDB(db *database.DB) {
	h.db = db
}

func (h *ConfigHandler) validateRobotServiceAccounts(robots config.RobotsConfig) error {
	if h.db == nil {
		return fmt.Errorf("RBAC service unavailable; cannot validate the robot service account")
	}
	for platform, userID := range robots.ServiceAccountUserIDs() {
		user, err := h.db.GetRBACUserByID(userID)
		if err != nil {
			return fmt.Errorf("the user for robots.%s.auth.service_user_id does not exist", platform)
		}
		if !user.Enabled {
			return fmt.Errorf("the user for robots.%s.auth.service_user_id is disabled", platform)
		}
	}
	return nil
}

// AttackChainUpdater is the attack chain handler update interface
type AttackChainUpdater interface {
	UpdateConfig(cfg *config.OpenAIConfig)
}

// AgentUpdater is the Agent update interface
type AgentUpdater interface {
	UpdateConfig(cfg *config.OpenAIConfig)
	UpdateMaxIterations(maxIterations int)
	UpdateToolDescriptionMode(mode string)
}

// NewConfigHandler creates a new configuration handler
func NewConfigHandler(configPath string, cfg *config.Config, mcpServer *mcp.Server, executor *security.Executor, agent AgentUpdater, attackChainHandler AttackChainUpdater, externalMCPMgr *mcp.ExternalMCPManager, logger *zap.Logger) *ConfigHandler {
	// Save the initial embedding model configuration (if the knowledge base is enabled)
	var lastEmbeddingConfig *config.EmbeddingConfig
	if cfg.Knowledge.Enabled {
		lastEmbeddingConfig = &config.EmbeddingConfig{
			Provider: cfg.Knowledge.Embedding.Provider,
			Model:    cfg.Knowledge.Embedding.Model,
			BaseURL:  cfg.Knowledge.Embedding.BaseURL,
			APIKey:   cfg.Knowledge.Embedding.APIKey,
		}
	}
	return &ConfigHandler{
		configPath:          configPath,
		config:              cfg,
		mcpServer:           mcpServer,
		executor:            executor,
		agent:               agent,
		attackChainHandler:  attackChainHandler,
		externalMCPMgr:      externalMCPMgr,
		logger:              logger,
		lastEmbeddingConfig: lastEmbeddingConfig,
	}
}

// SetKnowledgeToolRegistrar sets the knowledge base tool registrar
func (h *ConfigHandler) SetKnowledgeToolRegistrar(registrar KnowledgeToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.knowledgeToolRegistrar = registrar
}

// SetVulnerabilityToolRegistrar sets the vulnerability tool registrar
func (h *ConfigHandler) SetVulnerabilityToolRegistrar(registrar VulnerabilityToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.vulnerabilityToolRegistrar = registrar
}

// SetWebshellToolRegistrar sets the WebShell tool registrar
func (h *ConfigHandler) SetWebshellToolRegistrar(registrar WebshellToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.webshellToolRegistrar = registrar
}

// SetSkillsToolRegistrar sets the Skills tool registrar
func (h *ConfigHandler) SetSkillsToolRegistrar(registrar SkillsToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.skillsToolRegistrar = registrar
}

// SetBatchTaskToolRegistrar sets the batch task MCP tool registrar
func (h *ConfigHandler) SetBatchTaskToolRegistrar(registrar BatchTaskToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.batchTaskToolRegistrar = registrar
}

// SetC2ToolRegistrar sets the C2 MCP tool registrar
func (h *ConfigHandler) SetC2ToolRegistrar(registrar C2ToolRegistrar) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.c2ToolRegistrar = registrar
}

// SetC2Runtime sets the C2 runtime (starts/stops on Apply)
func (h *ConfigHandler) SetC2Runtime(rt C2Runtime) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.c2Runtime = rt
}

// SetRetrieverUpdater sets the retriever updater
func (h *ConfigHandler) SetRetrieverUpdater(updater RetrieverUpdater) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.retrieverUpdater = updater
}

// SetKnowledgeInitializer sets the knowledge base initializer
func (h *ConfigHandler) SetKnowledgeInitializer(initializer KnowledgeInitializer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.knowledgeInitializer = initializer
}

// SetAppUpdater sets the App updater
func (h *ConfigHandler) SetAppUpdater(updater AppUpdater) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.appUpdater = updater
}

// SetRobotRestarter sets the robot connection restarter (used to restart DingTalk/Feishu long connections on ApplyConfig)
func (h *ConfigHandler) SetRobotRestarter(restarter RobotRestarter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.robotRestarter = restarter
}

// SetAudit wires platform audit logging.
func (h *ConfigHandler) SetAudit(s *audit.Service) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.audit = s
}

// ApplyWechatRobotBinding writes the configuration and restarts the robot connection after a successful WeChat iLink QR code binding
func (h *ConfigHandler) ApplyWechatRobotBinding(wc config.RobotWechatConfig) error {
	h.mu.Lock()
	wc.Enabled = true
	h.config.Robots.Wechat = wc
	h.mu.Unlock()
	if err := h.saveConfig(); err != nil {
		return err
	}
	if h.robotRestarter != nil {
		h.robotRestarter.RestartRobotConnections()
	}
	h.logger.Info("WeChat robot binding saved",
		zap.String("ilink_bot_id", wc.ILinkBotID),
		zap.Bool("enabled", wc.Enabled),
	)
	return nil
}

// GetConfigResponse is the get-configuration response
type GetConfigResponse struct {
	AI         config.AIConfig          `json:"ai"`
	OpenAI     config.OpenAIConfig      `json:"openai"`
	Vision     config.VisionConfig      `json:"vision"`
	FOFA       config.FofaConfig        `json:"fofa"`
	ZoomEye    config.SpaceSearchConfig `json:"zoomeye"`
	Quake      config.SpaceSearchConfig `json:"quake"`
	Shodan     config.SpaceSearchConfig `json:"shodan"`
	MCP        config.MCPConfig         `json:"mcp"`
	Tools      []ToolConfigInfo         `json:"tools"`
	Agent      config.AgentConfig       `json:"agent"`
	Hitl       config.HitlConfig        `json:"hitl,omitempty"`
	Knowledge  config.KnowledgeConfig   `json:"knowledge"`
	Robots     config.RobotsConfig      `json:"robots,omitempty"`
	MultiAgent config.MultiAgentPublic  `json:"multi_agent,omitempty"`
	C2         config.C2Public          `json:"c2"`
}

// ToolConfigInfo is tool configuration information
type ToolConfigInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	IsExternal  bool                   `json:"is_external,omitempty"`  // whether this is an external MCP tool
	ExternalMCP string                 `json:"external_mcp,omitempty"` // external MCP name (if an external tool)
	RoleEnabled *bool                  `json:"role_enabled,omitempty"` // whether the tool is enabled in the current role (nil means no role specified or all tools are used)
	InputSchema map[string]interface{} `json:"input_schema,omitempty"` // tool parameter JSON Schema (used for displaying details in the frontend)
}

// GetConfig gets the current configuration
func (h *ConfigHandler) GetConfig(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Get tool list (includes internal and external tools)
	// First get tools from the configuration file
	configToolMap := make(map[string]bool)
	tools := make([]ToolConfigInfo, 0, len(h.config.Security.Tools))

	for _, tool := range h.config.Security.Tools {
		configToolMap[tool.Name] = true
		info := ToolConfigInfo{
			Name:        tool.Name,
			Description: h.pickToolDescription(tool.ShortDescription, tool.Description),
			Enabled:     tool.Enabled,
			IsExternal:  false,
		}
		tools = append(tools, info)
	}

	// Get all registered tools from the MCP server (including directly registered tools such as the knowledge retrieval tool)
	if h.mcpServer != nil {
		mcpTools := h.mcpServer.GetAllTools()
		for _, mcpTool := range mcpTools {
			if configToolMap[mcpTool.Name] {
				continue
			}
			description := h.pickToolDescription(mcpTool.ShortDescription, mcpTool.Description)
			tools = append(tools, ToolConfigInfo{
				Name:        mcpTool.Name,
				Description: description,
				Enabled:     true,
				IsExternal:  false,
			})
		}
	}

	// Get external MCP tools (uses cache; usually does not block while holding the lock)
	if h.externalMCPMgr != nil {
		ctx := context.Background()
		externalTools := h.getExternalMCPTools(ctx)
		for _, toolInfo := range externalTools {
			tools = append(tools, toolInfo)
		}
	}

	subAgentCount := len(h.config.MultiAgent.SubAgents)
	agentsDir := strings.TrimSpace(h.config.AgentsDir)
	if agentsDir == "" {
		agentsDir = "agents"
	}
	if !filepath.IsAbs(agentsDir) {
		agentsDir = filepath.Join(filepath.Dir(h.configPath), agentsDir)
	}
	if load, err := agents.LoadMarkdownAgentsDir(agentsDir); err == nil {
		subAgentCount = len(agents.MergeYAMLAndMarkdown(h.config.MultiAgent.SubAgents, load.SubAgents))
	}
	multiPub := config.MultiAgentPublic{
		Enabled:                                    h.config.MultiAgent.Enabled,
		RobotDefaultAgentMode:                      config.NormalizeRobotAgentMode(h.config.MultiAgent),
		BatchUseMultiAgent:                         h.config.MultiAgent.BatchUseMultiAgent,
		SubAgentCount:                              subAgentCount,
		Orchestration:                              config.NormalizeMultiAgentOrchestration(h.config.MultiAgent.Orchestration),
		PlanExecuteLoopMaxIterations:               h.config.MultiAgent.PlanExecuteLoopMaxIterations,
		SummarizationUserIntentLedgerMaxRunes:      h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerMaxRunesEffective(),
		SummarizationUserIntentLedgerEntryMaxRunes: h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerEntryMaxRunesEffective(),
		LatestUserMessageMaxRunes:                  h.config.MultiAgent.EinoMiddleware.LatestUserMessageMaxRunesEffective(),
		LatestUserMessageHeadRunes:                 h.config.MultiAgent.EinoMiddleware.LatestUserMessageHeadRunesEffective(),
		LatestUserMessageTailRunes:                 h.config.MultiAgent.EinoMiddleware.LatestUserMessageTailRunesEffective(),
		ModelRetryMaxRetries:                       h.config.MultiAgent.EinoMiddleware.ModelRetryMaxRetries,
		ModelRetryMaxBackoffSec:                    h.config.MultiAgent.EinoMiddleware.ModelRetryMaxBackoffSec,
		ModelFailoverChannels:                      append([]string(nil), h.config.MultiAgent.EinoMiddleware.ModelFailoverChannels...),
		ModelFailoverMaxRetries:                    h.config.MultiAgent.EinoMiddleware.ModelFailoverMaxRetries,
		ToolSearchAlwaysVisibleTools:               append([]string(nil), h.config.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools...),
		ToolSearchAlwaysVisibleEffectiveTools: mergeToolNameLists(
			h.config.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools,
			builtin.GetAllBuiltinTools(),
		),
	}

	response, err := maskedConfigResponse(GetConfigResponse{
		AI:         h.config.AI,
		OpenAI:     h.config.OpenAI,
		Vision:     h.config.Vision,
		FOFA:       h.config.FOFA,
		ZoomEye:    h.config.ZoomEye,
		Quake:      h.config.Quake,
		Shodan:     h.config.Shodan,
		MCP:        h.config.MCP,
		Tools:      tools,
		Agent:      h.config.Agent,
		Hitl:       h.config.Hitl,
		Knowledge:  h.config.Knowledge,
		C2:         h.config.C2.Public(),
		Robots:     h.config.Robots,
		MultiAgent: multiPub,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize configuration"})
		return
	}
	c.JSON(http.StatusOK, response)
}

// GetToolsResponse is the tool list response (paginated)
type GetToolsResponse struct {
	Tools        []ToolConfigInfo `json:"tools"`
	Total        int              `json:"total"`
	TotalEnabled int              `json:"total_enabled"` // total number of enabled tools
	Page         int              `json:"page"`
	PageSize     int              `json:"page_size"`
	TotalPages   int              `json:"total_pages"`
}

// GetTools gets the tool list (supports pagination and search)
func (h *ConfigHandler) GetTools(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")

	// Parse pagination parameters
	page := 1
	pageSize := 20
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	// Parse search parameters
	searchTerm := c.Query("search")
	searchTermLower := ""
	if searchTerm != "" {
		searchTermLower = strings.ToLower(searchTerm)
	}

	// Parse status filter: tool_filter=on|off (preferred by role dialogs etc., to avoid conflicts with special handling of enabled by gateways/proxies)
	// Compatible with the legacy parameter enabled=true|false
	var filterEnabled *bool
	toolFilter := strings.TrimSpace(strings.ToLower(c.Query("tool_filter")))
	switch toolFilter {
	case "on", "1", "true", "enabled":
		v := true
		filterEnabled = &v
	case "off", "0", "false", "disabled":
		v := false
		filterEnabled = &v
	default:
		enabledFilter := strings.TrimSpace(c.Query("enabled"))
		if enabledFilter == "true" {
			v := true
			filterEnabled = &v
		} else if enabledFilter == "false" {
			v := false
			filterEnabled = &v
		}
	}

	includeExternal := true
	if v := strings.TrimSpace(strings.ToLower(c.Query("include_external"))); v == "0" || v == "false" || v == "no" {
		includeExternal = false
	}
	refreshExternal := false
	if v := strings.TrimSpace(strings.ToLower(c.Query("refresh_external"))); v == "1" || v == "true" || v == "yes" {
		refreshExternal = true
	}

	// Filter by external MCP name (linked from the left-side card on the MCP management page to the right-side tool list)
	externalMCPFilter := strings.TrimSpace(c.Query("external_mcp"))

	// Release the lock right after snapshotting the configuration, to avoid external MCP network I/O blocking the whole configuration subsystem
	h.mu.RLock()
	securityTools := append([]config.ToolConfig(nil), h.config.Security.Tools...)
	roles := h.config.Roles
	toolDescriptionMode := h.config.Security.ToolDescriptionMode
	mcpServer := h.mcpServer
	externalMCPMgr := h.externalMCPMgr
	h.mu.RUnlock()

	pickDesc := func(shortDesc, fullDesc string) string {
		return pickToolDescriptionWithMode(toolDescriptionMode, shortDesc, fullDesc)
	}

	// Parse the role parameter, used to filter tools and mark enabled status
	roleName := c.Query("role")
	var roleToolsSet map[string]bool // set of tools configured for the role
	var roleUsesAllTools bool = true // whether the role uses all tools (default role)
	if roleName != "" && roleName != "default" && roles != nil {
		if role, exists := roles[roleName]; exists && role.Enabled {
			if len(role.Tools) > 0 {
				// the role has a configured tool list; only these tools are used
				roleToolsSet = make(map[string]bool)
				for _, toolKey := range role.Tools {
					roleToolsSet[toolKey] = true
				}
				roleUsesAllTools = false
			}
		}
	}

	// Get all internal tools and apply search filtering
	configToolMap := make(map[string]bool)
	allTools := make([]ToolConfigInfo, 0, len(securityTools))
	for _, tool := range securityTools {
		configToolMap[tool.Name] = true
		toolInfo := ToolConfigInfo{
			Name:        tool.Name,
			Description: pickDesc(tool.ShortDescription, tool.Description),
			Enabled:     tool.Enabled,
			IsExternal:  false,
		}

		// Mark tool status according to role configuration
		if roleName != "" {
			if roleUsesAllTools {
				// The role uses all tools; mark enabled tools as role_enabled=true
				if tool.Enabled {
					roleEnabled := true
					toolInfo.RoleEnabled = &roleEnabled
				} else {
					roleEnabled := false
					toolInfo.RoleEnabled = &roleEnabled
				}
			} else {
				// The role has a configured tool list; check whether the tool is in the list
				// internal tools use the tool name as the key
				if roleToolsSet[tool.Name] {
					roleEnabled := tool.Enabled // the tool must be in the role list and itself enabled
					toolInfo.RoleEnabled = &roleEnabled
				} else {
					// Not in the role list; mark as false
					roleEnabled := false
					toolInfo.RoleEnabled = &roleEnabled
				}
			}
		}

		// If there is a keyword, apply search filtering
		if searchTermLower != "" {
			nameLower := strings.ToLower(toolInfo.Name)
			descLower := strings.ToLower(toolInfo.Description)
			if !strings.Contains(nameLower, searchTermLower) && !strings.Contains(descLower, searchTermLower) {
				continue // no match; skip
			}
		}

		// Status filter
		if filterEnabled != nil && toolInfo.Enabled != *filterEnabled {
			continue
		}

		allTools = append(allTools, toolInfo)
	}

	// Get all registered tools from the MCP server (including directly registered tools such as the knowledge retrieval tool)
	if mcpServer != nil {
		mcpTools := mcpServer.GetAllTools()
		for _, mcpTool := range mcpTools {
			// Skip tools already in the configuration file (avoid duplicates)
			if configToolMap[mcpTool.Name] {
				continue
			}

			description := pickDesc(mcpTool.ShortDescription, mcpTool.Description)

			toolInfo := ToolConfigInfo{
				Name:        mcpTool.Name,
				Description: description,
				Enabled:     true,
				IsExternal:  false,
			}

			// Mark tool status according to role configuration
			if roleName != "" {
				if roleUsesAllTools {
					// The role uses all tools; directly registered tools are enabled by default
					roleEnabled := true
					toolInfo.RoleEnabled = &roleEnabled
				} else {
					// The role has a configured tool list; check whether the tool is in the list
					// internal tools use the tool name as the key
					if roleToolsSet[mcpTool.Name] {
						roleEnabled := true // in the role list and the tool itself is enabled
						toolInfo.RoleEnabled = &roleEnabled
					} else {
						// Not in the role list; mark as false
						roleEnabled := false
						toolInfo.RoleEnabled = &roleEnabled
					}
				}
			}

			// If there is a keyword, apply search filtering
			if searchTermLower != "" {
				nameLower := strings.ToLower(toolInfo.Name)
				descLower := strings.ToLower(toolInfo.Description)
				if !strings.Contains(nameLower, searchTermLower) && !strings.Contains(descLower, searchTermLower) {
					continue // no match; skip
				}
			}

			// Status filter
			if filterEnabled != nil && toolInfo.Enabled != *filterEnabled {
				continue
			}

			allTools = append(allTools, toolInfo)
		}
	}

	// Get external MCP tools (may use cache; does not hold the config lock)
	if includeExternal && externalMCPMgr != nil {
		if refreshExternal {
			externalMCPMgr.InvalidateAllToolCaches()
		}
		ctx := context.Background()
		externalTools := h.getExternalMCPToolsWithManager(ctx, externalMCPMgr, pickDesc)

		// Apply search filter and role configuration
		for _, toolInfo := range externalTools {
			// Search filter
			if searchTermLower != "" {
				nameLower := strings.ToLower(toolInfo.Name)
				descLower := strings.ToLower(toolInfo.Description)
				if !strings.Contains(nameLower, searchTermLower) && !strings.Contains(descLower, searchTermLower) {
					continue // no match; skip
				}
			}

			// Mark tool status according to role configuration
			if roleName != "" {
				if roleUsesAllTools {
					// The role uses all tools; mark enabled tools as role_enabled=true
					roleEnabled := toolInfo.Enabled
					toolInfo.RoleEnabled = &roleEnabled
				} else {
					// The role has a configured tool list; check whether the tool is in the list
					// external tools use the "mcpName::toolName" format as the key
					externalToolKey := fmt.Sprintf("%s::%s", toolInfo.ExternalMCP, toolInfo.Name)
					if roleToolsSet[externalToolKey] {
						roleEnabled := toolInfo.Enabled // the tool must be in the role list and itself enabled
						toolInfo.RoleEnabled = &roleEnabled
					} else {
						// Not in the role list; mark as false
						roleEnabled := false
						toolInfo.RoleEnabled = &roleEnabled
					}
				}
			}

			// Status filter
			if filterEnabled != nil && toolInfo.Enabled != *filterEnabled {
				continue
			}

			allTools = append(allTools, toolInfo)
		}
	}

	// If the role has a configured tool list, filter tools (keep only the tools in the list, but keep other tools and mark them disabled)
	// Note: tools are not filtered out directly here; all tools are kept and their status is marked via the role_enabled field
	// This way the frontend can show all tools and mark which ones are available in the current role

	if externalMCPFilter != "" {
		filtered := make([]ToolConfigInfo, 0)
		for _, tool := range allTools {
			if tool.IsExternal && tool.ExternalMCP == externalMCPFilter {
				filtered = append(filtered, tool)
			}
		}
		allTools = filtered
	}

	// Sort by name before paginating, so that the order in the configuration file does not make the first pages of "all" and "enabled only" look identical
	sort.SliceStable(allTools, func(i, j int) bool {
		key := func(t ToolConfigInfo) string {
			if t.IsExternal && t.ExternalMCP != "" {
				return strings.ToLower(t.ExternalMCP + "::" + t.Name)
			}
			return strings.ToLower(t.Name)
		}
		return key(allTools[i]) < key(allTools[j])
	})

	total := len(allTools)
	// Count enabled tools (enabled tools in the role)
	totalEnabled := 0
	for _, tool := range allTools {
		if tool.RoleEnabled != nil && *tool.RoleEnabled {
			totalEnabled++
		} else if tool.RoleEnabled == nil && tool.Enabled {
			// If no role is specified, count all enabled tools
			totalEnabled++
		}
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	// Compute pagination range
	offset := (page - 1) * pageSize
	end := offset + pageSize
	if end > total {
		end = total
	}

	var tools []ToolConfigInfo
	if offset < total {
		tools = allTools[offset:end]
	} else {
		tools = []ToolConfigInfo{}
	}

	c.JSON(http.StatusOK, GetToolsResponse{
		Tools:        tools,
		Total:        total,
		TotalEnabled: totalEnabled,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
	})
}

// UpdateConfigRequest is the update configuration request
type UpdateConfigRequest struct {
	AI         *config.AIConfig            `json:"ai,omitempty"`
	OpenAI     *config.OpenAIConfig        `json:"openai,omitempty"`
	Vision     *config.VisionConfig        `json:"vision,omitempty"`
	FOFA       *config.FofaConfig          `json:"fofa,omitempty"`
	ZoomEye    *config.SpaceSearchConfig   `json:"zoomeye,omitempty"`
	Quake      *config.SpaceSearchConfig   `json:"quake,omitempty"`
	Shodan     *config.SpaceSearchConfig   `json:"shodan,omitempty"`
	MCP        *config.MCPConfig           `json:"mcp,omitempty"`
	Tools      []ToolEnableStatus          `json:"tools,omitempty"`
	Agent      *AgentConfigUpdate          `json:"agent,omitempty"`
	Hitl       *config.HitlConfig          `json:"hitl,omitempty"`
	Knowledge  *config.KnowledgeConfig     `json:"knowledge,omitempty"`
	Robots     *config.RobotsConfig        `json:"robots,omitempty"`
	MultiAgent *config.MultiAgentAPIUpdate `json:"multi_agent,omitempty"`
	C2         *config.C2APIUpdate         `json:"c2,omitempty"`
	Storage    *config.StorageConfig       `json:"storage,omitempty"`
}

// AgentConfigUpdate is used for the agent section of PATCH /api/config: only fields present in the JSON (non-nil pointers) overwrite the in-memory configuration.
// Avoids the legacy "replace the whole *AgentConfig" behavior, where unsent integer fields were deserialized as 0 and overwrote values (e.g. tool_timeout_minutes becoming 0).
type AgentConfigUpdate struct {
	MaxIterations                      *int    `json:"max_iterations,omitempty"`
	ToolTimeoutMinutes                 *int    `json:"tool_timeout_minutes,omitempty"`
	ToolWaitTimeoutSeconds             *int    `json:"tool_wait_timeout_seconds,omitempty"`
	ExternalMCPMaxConcurrentPerServer  *int    `json:"external_mcp_max_concurrent_per_server,omitempty"`
	ExternalMCPMaxConcurrentTotal      *int    `json:"external_mcp_max_concurrent_total,omitempty"`
	ExternalMCPCircuitFailureThreshold *int    `json:"external_mcp_circuit_failure_threshold,omitempty"`
	ExternalMCPCircuitCooldownSeconds  *int    `json:"external_mcp_circuit_cooldown_seconds,omitempty"`
	SystemPromptPath                   *string `json:"system_prompt_path,omitempty"`
}

func applyAgentConfigUpdate(dst *config.AgentConfig, src *AgentConfigUpdate) {
	if dst == nil || src == nil {
		return
	}
	if src.MaxIterations != nil {
		dst.MaxIterations = *src.MaxIterations
	}
	if src.ToolTimeoutMinutes != nil {
		dst.ToolTimeoutMinutes = *src.ToolTimeoutMinutes
	}
	if src.ToolWaitTimeoutSeconds != nil {
		dst.ToolWaitTimeoutSeconds = *src.ToolWaitTimeoutSeconds
	}
	if src.ExternalMCPMaxConcurrentPerServer != nil {
		dst.ExternalMCPMaxConcurrentPerServer = *src.ExternalMCPMaxConcurrentPerServer
	}
	if src.ExternalMCPMaxConcurrentTotal != nil {
		dst.ExternalMCPMaxConcurrentTotal = *src.ExternalMCPMaxConcurrentTotal
	}
	if src.ExternalMCPCircuitFailureThreshold != nil {
		dst.ExternalMCPCircuitFailureThreshold = *src.ExternalMCPCircuitFailureThreshold
	}
	if src.ExternalMCPCircuitCooldownSeconds != nil {
		dst.ExternalMCPCircuitCooldownSeconds = *src.ExternalMCPCircuitCooldownSeconds
	}
	if src.SystemPromptPath != nil {
		dst.SystemPromptPath = *src.SystemPromptPath
	}
}

// ToolEnableStatus is the tool enable status
type ToolEnableStatus struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	IsExternal  bool   `json:"is_external,omitempty"`  // whether this is an external MCP tool
	ExternalMCP string `json:"external_mcp,omitempty"` // external MCP name (if an external tool)
}

// UpdateConfig updates the configuration
func (h *ConfigHandler) UpdateConfig(c *gin.Context) {
	var req UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request parameters: " + err.Error()})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if err := restoreConfigRequestSecrets(&req, h.config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update OpenAI configuration
	if req.AI != nil {
		prevRoutes := h.config.AI.ModelRoutes
		h.config.AI = *req.AI
		if h.config.AI.ModelRoutes == nil {
			h.config.AI.ModelRoutes = prevRoutes // model_routes is read-only here
		}
		h.config.ApplyDefaultAIChannel()
		h.logger.Info("updated AI channel configuration",
			zap.String("default_channel", h.config.AI.DefaultChannel),
			zap.Int("channels", len(h.config.AI.Channels)),
		)
	}
	if req.OpenAI != nil {
		h.config.OpenAI = *req.OpenAI
		h.config.AI.EnsureDefaultFromOpenAI(h.config.OpenAI)
		if def := config.NormalizeAIChannelID(h.config.AI.DefaultChannel); def != "" {
			h.config.AI.Channels[def] = config.AIChannelFromOpenAI(def, "Default", h.config.OpenAI)
		}
		h.logger.Info("updated OpenAI configuration",
			zap.String("base_url", h.config.OpenAI.BaseURL),
			zap.String("model", h.config.OpenAI.Model),
		)
	}

	if req.Vision != nil {
		h.config.Vision = *req.Vision
		h.logger.Info("updated Vision configuration",
			zap.Bool("enabled", h.config.Vision.Enabled),
			zap.String("model", h.config.Vision.Model),
		)
	}

	// Update FOFA configuration
	if req.FOFA != nil {
		h.config.FOFA = *req.FOFA
		h.logger.Info("updated FOFA configuration", zap.String("base_url", h.config.FOFA.BaseURL))
	}
	if req.ZoomEye != nil {
		h.config.ZoomEye = *req.ZoomEye
		h.logger.Info("updated ZoomEye configuration", zap.String("base_url", h.config.ZoomEye.BaseURL))
	}
	if req.Quake != nil {
		h.config.Quake = *req.Quake
		h.logger.Info("updated Quake configuration", zap.String("base_url", h.config.Quake.BaseURL))
	}
	if req.Shodan != nil {
		h.config.Shodan = *req.Shodan
		h.logger.Info("updated Shodan configuration", zap.String("base_url", h.config.Shodan.BaseURL))
	}

	// Update MCP configuration
	if req.MCP != nil {
		h.config.MCP = *req.MCP
		h.logger.Info("updated MCP configuration",
			zap.Bool("enabled", h.config.MCP.Enabled),
			zap.String("host", h.config.MCP.Host),
			zap.Int("port", h.config.MCP.Port),
		)
	}

	// Update Agent configuration (merged by field, to avoid partial JSON writing absent fields as 0)
	if req.Agent != nil {
		applyAgentConfigUpdate(&h.config.Agent, req.Agent)
		h.logger.Info("updated Agent configuration",
			zap.Int("max_iterations", h.config.Agent.MaxIterations),
			zap.Int("tool_timeout_minutes", h.config.Agent.ToolTimeoutMinutes),
			zap.Int("tool_wait_timeout_seconds", h.config.Agent.ToolWaitTimeoutSeconds),
			zap.Int("external_mcp_max_concurrent_per_server", h.config.Agent.ExternalMCPMaxConcurrentPerServer),
			zap.Int("external_mcp_max_concurrent_total", h.config.Agent.ExternalMCPMaxConcurrentTotal),
			zap.Int("external_mcp_circuit_failure_threshold", h.config.Agent.ExternalMCPCircuitFailureThreshold),
			zap.Int("external_mcp_circuit_cooldown_seconds", h.config.Agent.ExternalMCPCircuitCooldownSeconds),
		)
		if h.agent != nil && req.Agent.MaxIterations != nil {
			h.agent.UpdateMaxIterations(h.config.Agent.MaxIterations)
		}
		if h.executor != nil {
			h.executor.SetToolOutputMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
			h.executor.SetToolOutputSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
		}
		if h.mcpServer != nil {
			h.mcpServer.ConfigureHTTPToolCallTimeoutFromAgentMinutes(h.config.Agent.ToolTimeoutMinutes)
			h.mcpServer.ConfigureToolWaitTimeoutSeconds(h.config.Agent.ToolWaitTimeoutSeconds)
			h.mcpServer.ConfigureToolResultMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
			h.mcpServer.ConfigureToolResultSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
		}
		if h.externalMCPMgr != nil {
			h.externalMCPMgr.ConfigureToolWaitTimeoutSeconds(h.config.Agent.ToolWaitTimeoutSeconds)
			h.externalMCPMgr.ConfigureToolResultMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
			h.externalMCPMgr.ConfigureToolResultSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
			h.externalMCPMgr.ConfigureResilience(mcp.ExternalMCPResilienceConfig{
				MaxConcurrentPerServer:  h.config.Agent.ExternalMCPMaxConcurrentPerServer,
				MaxConcurrentTotal:      h.config.Agent.ExternalMCPMaxConcurrentTotal,
				CircuitFailureThreshold: h.config.Agent.ExternalMCPCircuitFailureThreshold,
				CircuitCooldown:         time.Duration(h.config.Agent.ExternalMCPCircuitCooldownSeconds) * time.Second,
			})
		}
	}

	if req.Hitl != nil {
		h.config.Hitl.AuditBackend = req.Hitl.EffectiveAuditBackend()
		h.config.Hitl.AuditModel = req.Hitl.AuditModel
		h.config.Hitl.ToolWhitelist = mergeHitlToolWhitelistSlice(nil, req.Hitl.ToolWhitelist)
		if strings.TrimSpace(req.Hitl.DefaultMode) != "" {
			h.config.Hitl.DefaultMode = req.Hitl.EffectiveDefaultMode()
		}
		h.config.Hitl.DefaultReviewer = req.Hitl.EffectiveDefaultReviewer()
		if req.Hitl.DefaultTimeoutSeconds != nil {
			v := req.Hitl.EffectiveDefaultTimeoutSeconds()
			h.config.Hitl.DefaultTimeoutSeconds = &v
		}
		h.config.Hitl.AuditAgentPrompt = strings.TrimSpace(req.Hitl.AuditAgentPrompt)
		h.config.Hitl.AuditAgentPromptReviewEdit = strings.TrimSpace(req.Hitl.AuditAgentPromptReviewEdit)
		if req.Hitl.RetentionDays != nil {
			v := *req.Hitl.RetentionDays
			if v < 0 {
				v = 0
			}
			h.config.Hitl.RetentionDays = &v
		}
		h.logger.Info("updated HITL configuration",
			zap.String("audit_backend", h.config.Hitl.AuditBackend),
			zap.String("default_reviewer", h.config.Hitl.DefaultReviewer),
			zap.Int("tool_whitelist", len(h.config.Hitl.ToolWhitelist)),
		)
	}

	if req.Storage != nil {
		st := &h.config.Storage
		if req.Storage.AutoClean != nil {
			v := *req.Storage.AutoClean
			st.AutoClean = &v
		}
		if req.Storage.IntervalMinutes != nil {
			v := *req.Storage.IntervalMinutes
			if v < 5 {
				v = 5
			}
			st.IntervalMinutes = &v
		}
		if req.Storage.OrphanGraceDays != nil {
			v := *req.Storage.OrphanGraceDays
			if v < 0 {
				v = 0
			}
			st.OrphanGraceDays = &v
		}
		if req.Storage.ActiveGraceHours != nil {
			v := *req.Storage.ActiveGraceHours
			if v < 1 {
				v = 1
			}
			st.ActiveGraceHours = &v
		}
		if req.Storage.Categories != nil {
			if st.Categories == nil {
				st.Categories = make(map[string]config.StorageCategoryConfig, len(req.Storage.Categories))
			}
			// Only accept category keys in the registry; unregistered keys are ignored to avoid being written into config.yaml.
			for _, key := range config.StorageCategoryOrder {
				patch, ok := req.Storage.Categories[key]
				if !ok {
					continue
				}
				cur := st.Categories[key]
				if patch.Enabled != nil {
					v := *patch.Enabled
					cur.Enabled = &v
				}
				if patch.RetentionDays != nil {
					v := *patch.RetentionDays
					if v < 0 {
						v = 0
					}
					cur.RetentionDays = &v
				}
				st.Categories[key] = cur
			}
		}
		h.logger.Info("updated workspace cleanup configuration",
			zap.Bool("auto_clean", st.AutoCleanEffective()),
			zap.Int("interval_minutes", st.IntervalMinutesEffective()),
			zap.Int("orphan_grace_days", st.OrphanGraceDaysEffective()),
			zap.Int("active_grace_hours", st.ActiveGraceHoursEffective()),
		)
	}

	// Update Knowledge configuration
	if req.Knowledge != nil {
		// Save the old embedding model configuration (used to detect changes)
		if h.config.Knowledge.Enabled {
			h.lastEmbeddingConfig = &config.EmbeddingConfig{
				Provider: h.config.Knowledge.Embedding.Provider,
				Model:    h.config.Knowledge.Embedding.Model,
				BaseURL:  h.config.Knowledge.Embedding.BaseURL,
				APIKey:   h.config.Knowledge.Embedding.APIKey,
			}
		}
		h.config.Knowledge = *req.Knowledge
		h.logger.Info("updated Knowledge configuration",
			zap.Bool("enabled", h.config.Knowledge.Enabled),
			zap.String("base_path", h.config.Knowledge.BasePath),
			zap.String("embedding_model", h.config.Knowledge.Embedding.Model),
			zap.Int("retrieval_top_k", h.config.Knowledge.Retrieval.TopK),
			zap.Float64("similarity_threshold", h.config.Knowledge.Retrieval.SimilarityThreshold),
		)
	}

	// Update robot configuration
	if req.Robots != nil {
		if err := config.ValidateWecomConfig(req.Robots.Wecom); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := config.ValidateRobotsAuthorization(*req.Robots); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := h.validateRobotServiceAccounts(*req.Robots); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		h.config.Robots = *req.Robots
		h.logger.Info("updated robot configuration",
			zap.Bool("wechat_enabled", h.config.Robots.Wechat.Enabled),
			zap.Bool("wecom_enabled", h.config.Robots.Wecom.Enabled),
			zap.Bool("dingtalk_enabled", h.config.Robots.Dingtalk.Enabled),
			zap.Bool("lark_enabled", h.config.Robots.Lark.Enabled),
			zap.Bool("telegram_enabled", h.config.Robots.Telegram.Enabled),
			zap.Bool("slack_enabled", h.config.Robots.Slack.Enabled),
			zap.Bool("discord_enabled", h.config.Robots.Discord.Enabled),
			zap.Bool("qq_enabled", h.config.Robots.QQ.Enabled),
		)
	}

	if req.C2 != nil {
		v := req.C2.Enabled
		h.config.C2.Enabled = &v
		h.logger.Info("updated C2 configuration", zap.Bool("enabled", v))
	}

	// Multi-agent scalars (sub_agents etc. are still maintained in config.yaml)
	if req.MultiAgent != nil {
		h.config.MultiAgent.Enabled = req.MultiAgent.Enabled
		h.config.MultiAgent.BatchUseMultiAgent = req.MultiAgent.BatchUseMultiAgent
		if mode := strings.TrimSpace(req.MultiAgent.RobotDefaultAgentMode); mode != "" {
			h.config.MultiAgent.RobotDefaultAgentMode = mode
		} else {
			h.config.MultiAgent.RobotDefaultAgentMode = "eino_single"
		}
		if req.MultiAgent.PlanExecuteLoopMaxIterations != nil {
			h.config.MultiAgent.PlanExecuteLoopMaxIterations = *req.MultiAgent.PlanExecuteLoopMaxIterations
		}
		if req.MultiAgent.SummarizationUserIntentLedgerMaxRunes != nil {
			v := *req.MultiAgent.SummarizationUserIntentLedgerMaxRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerMaxRunes = v
		}
		if req.MultiAgent.SummarizationUserIntentLedgerEntryMaxRunes != nil {
			v := *req.MultiAgent.SummarizationUserIntentLedgerEntryMaxRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerEntryMaxRunes = v
		}
		if req.MultiAgent.LatestUserMessageMaxRunes != nil {
			v := *req.MultiAgent.LatestUserMessageMaxRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.LatestUserMessageMaxRunes = v
		}
		if req.MultiAgent.LatestUserMessageHeadRunes != nil {
			v := *req.MultiAgent.LatestUserMessageHeadRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.LatestUserMessageHeadRunes = v
		}
		if req.MultiAgent.LatestUserMessageTailRunes != nil {
			v := *req.MultiAgent.LatestUserMessageTailRunes
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.LatestUserMessageTailRunes = v
		}
		if req.MultiAgent.ModelRetryMaxRetries != nil {
			v := *req.MultiAgent.ModelRetryMaxRetries
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.ModelRetryMaxRetries = v
		}
		if req.MultiAgent.ModelRetryMaxBackoffSec != nil {
			v := *req.MultiAgent.ModelRetryMaxBackoffSec
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.ModelRetryMaxBackoffSec = v
		}
		if req.MultiAgent.ModelFailoverChannels != nil {
			h.config.MultiAgent.EinoMiddleware.ModelFailoverChannels = dedupeTrimmedStringList(*req.MultiAgent.ModelFailoverChannels)
		}
		if req.MultiAgent.ModelFailoverMaxRetries != nil {
			v := *req.MultiAgent.ModelFailoverMaxRetries
			if v < 0 {
				v = 0
			}
			h.config.MultiAgent.EinoMiddleware.ModelFailoverMaxRetries = v
		}
		if req.MultiAgent.ToolSearchAlwaysVisibleTools != nil {
			h.config.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools = dedupeToolNameList(*req.MultiAgent.ToolSearchAlwaysVisibleTools)
		}
		h.logger.Info("updated multi-agent configuration",
			zap.Bool("enabled", h.config.MultiAgent.Enabled),
			zap.String("robot_default_agent_mode", config.NormalizeRobotAgentMode(h.config.MultiAgent)),
			zap.Bool("batch_use_multi_agent", h.config.MultiAgent.BatchUseMultiAgent),
			zap.Int("plan_execute_loop_max_iterations", h.config.MultiAgent.PlanExecuteLoopMaxIterations),
			zap.Int("summarization_user_intent_ledger_max_runes", h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerMaxRunesEffective()),
			zap.Int("summarization_user_intent_ledger_entry_max_runes", h.config.MultiAgent.EinoMiddleware.SummarizationUserIntentLedgerEntryMaxRunesEffective()),
			zap.Int("latest_user_message_max_runes", h.config.MultiAgent.EinoMiddleware.LatestUserMessageMaxRunesEffective()),
			zap.Int("latest_user_message_head_runes", h.config.MultiAgent.EinoMiddleware.LatestUserMessageHeadRunesEffective()),
			zap.Int("latest_user_message_tail_runes", h.config.MultiAgent.EinoMiddleware.LatestUserMessageTailRunesEffective()),
			zap.Int("model_retry_max_retries", h.config.MultiAgent.EinoMiddleware.ModelRetryMaxRetries),
			zap.Int("model_retry_max_backoff_sec", h.config.MultiAgent.EinoMiddleware.ModelRetryMaxBackoffSec),
			zap.Int("model_failover_channels", len(h.config.MultiAgent.EinoMiddleware.ModelFailoverChannels)),
			zap.Int("model_failover_max_retries", h.config.MultiAgent.EinoMiddleware.ModelFailoverMaxRetries),
			zap.Int("tool_search_always_visible_tools", len(h.config.MultiAgent.EinoMiddleware.ToolSearchAlwaysVisibleTools)),
		)
	}

	// Update tool enable status
	if req.Tools != nil {
		// Separate internal tools from external tools
		internalToolMap := make(map[string]bool)
		// External tool status: MCP name -> tool name -> enabled state
		externalMCPToolMap := make(map[string]map[string]bool)

		for _, toolStatus := range req.Tools {
			if toolStatus.IsExternal && toolStatus.ExternalMCP != "" {
				// External tools: save the independent state of each tool
				mcpName := toolStatus.ExternalMCP
				if externalMCPToolMap[mcpName] == nil {
					externalMCPToolMap[mcpName] = make(map[string]bool)
				}
				externalMCPToolMap[mcpName][toolStatus.Name] = toolStatus.Enabled
			} else {
				// Internal tools
				internalToolMap[toolStatus.Name] = toolStatus.Enabled
			}
		}

		// Update internal tool status
		for i := range h.config.Security.Tools {
			if enabled, ok := internalToolMap[h.config.Security.Tools[i].Name]; ok {
				h.config.Security.Tools[i].Enabled = enabled
				h.logger.Info("updated tool enable status",
					zap.String("tool", h.config.Security.Tools[i].Name),
					zap.Bool("enabled", enabled),
				)
			}
		}

		// Update external MCP tool status
		if h.externalMCPMgr != nil {
			for mcpName, toolStates := range externalMCPToolMap {
				// Update the tool enable status in the configuration
				if h.config.ExternalMCP.Servers == nil {
					h.config.ExternalMCP.Servers = make(map[string]config.ExternalMCPServerConfig)
				}
				cfg, exists := h.config.ExternalMCP.Servers[mcpName]
				if !exists {
					h.logger.Warn("external MCP configuration does not exist", zap.String("mcp", mcpName))
					continue
				}

				// Initialize the ToolEnabled map
				if cfg.ToolEnabled == nil {
					cfg.ToolEnabled = make(map[string]bool)
				}

				// Update the enable status of each tool
				for toolName, enabled := range toolStates {
					cfg.ToolEnabled[toolName] = enabled
					h.logger.Info("updated external tool enable status",
						zap.String("mcp", mcpName),
						zap.String("tool", toolName),
						zap.Bool("enabled", enabled),
					)
				}

				// Check whether any tool is enabled; if so, enable the MCP
				hasEnabledTool := false
				for _, enabled := range cfg.ToolEnabled {
					if enabled {
						hasEnabledTool = true
						break
					}
				}

				// If the MCP was not enabled before but now has enabled tools, enable the MCP
				// If the MCP was already enabled, keep it enabled (allows some tools to be disabled)
				if !cfg.ExternalMCPEnable && hasEnabledTool {
					cfg.ExternalMCPEnable = true
					h.logger.Info("automatically enabled external MCP (because tools are enabled)", zap.String("mcp", mcpName))
				}

				h.config.ExternalMCP.Servers[mcpName] = cfg
			}

			// Sync the configuration in externalMCPMgr so that GetConfigs() returns the latest configuration
			// Update once outside the loop to avoid repeated calls
			h.externalMCPMgr.LoadConfigs(&h.config.ExternalMCP)

			// Handle MCP connection status (asynchronous start, to avoid blocking)
			for mcpName := range externalMCPToolMap {
				cfg := h.config.ExternalMCP.Servers[mcpName]
				// If the MCP needs to be enabled, ensure the client has started
				if cfg.ExternalMCPEnable {
					// Start the external MCP (if not started) - runs asynchronously to avoid blocking
					client, exists := h.externalMCPMgr.GetClient(mcpName)
					if !exists || !client.IsConnected() {
						go func(name string) {
							if err := h.externalMCPMgr.StartClient(name); err != nil {
								h.logger.Warn("failed to start external MCP",
									zap.String("mcp", name),
									zap.Error(err),
								)
							} else {
								h.logger.Info("starting external MCP",
									zap.String("mcp", name),
								)
							}
						}(mcpName)
					}
				}
			}
		}
	}

	h.config.NormalizeAIProviderProfiles()

	// Save configuration to file
	if err := h.saveConfig(); err != nil {
		h.logger.Error("failed to save configuration", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save configuration: " + err.Error()})
		return
	}

	if h.audit != nil {
		h.audit.RecordOK(c, "config", "update", "updated in-memory configuration", "config", "", nil)
	}
	c.JSON(http.StatusOK, gin.H{"message": "configuration updated"})
}

// TestOpenAIRequest is the request to test an OpenAI connection
type TestOpenAIRequest struct {
	CredentialScope string            `json:"credential_scope,omitempty"`
	ChannelID       string            `json:"channel_id,omitempty"`
	Provider        string            `json:"provider"`
	BaseURL         string            `json:"base_url"`
	APIKey          string            `json:"api_key"`
	Model           string            `json:"model"`
	Headers         map[string]string `json:"headers,omitempty"`
}

// TestOpenAI tests whether the OpenAI API connection is available
func (h *ConfigHandler) TestOpenAI(c *gin.Context) {
	var req TestOpenAIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request parameters: " + err.Error()})
		return
	}

	resolvedKey, resolveErr := h.resolveProbeSecret(req.APIKey, req.ChannelID, req.BaseURL, req.CredentialScope)
	if resolveErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": resolveErr.Error()})
		return
	}
	req.APIKey = resolvedKey
	resolvedHeaders, headerErr := h.resolveProbeHeaders(req)
	if headerErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": headerErr.Error()})
		return
	}
	if strings.TrimSpace(req.APIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key cannot be empty"})
		return
	}
	if strings.TrimSpace(req.Model) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "model cannot be empty"})
		return
	}

	baseURL := strings.TrimSuffix(strings.TrimSpace(req.BaseURL), "/")
	if baseURL == "" {
		if strings.EqualFold(strings.TrimSpace(req.Provider), "claude") {
			baseURL = "https://api.anthropic.com"
		} else {
			baseURL = "https://api.openai.com/v1"
		}
	}

	// Construct a minimal chat completion request
	payload := map[string]interface{}{
		"model": req.Model,
		"messages": []map[string]string{
			{"role": "user", "content": "Hi"},
		},
		"max_completion_tokens": 5,
	}

	// OpenAI-compatible channels use the internal client; Claude channels use Eino agenticclaude directly below.
	tmpCfg := &config.OpenAIConfig{
		Provider: req.Provider,
		BaseURL:  baseURL,
		APIKey:   strings.TrimSpace(req.APIKey),
		Model:    req.Model,
		Headers:  resolvedHeaders,
	}
	client := openai.NewClient(tmpCfg, nil, h.logger)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	// The connection test has no real conversation context, so an explicit probe value fills %session_id%,
	// so channels with session placeholders can also send their custom headers for real during testing.
	ctx = openai.WithSessionID(ctx, "connect-test")

	start := time.Now()
	if llm.IsClaudeProvider(req.Provider) {
		nativeModel, err := llm.NewClaudeAgenticModel(ctx, *tmpCfg, nil, 5, nil)
		if err == nil {
			_, err = nativeModel.Generate(ctx, []*schema.AgenticMessage{
				schema.UserAgenticMessage("Hi"),
			})
		}
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"error":   "connection failed: " + err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"model":      tmpCfg.Model,
			"latency_ms": time.Since(start).Milliseconds(),
		})
		return
	}

	var chatResp struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	err := client.ChatCompletion(ctx, payload, &chatResp)
	latency := time.Since(start)

	if err != nil {
		if apiErr, ok := err.(*openai.APIError); ok {
			c.JSON(http.StatusOK, gin.H{
				"success":     false,
				"error":       fmt.Sprintf("API returned an error (HTTP %d): %s", apiErr.StatusCode, apiErr.Body),
				"status_code": apiErr.StatusCode,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "connection failed: " + err.Error(),
		})
		return
	}

	// Strict validation: must include choices and an assistant reply
	if len(chatResp.Choices) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "API response is missing the choices field; check whether the Base URL path is correct",
		})
		return
	}
	if chatResp.ID == "" && chatResp.Model == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "unexpected API response format; check whether the Base URL is correct",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"model":      chatResp.Model,
		"latency_ms": latency.Milliseconds(),
	})
}

// TestTypeSafeRequest tests the TypeSafe / Jev connection.
type TestTypeSafeRequest struct {
	CredentialScope string `json:"credential_scope,omitempty"`
	ChannelID       string `json:"channel_id,omitempty"`
	BaseURL         string `json:"base_url"`
	APIKey          string `json:"api_key"`
	Model           string `json:"model"`
}

// TestTypeSafe verifies whether TypeSafe System One is available using a minimal Noul request.
func (h *ConfigHandler) TestTypeSafe(c *gin.Context) {
	var req TestTypeSafeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request parameters: " + err.Error()})
		return
	}
	resolvedKey, resolveErr := h.resolveProbeSecret(req.APIKey, req.ChannelID, req.BaseURL, req.CredentialScope)
	if resolveErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": resolveErr.Error()})
		return
	}
	req.APIKey = resolvedKey
	if strings.TrimSpace(req.APIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TypeSafe API Key cannot be empty"})
		return
	}

	client := typesafe.NewClient(req.BaseURL, req.APIKey, req.Model, nil)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	start := time.Now()
	result, err := client.SystemOne(ctx, "connectivity ping", map[string]typesafe.Question{
		"ok": typesafe.Noul("Is this a connectivity test ping?", "Yes, this is only a ping.", "No."),
	})
	if err != nil {
		if apiErr, ok := err.(*typesafe.APIError); ok {
			c.JSON(http.StatusOK, gin.H{
				"success":     false,
				"error":       fmt.Sprintf("API returned an error (HTTP %d): %s", apiErr.StatusCode, apiErr.Body),
				"status_code": apiErr.StatusCode,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "connection failed: " + err.Error(),
		})
		return
	}
	model := strings.TrimSpace(req.Model)
	if result != nil && strings.TrimSpace(result.Model) != "" {
		model = result.Model
	}
	if model == "" {
		model = config.TypeSafeDefaultModel
	}
	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"model":      model,
		"latency_ms": time.Since(start).Milliseconds(),
	})
}

// ListModelsRequest is the request to list models (OpenAI-compatible GET /models).
type ListModelsRequest struct {
	CredentialScope string `json:"credential_scope,omitempty"`
	ChannelID       string `json:"channel_id,omitempty"`
	Provider        string `json:"provider"`
	BaseURL         string `json:"base_url"`
	APIKey          string `json:"api_key"`
}

// ListModels proxies a call to the upstream GET /models and returns the list of available model IDs.
func (h *ConfigHandler) ListModels(c *gin.Context) {
	var req ListModelsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request parameters: " + err.Error()})
		return
	}

	resolvedKey, resolveErr := h.resolveProbeSecret(req.APIKey, req.ChannelID, req.BaseURL, req.CredentialScope)
	if resolveErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": resolveErr.Error()})
		return
	}
	req.APIKey = resolvedKey
	provider := strings.TrimSpace(req.Provider)
	if provider == "" {
		provider = "openai"
	}
	if strings.EqualFold(provider, "claude") {
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": false,
			"error":     "Claude (Anthropic Messages API) does not support automatically fetching the model list; please enter it manually",
		})
		return
	}

	if strings.TrimSpace(req.APIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key cannot be empty"})
		return
	}

	baseURL := strings.TrimSuffix(strings.TrimSpace(req.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	tmpCfg := &config.OpenAIConfig{
		Provider: provider,
		BaseURL:  baseURL,
		APIKey:   strings.TrimSpace(req.APIKey),
	}
	client := openai.NewClient(tmpCfg, nil, h.logger)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	models, err := client.ListModels(ctx)
	if err != nil {
		if apiErr, ok := err.(*openai.APIError); ok {
			c.JSON(http.StatusOK, gin.H{
				"success":   false,
				"supported": true,
				"error":     fmt.Sprintf("API returned an error (HTTP %d): %s", apiErr.StatusCode, apiErr.Body),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": true,
			"error":     err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"supported": true,
		"models":    models,
		"count":     len(models),
	})
}

// TestVisionRequest tests the Vision model connection; when vision.api_key/base_url are empty, the openai section may be passed as a fallback.
type TestVisionRequest struct {
	ChannelID string              `json:"channel_id,omitempty"`
	Vision    config.VisionConfig `json:"vision"`
	OpenAI    config.OpenAIConfig `json:"openai,omitempty"`
}

// TestVision tests the vision model API connection (minimal chat completion).
func (h *ConfigHandler) TestVision(c *gin.Context) {
	var req TestVisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request parameters: " + err.Error()})
		return
	}
	mainKey, mainErr := h.resolveProbeSecret(req.OpenAI.APIKey, req.ChannelID, req.OpenAI.BaseURL, "openai")
	if mainErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": mainErr.Error()})
		return
	}
	req.OpenAI.APIKey = mainKey
	h.mu.RLock()
	restoreErr := restoreConfigRequestSecrets(&req, h.config)
	h.mu.RUnlock()
	if restoreErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": restoreErr.Error()})
		return
	}
	oa := req.Vision.OpenAICfgEffective(req.OpenAI)
	if strings.TrimSpace(oa.APIKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key cannot be empty (you may fill in vision.api_key or openai.api_key)"})
		return
	}
	if strings.TrimSpace(oa.Model) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "vision model cannot be empty"})
		return
	}

	baseURL := strings.TrimSuffix(strings.TrimSpace(oa.BaseURL), "/")
	if baseURL == "" {
		if strings.EqualFold(strings.TrimSpace(oa.Provider), "claude") {
			baseURL = "https://api.anthropic.com"
		} else {
			baseURL = "https://api.openai.com/v1"
		}
	}

	payload := map[string]interface{}{
		"model": oa.Model,
		"messages": []map[string]string{
			{"role": "user", "content": "Hi"},
		},
		"max_completion_tokens": 5,
	}

	tmpCfg := &config.OpenAIConfig{
		Provider: oa.Provider,
		BaseURL:  baseURL,
		APIKey:   strings.TrimSpace(oa.APIKey),
		Model:    oa.Model,
	}
	client := openai.NewClient(tmpCfg, nil, h.logger)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	start := time.Now()
	var chatResp struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	err := client.ChatCompletion(ctx, payload, &chatResp)
	latency := time.Since(start)

	if err != nil {
		if apiErr, ok := err.(*openai.APIError); ok {
			c.JSON(http.StatusOK, gin.H{
				"success":     false,
				"error":       fmt.Sprintf("API returned an error (HTTP %d): %s", apiErr.StatusCode, apiErr.Body),
				"status_code": apiErr.StatusCode,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "connection failed: " + err.Error(),
		})
		return
	}
	if len(chatResp.Choices) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "API response is missing the choices field; check the Base URL and the vision model name",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"model":      chatResp.Model,
		"latency_ms": latency.Milliseconds(),
	})
}

// ApplyConfig applies the configuration (reloads and restarts related services)
func (h *ConfigHandler) ApplyConfig(c *gin.Context) {
	// First check whether the knowledge base needs dynamic initialization (performed outside the lock to avoid blocking other requests)
	var needInitKnowledge bool
	var knowledgeInitializer KnowledgeInitializer

	h.mu.RLock()
	needInitKnowledge = h.config.Knowledge.Enabled && h.knowledgeToolRegistrar == nil && h.knowledgeInitializer != nil
	if needInitKnowledge {
		knowledgeInitializer = h.knowledgeInitializer
	}
	h.mu.RUnlock()

	// If dynamic initialization of the knowledge base is needed, run it outside the lock (this is a time-consuming operation)
	if needInitKnowledge {
		h.logger.Info("knowledge base changed from disabled to enabled; starting dynamic initialization of knowledge base components")
		if _, err := knowledgeInitializer(); err != nil {
			h.logger.Error("dynamic knowledge base initialization failed", zap.Error(err))
			if h.audit != nil {
				h.audit.RecordFail(c, "config", "apply", "Failed to apply config: initialize knowledge base", map[string]interface{}{"error": err.Error()})
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize knowledge base: " + err.Error()})
			return
		}
		h.logger.Debug("dynamic knowledge base initialization complete; tools registered")
	}

	// Check whether the embedding model configuration has changed (must run outside the lock to avoid blocking)
	var needReinitKnowledge bool
	var reinitKnowledgeInitializer KnowledgeInitializer
	h.mu.RLock()
	if h.config.Knowledge.Enabled && h.knowledgeInitializer != nil && h.lastEmbeddingConfig != nil {
		// Check whether the embedding model configuration has changed
		currentEmbedding := h.config.Knowledge.Embedding
		if currentEmbedding.Provider != h.lastEmbeddingConfig.Provider ||
			currentEmbedding.Model != h.lastEmbeddingConfig.Model ||
			currentEmbedding.BaseURL != h.lastEmbeddingConfig.BaseURL ||
			currentEmbedding.APIKey != h.lastEmbeddingConfig.APIKey {
			needReinitKnowledge = true
			reinitKnowledgeInitializer = h.knowledgeInitializer
			h.logger.Info("embedding model configuration changed; knowledge base components need to be re-initialized",
				zap.String("old_model", h.lastEmbeddingConfig.Model),
				zap.String("new_model", currentEmbedding.Model),
				zap.String("old_base_url", h.lastEmbeddingConfig.BaseURL),
				zap.String("new_base_url", currentEmbedding.BaseURL),
			)
		}
	}
	h.mu.RUnlock()

	// If the knowledge base needs re-initialization (embedding model configuration changed), run it outside the lock
	if needReinitKnowledge {
		h.logger.Info("starting re-initialization of knowledge base components (embedding model configuration changed)")
		if _, err := reinitKnowledgeInitializer(); err != nil {
			h.logger.Error("failed to re-initialize knowledge base", zap.Error(err))
			if h.audit != nil {
				h.audit.RecordFail(c, "config", "apply", "Failed to apply config: reinitialize knowledge base", map[string]interface{}{"error": err.Error()})
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to re-initialize knowledge base: " + err.Error()})
			return
		}
		h.logger.Info("knowledge base components re-initialized")
	}

	// C2: start/stop according to configuration before ClearTools (MCP tools are then registered by c2ToolRegistrar)
	h.mu.RLock()
	c2Rt := h.c2Runtime
	h.mu.RUnlock()
	if c2Rt != nil {
		if err := c2Rt.ReconcileC2AfterConfigApply(); err != nil {
			h.logger.Error("failed to apply C2 configuration", zap.Error(err))
			if h.audit != nil {
				h.audit.RecordFail(c, "config", "apply", "Failed to apply config: C2", map[string]interface{}{"error": err.Error()})
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "C2 failed to start: " + err.Error()})
			return
		}
	}

	// Now acquire the write lock and perform the quick operations
	h.mu.Lock()
	defer h.mu.Unlock()

	// If the knowledge base was re-initialized, update the embedding model configuration record
	if needReinitKnowledge && h.config.Knowledge.Enabled {
		h.lastEmbeddingConfig = &config.EmbeddingConfig{
			Provider: h.config.Knowledge.Embedding.Provider,
			Model:    h.config.Knowledge.Embedding.Model,
			BaseURL:  h.config.Knowledge.Embedding.BaseURL,
			APIKey:   h.config.Knowledge.Embedding.APIKey,
		}
		h.logger.Info("updated embedding model configuration record")
	}

	// Reload tool configuration from the tools directory (no restart needed after adding/modifying/deleting yaml)
	if err := config.ReloadSecurityToolsFromDir(h.config, h.configPath); err != nil {
		h.logger.Error("failed to reload tool configuration", zap.Error(err))
		if h.audit != nil {
			h.audit.RecordFail(c, "config", "apply", "apply configuration failed: reload tools", map[string]interface{}{"error": err.Error()})
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reload tool configuration: " + err.Error()})
		return
	}
	h.logger.Debug("reloaded tool configuration from tools directory", zap.Int("tools_count", len(h.config.Security.Tools)))

	// Re-register tools (according to the new enable status)
	h.logger.Debug("re-registering tools")

	// Clear tools in the MCP server
	h.mcpServer.ClearTools()

	// Re-register security tools
	h.executor.SetToolOutputMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
	h.executor.SetToolOutputSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
	h.executor.RegisterTools(h.mcpServer)
	mcp.RegisterExecutionControlTools(h.mcpServer, h.externalMCPMgr)

	// Re-register the vulnerability recording tool (built-in, must be registered)
	if h.vulnerabilityToolRegistrar != nil {
		h.logger.Info("re-registering vulnerability recording tool")
		if err := h.vulnerabilityToolRegistrar(); err != nil {
			h.logger.Error("failed to re-register vulnerability recording tool", zap.Error(err))
		} else {
			h.logger.Info("vulnerability recording tool re-registered")
		}
	}

	// Re-register WebShell tools (built-in, must be registered)
	if h.webshellToolRegistrar != nil {
		h.logger.Info("re-registering WebShell tools")
		if err := h.webshellToolRegistrar(); err != nil {
			h.logger.Error("failed to re-register WebShell tools", zap.Error(err))
		} else {
			h.logger.Info("WebShell tools re-registered")
		}
	}

	// Re-register Skills tools (built-in, must be registered)
	if h.skillsToolRegistrar != nil {
		h.logger.Info("re-registering Skills tools")
		if err := h.skillsToolRegistrar(); err != nil {
			h.logger.Error("failed to re-register Skills tools", zap.Error(err))
		} else {
			h.logger.Info("Skills tools re-registered")
		}
	}

	// Re-register batch task MCP tools
	if h.batchTaskToolRegistrar != nil {
		h.logger.Info("re-registering batch task MCP tools")
		if err := h.batchTaskToolRegistrar(); err != nil {
			h.logger.Error("failed to re-register batch task MCP tools", zap.Error(err))
		} else {
			h.logger.Info("batch task MCP tools re-registered")
		}
	}

	// Re-register C2 MCP tools (only when C2 has started)
	if h.c2ToolRegistrar != nil {
		h.logger.Info("re-registering C2 MCP tools")
		if err := h.c2ToolRegistrar(); err != nil {
			h.logger.Error("failed to re-register C2 MCP tools", zap.Error(err))
		} else {
			h.logger.Info("C2 MCP tools processed")
		}
	}

	// If the knowledge base is enabled, re-register knowledge base tools
	if h.config.Knowledge.Enabled && h.knowledgeToolRegistrar != nil {
		h.logger.Info("re-registering knowledge base tools")
		if err := h.knowledgeToolRegistrar(); err != nil {
			h.logger.Error("failed to re-register knowledge base tools", zap.Error(err))
		} else {
			h.logger.Info("knowledge base tools re-registered")
		}
	}

	// Update the Agent OpenAI configuration
	if h.agent != nil {
		h.agent.UpdateConfig(&h.config.OpenAI)
		h.agent.UpdateMaxIterations(h.config.Agent.MaxIterations)
		h.agent.UpdateToolDescriptionMode(h.config.Security.ToolDescriptionMode)
		h.logger.Info("Agent configuration updated")
	}
	if h.mcpServer != nil {
		h.mcpServer.ConfigureHTTPToolCallTimeoutFromAgentMinutes(h.config.Agent.ToolTimeoutMinutes)
		h.mcpServer.ConfigureToolWaitTimeoutSeconds(h.config.Agent.ToolWaitTimeoutSeconds)
		h.mcpServer.ConfigureToolResultMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
		h.mcpServer.ConfigureToolResultSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
	}
	if h.executor != nil {
		h.executor.SetToolOutputMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
		h.executor.SetToolOutputSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
	}
	if h.externalMCPMgr != nil {
		h.externalMCPMgr.ConfigureToolWaitTimeoutSeconds(h.config.Agent.ToolWaitTimeoutSeconds)
		h.externalMCPMgr.ConfigureToolResultMaxBytes(h.config.MultiAgent.EinoMiddleware.ReductionMaxLengthForTruncEffective())
		h.externalMCPMgr.ConfigureToolResultSpillRoot(h.config.MultiAgent.EinoMiddleware.ReductionRootDir)
		h.externalMCPMgr.ConfigureResilience(mcp.ExternalMCPResilienceConfig{
			MaxConcurrentPerServer:  h.config.Agent.ExternalMCPMaxConcurrentPerServer,
			MaxConcurrentTotal:      h.config.Agent.ExternalMCPMaxConcurrentTotal,
			CircuitFailureThreshold: h.config.Agent.ExternalMCPCircuitFailureThreshold,
			CircuitCooldown:         time.Duration(h.config.Agent.ExternalMCPCircuitCooldownSeconds) * time.Second,
		})
	}

	// Update the AttackChainHandler OpenAI configuration
	if h.attackChainHandler != nil {
		h.attackChainHandler.UpdateConfig(&h.config.OpenAI)
		h.logger.Info("AttackChainHandler configuration updated")
	}

	// Update retriever configuration (if the knowledge base is enabled)
	if h.config.Knowledge.Enabled && h.retrieverUpdater != nil {
		retrievalConfig := knowledge.RetrievalConfigFromYAML(h.config.Knowledge.Retrieval)
		h.retrieverUpdater.UpdateConfig(retrievalConfig)
		h.logger.Info("retriever configuration updated",
			zap.Int("top_k", retrievalConfig.TopK),
			zap.Float64("similarity_threshold", retrievalConfig.SimilarityThreshold),
		)
	}

	// Update embedding model configuration record (if the knowledge base is enabled)
	if h.config.Knowledge.Enabled {
		h.lastEmbeddingConfig = &config.EmbeddingConfig{
			Provider: h.config.Knowledge.Embedding.Provider,
			Model:    h.config.Knowledge.Embedding.Model,
			BaseURL:  h.config.Knowledge.Embedding.BaseURL,
			APIKey:   h.config.Knowledge.Embedding.APIKey,
		}
	}

	// Restart DingTalk/Feishu long connections so robot configuration changed in the frontend takes effect immediately (no service restart needed)
	if h.robotRestarter != nil {
		h.robotRestarter.RestartRobotConnections()
		h.logger.Info("robot connection restart triggered (DingTalk/Feishu)")
	}

	h.logger.Info("configuration applied",
		zap.Int("tools_count", len(h.config.Security.Tools)),
	)

	if h.audit != nil {
		h.audit.Record(c, audit.Entry{
			Category: "config",
			Action:   "apply",
			Result:   "success",
			Message:  "configuration applied",
			Detail: map[string]interface{}{
				"tools_count":       len(h.config.Security.Tools),
				"knowledge_enabled": h.config.Knowledge.Enabled,
				"c2_enabled":        h.config.C2.EnabledEffective(),
			},
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "configuration applied",
		"tools_count": len(h.config.Security.Tools),
	})
}

// SetUpdateSource records the update source for one-click updates (single repository address; empty = back to the official repository).
// Uses the same write path as other settings: back up the old file, modify only the update section of the YAML document, and persist atomically.
func (h *ConfigHandler) SetUpdateSource(repo string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	previous := h.config.Update
	h.config.Update = config.UpdateConfig{Repo: strings.TrimSpace(repo)}
	if err := h.saveConfig(); err != nil {
		h.config.Update = previous
		return err
	}
	return nil
}

// UpdateSource reads the current configured update source address (under a read lock; the update handler reads it on every request, so it takes effect immediately after saving).
func (h *ConfigHandler) UpdateSource() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.config.Update.Repo
}

// saveConfig saves the configuration to file
func (h *ConfigHandler) saveConfig() error {
	configFileMu.Lock()
	defer configFileMu.Unlock()
	h.config.NormalizeAIProviderProfiles()

	// Read the existing configuration file and create a backup
	data, err := os.ReadFile(h.configPath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %w", err)
	}

	if err := os.WriteFile(h.configPath+".backup", data, 0644); err != nil {
		h.logger.Warn("failed to create configuration backup", zap.Error(err))
	}

	root, err := loadYAMLDocument(h.configPath)
	if err != nil {
		return fmt.Errorf("failed to parse configuration file: %w", err)
	}

	updateAgentConfig(root, h.config.Agent)
	updateMCPConfig(root, h.config.MCP)
	updateAIConfig(root, h.config.AI)
	removeKeyFromMap(root.Content[0], "openai")
	updateVisionConfig(root, h.config.Vision)
	updateUpdateSourceConfig(root, h.config.Update)
	updateFOFAConfig(root, h.config.FOFA)
	updateSpaceSearchConfig(root, "zoomeye", h.config.ZoomEye)
	updateSpaceSearchConfig(root, "quake", h.config.Quake)
	updateSpaceSearchConfig(root, "shodan", h.config.Shodan)
	updateKnowledgeConfig(root, h.config.Knowledge)
	updateC2Config(root, h.config.C2)
	updateRobotsConfig(root, h.config.Robots)
	updateHitlConfig(root, h.config.Hitl)
	updateStorageConfig(root, h.config.Storage)
	updateMultiAgentConfig(root, h.config.MultiAgent)
	// Update external MCP configuration (uses the functions in external_mcp.go; directly callable within the same package)
	updateExternalMCPConfig(root, h.config.ExternalMCP)

	if err := writeYAMLDocument(h.configPath, root); err != nil {
		return fmt.Errorf("failed to save configuration file: %w", err)
	}

	// Update the enabled status in tool configuration files
	if h.config.Security.ToolsDir != "" {
		configDir := filepath.Dir(h.configPath)
		toolsDir := h.config.Security.ToolsDir
		if !filepath.IsAbs(toolsDir) {
			toolsDir = filepath.Join(configDir, toolsDir)
		}

		for _, tool := range h.config.Security.Tools {
			toolFile := filepath.Join(toolsDir, tool.Name+".yaml")
			// Check whether the file exists
			if _, err := os.Stat(toolFile); os.IsNotExist(err) {
				// Try the .yml extension
				toolFile = filepath.Join(toolsDir, tool.Name+".yml")
				if _, err := os.Stat(toolFile); os.IsNotExist(err) {
					h.logger.Warn("tool configuration file does not exist", zap.String("tool", tool.Name))
					continue
				}
			}

			toolDoc, err := loadYAMLDocument(toolFile)
			if err != nil {
				h.logger.Warn("failed to parse tool configuration", zap.String("tool", tool.Name), zap.Error(err))
				continue
			}

			setBoolInMap(toolDoc.Content[0], "enabled", tool.Enabled)

			if err := writeYAMLDocument(toolFile, toolDoc); err != nil {
				h.logger.Warn("failed to save tool configuration file", zap.String("tool", tool.Name), zap.Error(err))
				continue
			}

			h.logger.Info("updated tool configuration", zap.String("tool", tool.Name), zap.Bool("enabled", tool.Enabled))
		}
	}

	h.logger.Info("configuration saved", zap.String("path", h.configPath))
	return nil
}

func loadYAMLDocument(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(bytes.TrimSpace(data)) == 0 {
		return newEmptyYAMLDocument(), nil
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return newEmptyYAMLDocument(), nil
	}

	if doc.Content[0].Kind != yaml.MappingNode {
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Content = []*yaml.Node{root}
	}

	return &doc, nil
}

func newEmptyYAMLDocument() *yaml.Node {
	root := &yaml.Node{
		Kind:    yaml.DocumentNode,
		Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}},
	}
	return root
}

func writeYAMLDocument(path string, doc *yaml.Node) error {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}

func updateAgentConfig(doc *yaml.Node, agent config.AgentConfig) {
	root := doc.Content[0]
	agentNode := ensureMap(root, "agent")
	setIntInMap(agentNode, "max_iterations", agent.MaxIterations)
	setIntInMap(agentNode, "tool_timeout_minutes", agent.ToolTimeoutMinutes)
	setIntInMap(agentNode, "tool_wait_timeout_seconds", agent.ToolWaitTimeoutSeconds)
	setIntInMap(agentNode, "external_mcp_max_concurrent_per_server", agent.ExternalMCPMaxConcurrentPerServer)
	setIntInMap(agentNode, "external_mcp_max_concurrent_total", agent.ExternalMCPMaxConcurrentTotal)
	setIntInMap(agentNode, "external_mcp_circuit_failure_threshold", agent.ExternalMCPCircuitFailureThreshold)
	setIntInMap(agentNode, "external_mcp_circuit_cooldown_seconds", agent.ExternalMCPCircuitCooldownSeconds)
	setStringInMap(agentNode, "system_prompt_path", agent.SystemPromptPath)
}

func updateMCPConfig(doc *yaml.Node, cfg config.MCPConfig) {
	root := doc.Content[0]
	mcpNode := ensureMap(root, "mcp")
	setBoolInMap(mcpNode, "enabled", cfg.Enabled)
	setStringInMap(mcpNode, "host", cfg.Host)
	setIntInMap(mcpNode, "port", cfg.Port)
}

// updateUpdateSourceConfig writes the update source for one-click updates (the single repo field of the update section).
// When left empty, the whole section is deleted instead of leaving an empty update: block; "not configured" should simply mean the section is absent from the file,
// and it is handled as the official repository at runtime.
func updateUpdateSourceConfig(doc *yaml.Node, cfg config.UpdateConfig) {
	root := doc.Content[0]
	repo := strings.TrimSpace(cfg.Repo)
	if repo == "" {
		removeKeyFromMap(root, "update")
		return
	}
	node := ensureMap(root, "update")
	setStringInMap(node, "repo", repo)
}

func updateVisionConfig(doc *yaml.Node, cfg config.VisionConfig) {
	root := doc.Content[0]
	visionNode := ensureMap(root, "vision")
	setBoolInMap(visionNode, "enabled", cfg.Enabled)
	if strings.TrimSpace(cfg.APIKey) != "" {
		setStringInMap(visionNode, "api_key", cfg.APIKey)
	} else {
		setStringInMap(visionNode, "api_key", "")
	}
	if strings.TrimSpace(cfg.BaseURL) != "" {
		setStringInMap(visionNode, "base_url", cfg.BaseURL)
	} else {
		setStringInMap(visionNode, "base_url", "")
	}
	setStringInMap(visionNode, "model", cfg.Model)
	if strings.TrimSpace(cfg.Provider) != "" {
		setStringInMap(visionNode, "provider", cfg.Provider)
	}
	if cfg.TimeoutSeconds > 0 {
		setIntInMap(visionNode, "timeout_seconds", cfg.TimeoutSeconds)
	}
	if cfg.MaxImageBytes > 0 {
		setIntInMap(visionNode, "max_image_bytes", int(cfg.MaxImageBytes))
	}
	if cfg.MaxDimension > 0 {
		setIntInMap(visionNode, "max_dimension", cfg.MaxDimension)
	}
	if cfg.JPEGQuality > 0 {
		setIntInMap(visionNode, "jpeg_quality", cfg.JPEGQuality)
	}
	if cfg.MaxPayloadBytes > 0 {
		setIntInMap(visionNode, "max_payload_bytes", int(cfg.MaxPayloadBytes))
	}
	setIntInMap(visionNode, "skip_preprocess_below_bytes", int(cfg.SkipPreprocessBelowBytes))
	if strings.TrimSpace(cfg.Detail) != "" {
		setStringInMap(visionNode, "detail", cfg.Detail)
	}
}

func updateOpenAIConfig(doc *yaml.Node, cfg config.OpenAIConfig) {
	root := doc.Content[0]
	openaiNode := ensureMap(root, "openai")
	if cfg.Provider != "" {
		setStringInMap(openaiNode, "provider", cfg.Provider)
	}
	setStringInMap(openaiNode, "api_key", cfg.APIKey)
	setStringInMap(openaiNode, "base_url", cfg.BaseURL)
	setStringInMap(openaiNode, "model", cfg.Model)
	setStringMapInMap(openaiNode, "headers", cfg.Headers)
	if cfg.MaxTotalTokens > 0 {
		setIntInMap(openaiNode, "max_total_tokens", cfg.MaxTotalTokens)
	}
	rn := ensureMap(openaiNode, "reasoning")
	if strings.TrimSpace(cfg.Reasoning.Mode) != "" {
		setStringInMap(rn, "mode", cfg.Reasoning.Mode)
	}
	if strings.TrimSpace(cfg.Reasoning.Effort) != "" {
		setStringInMap(rn, "effort", cfg.Reasoning.Effort)
	}
	if cfg.Reasoning.AllowClientReasoning != nil {
		setBoolInMap(rn, "allow_client_reasoning", *cfg.Reasoning.AllowClientReasoning)
	}
	if strings.TrimSpace(cfg.Reasoning.Profile) != "" {
		setStringInMap(rn, "profile", cfg.Reasoning.Profile)
	}
}

func updateAIConfig(doc *yaml.Node, cfg config.AIConfig) {
	root := doc.Content[0]
	aiNode := ensureMap(root, "ai")
	if strings.TrimSpace(cfg.DefaultChannel) != "" {
		setStringInMap(aiNode, "default_channel", config.NormalizeAIChannelID(cfg.DefaultChannel))
	}
	channelsNode := ensureMap(aiNode, "channels")
	channelsNode.Content = nil
	normalized := make(map[string]config.AIChannelConfig, len(cfg.Channels))
	ids := make([]string, 0, len(cfg.Channels))
	for id, ch := range cfg.Channels {
		nid := config.NormalizeAIChannelID(id)
		if nid == "" {
			continue
		}
		if _, exists := normalized[nid]; !exists {
			ids = append(ids, nid)
		}
		normalized[nid] = ch
	}
	sort.Strings(ids)
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		ch := normalized[id]
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: id}
		channelNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		channelsNode.Content = append(channelsNode.Content, keyNode, channelNode)
		setStringInMap(channelNode, "name", ch.Name)
		if strings.TrimSpace(ch.Provider) != "" {
			setStringInMap(channelNode, "provider", ch.Provider)
		}
		setStringInMap(channelNode, "api_key", ch.APIKey)
		setStringInMap(channelNode, "base_url", ch.BaseURL)
		setStringInMap(channelNode, "model", ch.Model)
		setStringMapInMap(channelNode, "headers", ch.Headers)
		if ch.MaxTotalTokens > 0 {
			setIntInMap(channelNode, "max_total_tokens", ch.MaxTotalTokens)
		}
		if ch.MaxCompletionTokens > 0 {
			setIntInMap(channelNode, "max_completion_tokens", ch.MaxCompletionTokens)
		}
		rn := ensureMap(channelNode, "reasoning")
		if strings.TrimSpace(ch.Reasoning.Mode) != "" {
			setStringInMap(rn, "mode", ch.Reasoning.Mode)
		}
		if strings.TrimSpace(ch.Reasoning.Effort) != "" {
			setStringInMap(rn, "effort", ch.Reasoning.Effort)
		}
		if ch.Reasoning.AllowClientReasoning != nil {
			setBoolInMap(rn, "allow_client_reasoning", *ch.Reasoning.AllowClientReasoning)
		}
		if strings.TrimSpace(ch.Reasoning.Profile) != "" {
			setStringInMap(rn, "profile", ch.Reasoning.Profile)
		}
		if len(rn.Content) == 0 {
			removeKeyFromMap(channelNode, "reasoning")
		}
	}
}

func updateFOFAConfig(doc *yaml.Node, cfg config.FofaConfig) {
	root := doc.Content[0]
	fofaNode := ensureMap(root, "fofa")
	setStringInMap(fofaNode, "base_url", cfg.BaseURL)
	removeKeyFromMap(fofaNode, "email")
	setStringInMap(fofaNode, "api_key", cfg.APIKey)
}

func updateSpaceSearchConfig(doc *yaml.Node, key string, cfg config.SpaceSearchConfig) {
	root := doc.Content[0]
	node := ensureMap(root, key)
	setStringInMap(node, "base_url", cfg.BaseURL)
	setStringInMap(node, "api_key", cfg.APIKey)
}

func updateKnowledgeConfig(doc *yaml.Node, cfg config.KnowledgeConfig) {
	root := doc.Content[0]
	knowledgeNode := ensureMap(root, "knowledge")
	setBoolInMap(knowledgeNode, "enabled", cfg.Enabled)
	setStringInMap(knowledgeNode, "base_path", cfg.BasePath)

	// Update embedding configuration
	embeddingNode := ensureMap(knowledgeNode, "embedding")
	setStringInMap(embeddingNode, "provider", cfg.Embedding.Provider)
	setStringInMap(embeddingNode, "model", cfg.Embedding.Model)
	if cfg.Embedding.BaseURL != "" {
		setStringInMap(embeddingNode, "base_url", cfg.Embedding.BaseURL)
	}
	if cfg.Embedding.APIKey != "" {
		setStringInMap(embeddingNode, "api_key", cfg.Embedding.APIKey)
	}

	// Update retrieval configuration
	retrievalNode := ensureMap(knowledgeNode, "retrieval")
	setIntInMap(retrievalNode, "top_k", cfg.Retrieval.TopK)
	setFloatInMap(retrievalNode, "similarity_threshold", cfg.Retrieval.SimilarityThreshold)
	setStringInMap(retrievalNode, "sub_index_filter", cfg.Retrieval.SubIndexFilter)
	mqNode := ensureMap(retrievalNode, "multi_query")
	setIntInMap(mqNode, "max_queries", cfg.Retrieval.MultiQuery.MaxQueries)
	rerankNode := ensureMap(retrievalNode, "rerank")
	setStringInMap(rerankNode, "provider", cfg.Retrieval.Rerank.Provider)
	setStringInMap(rerankNode, "model", cfg.Retrieval.Rerank.Model)
	setStringInMap(rerankNode, "base_url", cfg.Retrieval.Rerank.BaseURL)
	setStringInMap(rerankNode, "api_key", cfg.Retrieval.Rerank.APIKey)
	postNode := ensureMap(retrievalNode, "post_retrieve")
	setIntInMap(postNode, "prefetch_top_k", cfg.Retrieval.PostRetrieve.PrefetchTopK)
	setIntInMap(postNode, "max_context_chars", cfg.Retrieval.PostRetrieve.MaxContextChars)
	setIntInMap(postNode, "max_context_tokens", cfg.Retrieval.PostRetrieve.MaxContextTokens)

	// Update index configuration
	indexingNode := ensureMap(knowledgeNode, "indexing")
	setStringInMap(indexingNode, "chunk_strategy", cfg.Indexing.ChunkStrategy)
	setIntInMap(indexingNode, "request_timeout_seconds", cfg.Indexing.RequestTimeoutSeconds)
	setIntInMap(indexingNode, "chunk_size", cfg.Indexing.ChunkSize)
	setIntInMap(indexingNode, "chunk_overlap", cfg.Indexing.ChunkOverlap)
	setIntInMap(indexingNode, "max_chunks_per_item", cfg.Indexing.MaxChunksPerItem)
	setBoolInMap(indexingNode, "prefer_source_file", cfg.Indexing.PreferSourceFile)
	setIntInMap(indexingNode, "batch_size", cfg.Indexing.BatchSize)
	setStringSliceInMap(indexingNode, "sub_indexes", cfg.Indexing.SubIndexes)
	setIntInMap(indexingNode, "max_rpm", cfg.Indexing.MaxRPM)
	setIntInMap(indexingNode, "rate_limit_delay_ms", cfg.Indexing.RateLimitDelayMs)
	setIntInMap(indexingNode, "max_retries", cfg.Indexing.MaxRetries)
	setIntInMap(indexingNode, "retry_delay_ms", cfg.Indexing.RetryDelayMs)
}

func updateC2Config(doc *yaml.Node, cfg config.C2Config) {
	root := doc.Content[0]
	c2Node := ensureMap(root, "c2")
	setBoolInMap(c2Node, "enabled", cfg.EnabledEffective())
}

func mergeHitlToolWhitelistSlice(existing, add []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(existing)+len(add))
	for _, list := range [][]string{existing, add} {
		for _, t := range list {
			n := strings.ToLower(strings.TrimSpace(t))
			if n == "" {
				continue
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

// SetHitlToolWhitelist writes the entire global approval-exempt tool allowlist to config.yaml (replace, not merge).
func (h *ConfigHandler) SetHitlToolWhitelist(tools []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Hitl.ToolWhitelist = mergeHitlToolWhitelistSlice(nil, tools)
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL global tool allowlist written to configuration file",
		zap.Int("count", len(h.config.Hitl.ToolWhitelist)),
	)
	return nil
}

// MergeHitlToolWhitelistIntoConfig merges the approval-exempt tool names submitted from the session sidebar into the in-memory configuration and writes config.yaml (same deduplication rules as the global allowlist: lowercase keys, keeping the original case of the first occurrence).
func (h *ConfigHandler) MergeHitlToolWhitelistIntoConfig(add []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	merged := mergeHitlToolWhitelistSlice(h.config.Hitl.ToolWhitelist, add)
	h.config.Hitl.ToolWhitelist = merged
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL global tool allowlist merged and written to configuration file",
		zap.Int("count", len(merged)),
	)
	return nil
}

func updateHitlConfig(doc *yaml.Node, cfg config.HitlConfig) {
	root := doc.Content[0]
	hitlNode := ensureMap(root, "hitl")
	setStringInMap(hitlNode, "audit_backend", cfg.EffectiveAuditBackend())
	auditModelNode := ensureMap(hitlNode, "audit_model")
	setStringInMap(auditModelNode, "provider", cfg.AuditModel.Provider)
	setStringInMap(auditModelNode, "base_url", cfg.AuditModel.BaseURL)
	setStringInMap(auditModelNode, "api_key", cfg.AuditModel.APIKey)
	setStringInMap(auditModelNode, "model", cfg.AuditModel.Model)
	setStringMapInMap(auditModelNode, "headers", cfg.AuditModel.Headers)
	setStringInMap(ensureMap(auditModelNode, "reasoning"), "profile", cfg.AuditModel.Reasoning.Profile)
	// flow style [a, b, c] on a single line; saves lines compared to block sequences when there are many tools
	setFlowStringSliceInMap(hitlNode, "tool_whitelist", cfg.ToolWhitelist)
	setStringInMap(hitlNode, "default_mode", cfg.EffectiveDefaultMode())
	setStringInMap(hitlNode, "default_reviewer", cfg.EffectiveDefaultReviewer())
	setIntInMap(hitlNode, "default_timeout_seconds", cfg.EffectiveDefaultTimeoutSeconds())
	setIntInMap(hitlNode, "retention_days", cfg.RetentionDaysEffective())
	setStringInMap(hitlNode, "audit_agent_prompt", cfg.AuditAgentPrompt)
	setStringInMap(hitlNode, "audit_agent_prompt_review_edit", cfg.AuditAgentPromptReviewEdit)
}

// updateStorageConfig writes the workspace cleanup policy back to config.yaml, preserving the rest of the file contents and comments.
func updateStorageConfig(doc *yaml.Node, cfg config.StorageConfig) {
	root := doc.Content[0]
	storageNode := ensureMap(root, "storage")
	setBoolInMap(storageNode, "auto_clean", cfg.AutoCleanEffective())
	setIntInMap(storageNode, "interval_minutes", cfg.IntervalMinutesEffective())
	setIntInMap(storageNode, "orphan_grace_days", cfg.OrphanGraceDaysEffective())
	setIntInMap(storageNode, "active_grace_hours", cfg.ActiveGraceHoursEffective())

	// Output in a fixed order, to avoid reordering the whole file on every save because map iteration order differs.
	categoriesNode := ensureMap(storageNode, "categories")
	for _, key := range config.StorageCategoryOrder {
		categoryNode := ensureMap(categoriesNode, key)
		setBoolInMap(categoryNode, "enabled", cfg.CategoryEnabled(key))
		setIntInMap(categoryNode, "retention_days", cfg.CategoryRetentionDays(key))
	}
}

// UpdateHitlDefaultConfig updates the global default HITL configuration and writes it to config.yaml.
func (h *ConfigHandler) UpdateHitlDefaultConfig(mode, reviewer string, timeoutSeconds int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Hitl.DefaultMode = config.HitlConfig{DefaultMode: mode}.EffectiveDefaultMode()
	h.config.Hitl.DefaultReviewer = config.HitlConfig{DefaultReviewer: reviewer}.EffectiveDefaultReviewer()
	if timeoutSeconds < 0 {
		timeoutSeconds = 0
	}
	h.config.Hitl.DefaultTimeoutSeconds = &timeoutSeconds
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL global default configuration written to configuration file",
		zap.String("default_mode", h.config.Hitl.DefaultMode),
		zap.String("default_reviewer", h.config.Hitl.DefaultReviewer),
		zap.Int("default_timeout_seconds", timeoutSeconds),
	)
	return nil
}

// UpdateHitlDefaultReviewer updates the global default reviewer and writes it to config.yaml.
func (h *ConfigHandler) UpdateHitlDefaultReviewer(reviewer string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Hitl.DefaultReviewer = config.HitlConfig{DefaultReviewer: reviewer}.EffectiveDefaultReviewer()
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL global default reviewer written to configuration file", zap.String("default_reviewer", h.config.Hitl.DefaultReviewer))
	return nil
}

// UpdateHitlAuditAgentStrategy updates the two audit Agent prompts (approval and review-edit) and writes them to config.yaml.
func (h *ConfigHandler) UpdateHitlAuditAgentStrategy(approvalPrompt, reviewEditPrompt string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Hitl.AuditAgentPrompt = strings.TrimSpace(approvalPrompt)
	h.config.Hitl.AuditAgentPromptReviewEdit = strings.TrimSpace(reviewEditPrompt)
	if err := h.saveConfig(); err != nil {
		return err
	}
	h.logger.Info("HITL audit Agent prompt written to configuration file")
	return nil
}

func updateRobotsConfig(doc *yaml.Node, cfg config.RobotsConfig) {
	root := doc.Content[0]
	robotsNode := ensureMap(root, "robots")

	if cfg.Session.StrictUserIdentity != nil {
		sessionNode := ensureMap(robotsNode, "session")
		setBoolInMap(sessionNode, "strict_user_identity", *cfg.Session.StrictUserIdentity)
	}

	wechatNode := ensureMap(robotsNode, "wechat")
	setBoolInMap(wechatNode, "enabled", cfg.Wechat.Enabled)
	setStringInMap(wechatNode, "bot_token", cfg.Wechat.BotToken)
	setStringInMap(wechatNode, "ilink_bot_id", cfg.Wechat.ILinkBotID)
	setStringInMap(wechatNode, "ilink_user_id", cfg.Wechat.ILinkUserID)
	setStringInMap(wechatNode, "base_url", cfg.Wechat.BaseURL)
	setStringInMap(wechatNode, "bot_type", cfg.Wechat.BotType)
	setStringInMap(wechatNode, "bot_agent", cfg.Wechat.BotAgent)

	wecomNode := ensureMap(robotsNode, "wecom")
	setBoolInMap(wecomNode, "enabled", cfg.Wecom.Enabled)
	setStringInMap(wecomNode, "token", cfg.Wecom.Token)
	setStringInMap(wecomNode, "encoding_aes_key", cfg.Wecom.EncodingAESKey)
	setStringInMap(wecomNode, "corp_id", cfg.Wecom.CorpID)
	setStringInMap(wecomNode, "secret", cfg.Wecom.Secret)
	setIntInMap(wecomNode, "agent_id", int(cfg.Wecom.AgentID))

	dingtalkNode := ensureMap(robotsNode, "dingtalk")
	setBoolInMap(dingtalkNode, "enabled", cfg.Dingtalk.Enabled)
	setStringInMap(dingtalkNode, "client_id", cfg.Dingtalk.ClientID)
	setStringInMap(dingtalkNode, "client_secret", cfg.Dingtalk.ClientSecret)
	setBoolInMap(dingtalkNode, "allow_conversation_id_fallback", cfg.Dingtalk.AllowConversationIDFallback)

	larkNode := ensureMap(robotsNode, "lark")
	setBoolInMap(larkNode, "enabled", cfg.Lark.Enabled)
	setStringInMap(larkNode, "app_id", cfg.Lark.AppID)
	setStringInMap(larkNode, "app_secret", cfg.Lark.AppSecret)
	setStringInMap(larkNode, "verify_token", cfg.Lark.VerifyToken)
	setBoolInMap(larkNode, "allow_chat_id_fallback", cfg.Lark.AllowChatIDFallback)

	telegramNode := ensureMap(robotsNode, "telegram")
	setBoolInMap(telegramNode, "enabled", cfg.Telegram.Enabled)
	setStringInMap(telegramNode, "bot_token", cfg.Telegram.BotToken)
	setStringInMap(telegramNode, "bot_username", cfg.Telegram.BotUsername)
	setBoolInMap(telegramNode, "allow_group_messages", cfg.Telegram.AllowGroupMessages)

	slackNode := ensureMap(robotsNode, "slack")
	setBoolInMap(slackNode, "enabled", cfg.Slack.Enabled)
	setStringInMap(slackNode, "bot_token", cfg.Slack.BotToken)
	setStringInMap(slackNode, "app_token", cfg.Slack.AppToken)

	discordNode := ensureMap(robotsNode, "discord")
	setBoolInMap(discordNode, "enabled", cfg.Discord.Enabled)
	setStringInMap(discordNode, "bot_token", cfg.Discord.BotToken)
	setBoolInMap(discordNode, "allow_guild_messages", cfg.Discord.AllowGuildMessages)

	qqNode := ensureMap(robotsNode, "qq")
	setBoolInMap(qqNode, "enabled", cfg.QQ.Enabled)
	setStringInMap(qqNode, "app_id", cfg.QQ.AppID)
	setStringInMap(qqNode, "client_secret", cfg.QQ.ClientSecret)
	setBoolInMap(qqNode, "sandbox", cfg.QQ.Sandbox)
}

func updateMultiAgentConfig(doc *yaml.Node, cfg config.MultiAgentConfig) {
	root := doc.Content[0]
	maNode := ensureMap(root, "multi_agent")
	setBoolInMap(maNode, "enabled", cfg.Enabled)
	setStringInMap(maNode, "robot_default_agent_mode", config.NormalizeRobotAgentMode(cfg))
	setBoolInMap(maNode, "batch_use_multi_agent", cfg.BatchUseMultiAgent)
	setIntInMap(maNode, "plan_execute_loop_max_iterations", cfg.PlanExecuteLoopMaxIterations)
	mwNode := ensureMap(maNode, "eino_middleware")
	setIntInMap(mwNode, "summarization_user_intent_ledger_max_runes", cfg.EinoMiddleware.SummarizationUserIntentLedgerMaxRunesEffective())
	setIntInMap(mwNode, "summarization_user_intent_ledger_entry_max_runes", cfg.EinoMiddleware.SummarizationUserIntentLedgerEntryMaxRunesEffective())
	setIntInMap(mwNode, "latest_user_message_max_runes", cfg.EinoMiddleware.LatestUserMessageMaxRunesEffective())
	setIntInMap(mwNode, "latest_user_message_head_runes", cfg.EinoMiddleware.LatestUserMessageHeadRunesEffective())
	setIntInMap(mwNode, "latest_user_message_tail_runes", cfg.EinoMiddleware.LatestUserMessageTailRunesEffective())
	setIntInMap(mwNode, "model_retry_max_retries", cfg.EinoMiddleware.ModelRetryMaxRetries)
	setIntInMap(mwNode, "model_retry_max_backoff_sec", cfg.EinoMiddleware.ModelRetryMaxBackoffSec)
	setFlowStringSliceInMap(mwNode, "model_failover_channels", dedupeTrimmedStringList(cfg.EinoMiddleware.ModelFailoverChannels))
	setIntInMap(mwNode, "model_failover_max_retries", cfg.EinoMiddleware.ModelFailoverMaxRetries)
	setFlowStringSliceInMap(mwNode, "tool_search_always_visible_tools", dedupeToolNameList(cfg.EinoMiddleware.ToolSearchAlwaysVisibleTools))
}

func dedupeToolNameList(in []string) []string {
	return dedupeTrimmedStringList(in)
}

func dedupeTrimmedStringList(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, name := range in {
		n := strings.TrimSpace(name)
		if n == "" {
			continue
		}
		key := strings.ToLower(n)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, n)
	}
	return out
}

func mergeToolNameLists(a, b []string) []string {
	return dedupeToolNameList(append(append([]string{}, a...), b...))
}

func ensureMap(parent *yaml.Node, path ...string) *yaml.Node {
	current := parent
	for _, key := range path {
		value := findMapValue(current, key)
		if value == nil {
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
			mapNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			current.Content = append(current.Content, keyNode, mapNode)
			value = mapNode
		}

		if value.Kind != yaml.MappingNode {
			value.Kind = yaml.MappingNode
			value.Tag = "!!map"
			value.Style = 0
			value.Content = nil
		}

		current = value
	}

	return current
}

func findMapValue(mapNode *yaml.Node, key string) *yaml.Node {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			return mapNode.Content[i+1]
		}
	}
	return nil
}

func ensureKeyValue(mapNode *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil, nil
	}

	for i := 0; i < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			return mapNode.Content[i], mapNode.Content[i+1]
		}
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valueNode := &yaml.Node{}
	mapNode.Content = append(mapNode.Content, keyNode, valueNode)
	return keyNode, valueNode
}

func setStringInMap(mapNode *yaml.Node, key, value string) {
	_, valueNode := ensureKeyValue(mapNode, key)
	valueNode.Kind = yaml.ScalarNode
	valueNode.Tag = "!!str"
	valueNode.Style = 0
	valueNode.Value = value
}

// setStringMapInMap writes a map[string]string as a YAML mapping node (keys sorted; empty values removed).
func setStringMapInMap(mapNode *yaml.Node, key string, values map[string]string) {
	if len(values) == 0 {
		removeKeyFromMap(mapNode, key)
		return
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		if strings.TrimSpace(k) == "" {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		removeKeyFromMap(mapNode, key)
		return
	}
	sort.Strings(keys)
	mapValue := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, k := range keys {
		mapValue.Content = append(mapValue.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: values[k]})
	}
	_, valueNode := ensureKeyValue(mapNode, key)
	*valueNode = *mapValue
}

func removeKeyFromMap(mapNode *yaml.Node, key string) {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		if mapNode.Content[i].Value == key {
			mapNode.Content = append(mapNode.Content[:i], mapNode.Content[i+2:]...)
			return
		}
	}
}

func setStringSliceInMap(mapNode *yaml.Node, key string, values []string) {
	_, valueNode := ensureKeyValue(mapNode, key)
	valueNode.Kind = yaml.SequenceNode
	valueNode.Tag = "!!seq"
	valueNode.Style = 0
	valueNode.Content = nil
	for _, v := range values {
		valueNode.Content = append(valueNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: v,
		})
	}
}

func setFlowStringSliceInMap(mapNode *yaml.Node, key string, values []string) {
	_, valueNode := ensureKeyValue(mapNode, key)
	valueNode.Kind = yaml.SequenceNode
	valueNode.Tag = "!!seq"
	valueNode.Style = yaml.FlowStyle
	valueNode.Content = nil
	for _, v := range values {
		valueNode.Content = append(valueNode.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: v,
		})
	}
}

func setIntInMap(mapNode *yaml.Node, key string, value int) {
	_, valueNode := ensureKeyValue(mapNode, key)
	valueNode.Kind = yaml.ScalarNode
	valueNode.Tag = "!!int"
	valueNode.Style = 0
	valueNode.Value = fmt.Sprintf("%d", value)
}

func findBoolInMap(mapNode *yaml.Node, key string) *bool {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i < len(mapNode.Content); i += 2 {
		if i+1 >= len(mapNode.Content) {
			break
		}
		keyNode := mapNode.Content[i]
		valueNode := mapNode.Content[i+1]

		if keyNode.Kind == yaml.ScalarNode && keyNode.Value == key {
			if valueNode.Kind == yaml.ScalarNode {
				if valueNode.Value == "true" {
					result := true
					return &result
				} else if valueNode.Value == "false" {
					result := false
					return &result
				}
			}
			return nil
		}
	}
	return nil
}

func setBoolInMap(mapNode *yaml.Node, key string, value bool) {
	_, valueNode := ensureKeyValue(mapNode, key)
	valueNode.Kind = yaml.ScalarNode
	valueNode.Tag = "!!bool"
	valueNode.Style = 0
	if value {
		valueNode.Value = "true"
	} else {
		valueNode.Value = "false"
	}
}

func setFloatInMap(mapNode *yaml.Node, key string, value float64) {
	_, valueNode := ensureKeyValue(mapNode, key)
	valueNode.Kind = yaml.ScalarNode
	valueNode.Tag = "!!float"
	valueNode.Style = 0
	// For values between 0.0 and 1.0 (e.g. similarity_threshold), use %.1f to ensure 0.0 is explicitly serialized as "0.0"
	// For other values, use %g to automatically choose the most appropriate format
	if value >= 0.0 && value <= 1.0 {
		valueNode.Value = fmt.Sprintf("%.1f", value)
	} else {
		valueNode.Value = fmt.Sprintf("%g", value)
	}
}

// getExternalMCPTools gets the external MCP tool list (public method)
func (h *ConfigHandler) getExternalMCPTools(ctx context.Context) []ToolConfigInfo {
	if h.externalMCPMgr == nil {
		return nil
	}
	return h.getExternalMCPToolsWithManager(ctx, h.externalMCPMgr, h.pickToolDescription)
}

// getExternalMCPToolsWithManager gets external MCP tools (does not hold the config lock; used by hot paths such as GetTools)
func (h *ConfigHandler) getExternalMCPToolsWithManager(
	ctx context.Context,
	mgr *mcp.ExternalMCPManager,
	pickDesc func(shortDesc, fullDesc string) string,
) []ToolConfigInfo {
	var result []ToolConfigInfo
	if mgr == nil {
		return result
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	externalTools, err := mgr.GetAllTools(timeoutCtx)
	if err != nil {
		h.logger.Warn("failed to get external MCP tools (connection may be broken); trying to return cached tools",
			zap.Error(err),
			zap.String("hint", "if external MCP tools are not shown, check the connection status or click the refresh button"),
		)
	}

	if len(externalTools) == 0 {
		return result
	}

	externalMCPConfigs := mgr.GetConfigs()

	for _, externalTool := range externalTools {
		mcpName, actualToolName := h.parseExternalToolName(externalTool.Name)
		if mcpName == "" || actualToolName == "" {
			continue
		}

		enabled := h.calculateExternalToolEnabledWithManager(mcpName, actualToolName, externalMCPConfigs, mgr)

		result = append(result, ToolConfigInfo{
			Name:        actualToolName,
			Description: pickDesc(externalTool.ShortDescription, externalTool.Description),
			Enabled:     enabled,
			IsExternal:  true,
			ExternalMCP: mcpName,
		})
	}

	return result
}

// parseExternalToolName parses an external tool name (format: mcpName::toolName)
func (h *ConfigHandler) parseExternalToolName(fullName string) (mcpName, toolName string) {
	idx := strings.Index(fullName, "::")
	if idx > 0 {
		return fullName[:idx], fullName[idx+2:]
	}
	return "", ""
}

// calculateExternalToolEnabled calculates the enable status of an external tool
func (h *ConfigHandler) calculateExternalToolEnabled(mcpName, toolName string, configs map[string]config.ExternalMCPServerConfig) bool {
	return h.calculateExternalToolEnabledWithManager(mcpName, toolName, configs, h.externalMCPMgr)
}

func (h *ConfigHandler) calculateExternalToolEnabledWithManager(
	mcpName, toolName string,
	configs map[string]config.ExternalMCPServerConfig,
	mgr *mcp.ExternalMCPManager,
) bool {
	cfg, exists := configs[mcpName]
	if !exists {
		return false
	}

	if !cfg.ExternalMCPEnable {
		return false
	}

	if cfg.ToolEnabled != nil {
		if toolEnabled, exists := cfg.ToolEnabled[toolName]; exists && !toolEnabled {
			return false
		}
	}

	if mgr == nil {
		return false
	}
	client, exists := mgr.GetClient(mcpName)
	if !exists || !client.IsConnected() {
		return false
	}

	return true
}

// pickToolDescription selects the short or full description according to security.tool_description_mode and limits its length.
// If the caller already holds the h.mu read lock, it must read the mode directly and call pickToolDescriptionWithMode, to avoid a nested RLock deadlock.
func (h *ConfigHandler) pickToolDescription(shortDesc, fullDesc string) string {
	return pickToolDescriptionWithMode(h.config.Security.ToolDescriptionMode, shortDesc, fullDesc)
}

func pickToolDescriptionWithMode(mode, shortDesc, fullDesc string) string {
	useFull := strings.TrimSpace(strings.ToLower(mode)) == "full"
	description := shortDesc
	if useFull {
		description = fullDesc
	} else if description == "" {
		description = fullDesc
	}
	if len(description) > 10000 {
		description = description[:10000] + "..."
	}
	return description
}

// GetToolSchema gets the inputSchema of a single tool (loaded on demand, to avoid the list endpoint returning large amounts of schema data)
func (h *ConfigHandler) GetToolSchema(c *gin.Context) {
	toolName := c.Param("name")
	if toolName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tool name cannot be empty"})
		return
	}

	externalMCP := c.Query("external_mcp")
	if externalMCP != "" {
		h.mu.RLock()
		externalMCPMgr := h.externalMCPMgr
		h.mu.RUnlock()

		if externalMCPMgr != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			externalTools, _ := externalMCPMgr.GetAllTools(ctx)
			fullName := externalMCP + "::" + toolName
			for _, t := range externalTools {
				if t.Name == fullName {
					c.JSON(http.StatusOK, gin.H{"input_schema": t.InputSchema})
					return
				}
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "external tool not found"})
		return
	}

	h.mu.RLock()
	securityTools := append([]config.ToolConfig(nil), h.config.Security.Tools...)
	mcpServer := h.mcpServer
	h.mu.RUnlock()

	for _, tool := range securityTools {
		if tool.Name == toolName {
			c.JSON(http.StatusOK, gin.H{"input_schema": buildInputSchemaFromParams(tool.Parameters)})
			return
		}
	}

	// MCP registered tools (e.g. knowledge retrieval)
	if mcpServer != nil {
		for _, mt := range mcpServer.GetAllTools() {
			if mt.Name == toolName {
				c.JSON(http.StatusOK, gin.H{"input_schema": mt.InputSchema})
				return
			}
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "tool not found"})
}

// buildInputSchemaFromParams builds a JSON Schema from the ParameterConfig of a YAML tool (for frontend display).
// Does not depend on MCP server registration state; all tools (including disabled ones) can return parameter definitions.
func buildInputSchemaFromParams(params []config.ParameterConfig) map[string]interface{} {
	if len(params) == 0 {
		return nil
	}

	properties := make(map[string]interface{})
	required := make([]string, 0)

	for _, p := range params {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		prop := map[string]interface{}{
			"type":        convertParamType(p.Type),
			"description": p.Description,
		}
		if p.Default != nil {
			prop["default"] = p.Default
		}
		if len(p.Options) > 0 {
			prop["enum"] = p.Options
		}
		properties[name] = prop
		if p.Required {
			required = append(required, name)
		}
	}

	schema := map[string]interface{}{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func convertParamType(t string) string {
	switch strings.TrimSpace(strings.ToLower(t)) {
	case "int", "integer", "number":
		return "number"
	case "bool", "boolean":
		return "boolean"
	case "array", "list":
		return "array"
	default:
		return "string"
	}
}
