package multiagent

import (
	"context"
	"fmt"
	"sync"

	"veritysec/internal/agent"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/einomcp"
	"veritysec/internal/project"
	"veritysec/internal/reasoning"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
	"go.uber.org/zap"
)

// einoSingleAgentName matches ChatModelAgent.Name, used to map streaming events to the main conversation area.
const einoSingleAgentName = "veritysec-eino-single"

// RunEinoSingleChatModelAgent uses Eino TypedChatModelAgent[*schema.AgenticMessage] + adk.NewRunner.Run (the Query in the official Quick Start is likewise the Runner API; here history + user message slicing is equivalent to multi-turn Query).
// Shares the SSE mapping and MCP bridge of runEinoADKAgentLoop with RunDeepAgent.
func RunEinoSingleChatModelAgent(
	ctx context.Context,
	appCfg *config.Config,
	ma *config.MultiAgentConfig,
	ag *agent.Agent,
	db *database.DB,
	logger *zap.Logger,
	conversationID string,
	projectID string,
	userMessage string,
	history []agent.ChatMessage,
	roleTools []string,
	progress func(eventType, message string, data interface{}),
	reasoningClient *reasoning.ClientIntent,
	systemPromptExtra string,
) (*RunResult, error) {
	if appCfg == nil || ag == nil {
		return nil, fmt.Errorf("eino single: configuration or Agent is empty")
	}
	if ma == nil {
		return nil, fmt.Errorf("eino single: multi_agent configuration is empty")
	}
	// agent.max_input_tokens_per_call (0 = off) lowers the per-call input window used by compaction/summarization.
	appCfg = capMaxTotalTokens(appCfg)
	// agent.run_token_budget (0 = off): per-run guard checked before every model call (see run_token_budget.go).
	tokenGuard := newRunTokenGuard(appCfg)
	runtimeUserMessage := prepareLatestUserMessageForModel(userMessage, appCfg, &ma.EinoMiddleware, conversationID, logger)

	einoLoc, einoSkillMW, einoFSTools, skillsRoot, einoErr := prepareEinoAgenticSkills(ctx, appCfg.SkillsDir, ma, logger)
	if einoErr != nil {
		return nil, einoErr
	}

	holder := &einomcp.ConversationHolder{}
	holder.Set(conversationID)

	var mcpIDsMu sync.Mutex
	var mcpIDs []string
	mcpExecBinder := NewMCPExecutionBinder()
	recorder := func(id, toolCallID string) {
		if id == "" {
			return
		}
		mcpExecBinder.Bind(toolCallID, id)
		mcpIDsMu.Lock()
		mcpIDs = append(mcpIDs, id)
		mcpIDsMu.Unlock()
	}

	snapshotMCPIDs := func() []string {
		mcpIDsMu.Lock()
		defer mcpIDsMu.Unlock()
		out := make([]string, len(mcpIDs))
		copy(out, mcpIDs)
		return out
	}

	toolInvokeNotify := einomcp.NewToolInvokeNotifyHolder()
	einoExecBegin, einoExecAppendPartial, einoExecRegisterCancel, einoExecUnregisterCancel, einoExecFinish := newEinoExecuteMonitorCallbacks(ctx, ag, recorder)
	mainDefs := ag.ToolsForRole(roleTools)
	evidenceRecord := newEngagementToolEvidenceRecorder(db, appCfg, &ma.EinoMiddleware, conversationID, logger)
	mainTools, err := einomcp.ToolsFromDefinitionsWithScope(ag, holder, mainDefs, recorder, nil, toolInvokeNotify, einoSingleAgentName, evidenceRecord, newEngagementScopeGuard(db, &ma.EinoMiddleware, conversationID, progress, logger))
	if err != nil {
		return nil, err
	}

	mainToolsForCfg, mainOrchestratorPre, singleToolSearchActive, err := prependEinoAgenticMiddlewares(ctx, &ma.EinoMiddleware, einoMWMain, mainTools, einoLoc, skillsRoot, conversationID, projectID, logger)
	if err != nil {
		return nil, fmt.Errorf("eino single eino middleware: %w", err)
	}

	baseHTTPClient := newEinoBaseHTTPClient()
	agenticModelFactory := newEinoAgenticChatModelFactory(baseHTTPClient, reasoningClient, logger)
	mainModel, err := agenticModelFactory(ctx, appCfg.OpenAI, einoModelModeNormal)
	if err != nil {
		return nil, fmt.Errorf("eino single agentic model: %w", err)
	}
	modelRetryCfg := newEinoAgenticModelRetryConfig(&ma.EinoMiddleware, logger, "eino_single")
	modelFailoverCfg, err := newEinoAgenticModelFailoverConfig(ctx, appCfg, &ma.EinoMiddleware, einoModelModeNormal, agenticModelFactory, logger, "eino_single", progress, "eino_single", conversationID)
	if err != nil {
		return nil, err
	}
	logEinoAgenticModelGate(
		logger,
		"eino_single",
		"eino_single",
		evaluateEinoAgenticModelGate(agenticModelGateFactory(agenticModelFactory, appCfg.OpenAI, einoModelModeNormal), einoAgenticRuntimeSupportV0914()),
	)

	mainSumMw, err := newEinoAgenticSummarizationMiddleware(ctx, mainModel, appCfg, &ma.EinoMiddleware, conversationID, db, projectID, logger)
	if err != nil {
		return nil, fmt.Errorf("eino single agentic summarization: %w", err)
	}

	modelFacingTrace := newModelFacingTraceHolder()

	handlers := make([]adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage], 0, 8)
	if ma.EinoMiddleware.EngagementAutoStagesEffective() {
		if stageMW := newEngagementStageMiddleware(db, conversationID); stageMW != nil {
			handlers = append(handlers, stageMW)
		}
	}
	// Token-budget guard first: it must run before reduction/summarization so an exhausted run never pays for another model call.
	if tgMW := tokenGuard.Middleware(); tgMW != nil {
		handlers = append(handlers, tgMW)
	}
	// mainOrchestratorPre comes from prependEinoAgenticMiddlewares: patchtoolcalls, reduction (eino reduction library; keeps
	// tool-call/tool-result pairs intact), toolsearch, plantask, manifest. This is the production path for context reduction.
	if len(mainOrchestratorPre) > 0 {
		handlers = append(handlers, mainOrchestratorPre...)
	}
	if einoSkillMW != nil {
		if einoFSTools && einoLoc != nil {
			fsMw, fsErr := subAgentAgenticFilesystemMiddleware(ctx, einoLoc, toolInvokeNotify, einoSingleAgentName, conversationID, projectID, ma.EinoMiddleware.ReductionRootDir, toolMaxBytesFromMW(&ma.EinoMiddleware), mcpExecBinder, einoExecBegin, einoExecAppendPartial, einoExecRegisterCancel, einoExecUnregisterCancel, einoExecFinish, agentToolTimeoutMinutes(appCfg), agentToolWaitTimeoutSeconds(appCfg), agentShellNoOutputTimeoutSeconds(appCfg), nil)
			if fsErr != nil {
				return nil, fmt.Errorf("eino single filesystem middleware: %w", fsErr)
			}
			handlers = append(handlers, fsMw)
		}
		handlers = append(handlers, einoSkillMW)
	}
	handlers = appendEinoAgenticChatModelTailMiddlewares(handlers, einoChatModelTailConfig{
		logger:               logger,
		phase:                "eino_single",
		agenticSummarization: mainSumMw,
		modelName:            appCfg.OpenAI.Model,
		maxTotalTokens:       appCfg.OpenAI.MaxTotalTokens,
		toolMaxBytes:         toolMaxBytesFromMW(&ma.EinoMiddleware),
		conversationID:       conversationID,
		trace:                modelFacingTrace,
		middlewareConfig:     &ma.EinoMiddleware,
	})

	maxIter := agentMaxIterations(appCfg)

	mainToolsCfg := adk.ToolsConfig{
		ToolsNodeConfig: compose.ToolsNodeConfig{
			Tools:               mainToolsForCfg,
			UnknownToolsHandler: einomcp.UnknownToolReminderHandler(),
			ToolCallMiddlewares: []compose.ToolMiddleware{
				modelOutputExecutionGuardMiddleware(),
				localToolRBACMiddleware(),
				hitlToolCallMiddleware(),
				softRecoveryToolMiddleware(),
			},
		},
		EmitInternalEvents: true,
	}
	ins := project.AppendSystemPromptBlock(ag.EinoSingleAgentSystemInstruction(), systemPromptExtra)
	ins = project.AppendVisionImageAnalysisIfReady(ins, appCfg.Vision.Ready())
	ins = injectToolNamesOnlyInstruction(ctx, ins, mainTools, singleToolSearchActive)
	if logger != nil {
		names := collectToolNames(ctx, mainTools)
		mountedNames := collectToolNames(ctx, mainToolsForCfg)
		logger.Info("eino tool-name injection",
			zap.String("scope", "eino_single"),
			zap.Int("tool_names", len(names)),
			zap.Int("mounted_tool_names", len(mountedNames)),
			zap.Bool("tool_search_middleware", singleToolSearchActive),
		)
	}

	chatCfg := einoAgenticChatModelAgentConfig{
		Name:                einoSingleAgentName,
		Description:         "Eino ADK ChatModelAgent with MCP tools for authorized security testing.",
		Instruction:         ins,
		GenModelInput:       literalAgenticInstructionGenModelInput,
		Model:               mainModel,
		ToolsConfig:         mainToolsCfg,
		MaxIterations:       maxIter,
		Handlers:            handlers,
		ModelRetryConfig:    modelRetryCfg,
		ModelFailoverConfig: modelFailoverCfg,
	}
	outKey, _ := deepExtrasFromConfig(ma)
	if outKey != "" {
		chatCfg.OutputKey = outKey
	}

	chatAgent, err := newEinoAgenticChatModelAgentAdapter(ctx, chatCfg)
	if err != nil {
		return nil, fmt.Errorf("eino single Agentic ChatModelAgent: %w", err)
	}

	baseMsgs := historyToMessages(history, appCfg, &ma.EinoMiddleware)
	baseMsgs = appendUserMessageIfNeeded(baseMsgs, runtimeUserMessage)

	streamsMainAssistant := func(agent string) bool {
		return agent == "" || agent == einoSingleAgentName
	}
	einoRoleTag := func(agent string) string {
		_ = agent
		return "orchestrator"
	}

	return runEinoADKAgentLoop(ctx, &einoADKRunLoopArgs{
		OrchMode:             "eino_single",
		OrchestratorName:     einoSingleAgentName,
		ConversationID:       conversationID,
		Progress:             progress,
		Logger:               logger,
		SnapshotMCPIDs:       snapshotMCPIDs,
		StreamsMainAssistant: streamsMainAssistant,
		EinoRoleTag:          einoRoleTag,
		// Chat history recovery is intentionally centralized in last_react_*.
		// ADK checkpoints are a second persisted model-state channel and make
		// stale-context bugs hard to reason about across user turns.
		CheckpointDir:           "",
		RunRetryMaxAttempts:     RunRetryMaxAttemptsFromConfig(&ma.EinoMiddleware),
		RunRetryMaxBackoffSec:   int(einoRunRetryMaxBackoffFromConfig(&ma.EinoMiddleware).Seconds()),
		McpIDsMu:                &mcpIDsMu,
		McpIDs:                  &mcpIDs,
		FilesystemMonitorAgent:  ag,
		FilesystemMonitorRecord: recorder,
		MCPExecutionBinder:      mcpExecBinder,
		ToolInvokeNotify:        toolInvokeNotify,
		TokenGuard:              tokenGuard,
		DA:                      chatAgent,
		ModelFacingTrace:        modelFacingTrace,
		EinoCallbacks:           &ma.EinoCallbacks,
		MaxTotalTokens:          appCfg.OpenAI.MaxTotalTokens,
		ToolMaxBytes:            toolMaxBytesFromMW(&ma.EinoMiddleware),
		ModelName:               appCfg.OpenAI.Model,
		MiddlewareConfig:        &ma.EinoMiddleware,
		EmptyResponseMessage: "(Eino ADK single-agent session completed but no assistant text was captured. Check process details or logs.) " +
			"(Eino ADK single-agent session completed, but no assistant text output was captured. Check process details or logs.)",
	}, baseMsgs)
}
