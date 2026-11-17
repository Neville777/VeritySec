package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veritysec/internal/config"
	"veritysec/internal/mcp"
	"veritysec/internal/project"
	"veritysec/internal/sandbox"
	"veritysec/internal/tooloutput"

	"github.com/creack/pty"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ToolOutputCallback pushes stdout/stderr increments to the upper layer (SSE) during tool execution.
// It is passed through context so the MCP ToolHandler signature does not change, which would cause the "hard-coded tool" problem.
type ToolOutputCallback func(chunk string)

type toolOutputCallbackCtxKey struct{}

// ToolOutputCallbackCtxKey is the context key under which the Agent stores the callback; the Executor reads it and streams through it.
var ToolOutputCallbackCtxKey = toolOutputCallbackCtxKey{}

// Executor is the security tool executor
type Executor struct {
	config                  *config.SecurityConfig
	toolIndex               map[string]*config.ToolConfig // tool index for O(1) lookup
	mcpServer               *mcp.Server
	logger                  *zap.Logger
	shellNoOutputTimeoutSec int // idle seconds with no new execute/exec output; 0 = default 300; -1 = disabled (see SetShellNoOutputTimeoutSeconds)
	toolOutputMaxBytes      int
	spillRootDir            string
	toolExec                config.ToolExecutionConfig // zero value => runtime "none"
	sandboxBaseDir          string                     // data directory under which per-run work dirs are created
}

// commandBuilder is the seam used to construct the tool host process.
var commandBuilder = exec.CommandContext

// SetToolExecution configures the optional Docker sandbox for tool recipes.
// dataDir is the data directory under which per-run work dirs are created.
func (e *Executor) SetToolExecution(cfg config.ToolExecutionConfig, dataDir string) {
	e.toolExec = cfg
	e.sandboxBaseDir = dataDir
	hostExecRefusedInDocker.Store(cfg.ContainerRuntimeEffective() == "docker")
}

// newToolCommand builds the process for a tool recipe. With runtime "none" it is
// exactly commandBuilder(ctx, name, args...). With runtime "docker" the tool is
// wrapped in `docker run` built by sandbox.BuildRunArgs.
//
// SECURITY NOTE: the docker wrapper limits filesystem and privilege access
// (read-only rootfs, dropped caps, no-new-privileges, memory/pids limits, only
// a per-run work dir mounted). It does NOT limit network access when network is
// "host": the tool then shares the host network namespace.
func (e *Executor) newToolCommand(ctx context.Context, name string, args []string) (*exec.Cmd, context.Context, func(), error) {
	noop := func() {}
	if e.toolExec.ContainerRuntimeEffective() != "docker" {
		return commandBuilder(ctx, name, args...), ctx, noop, nil
	}
	if e.sandboxBaseDir == "" {
		return nil, ctx, noop, fmt.Errorf("sandbox: data directory not configured")
	}
	runRoot := filepath.Join(e.sandboxBaseDir, "sandbox-runs")
	if err := os.MkdirAll(runRoot, 0o700); err != nil {
		return nil, ctx, noop, fmt.Errorf("sandbox: create run root: %w", err)
	}
	workDir := filepath.Join(runRoot, uuid.NewString())
	if err := os.Mkdir(workDir, 0o700); err != nil {
		return nil, ctx, noop, fmt.Errorf("sandbox: create work dir: %w", err)
	}
	if abs, err := filepath.Abs(workDir); err == nil {
		workDir = abs
	}
	cleanup := func() { _ = os.RemoveAll(workDir) }
	var sharedDir, sharedRoot string
	if convID := strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx)); convID != "" {
		// Same layout the agent uses: <cwd>/tmp/workspace/conversations/<id>.
		rel := project.WorkspaceRootDir("", "", convID)
		absDir, aerr := filepath.Abs(rel)
		absRoot, rerr := filepath.Abs(filepath.Dir(rel))
		if aerr != nil || rerr != nil {
			cleanup()
			return nil, ctx, noop, fmt.Errorf("sandbox: resolve conversation workspace")
		}
		if merr := os.MkdirAll(absDir, 0o700); merr != nil {
			cleanup()
			return nil, ctx, noop, fmt.Errorf("sandbox: create conversation workspace: %w", merr)
		}
		sharedDir, sharedRoot = absDir, absRoot
	}
	dargs, err := sandbox.BuildRunArgs(sandbox.Options{
		SharedDir:     sharedDir,
		SharedRoot:    sharedRoot,
		Image:         e.toolExec.DockerImage,
		Network:       e.toolExec.Network,
		BridgeNetwork: e.toolExec.BridgeNetwork,
		CapAdd:        e.toolExec.CapAdd,
		Memory:        e.toolExec.Memory,
		PidsLimit:     e.toolExec.PidsLimit,
		WorkDir:       workDir,
		Argv:          append([]string{sandboxArgv0(name)}, args...),
	})
	if err != nil {
		cleanup()
		return nil, ctx, noop, err
	}
	cancel := func() {}
	if e.toolExec.TimeoutSeconds > 0 {
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, time.Duration(e.toolExec.TimeoutSeconds)*time.Second)
		cancel = c
	}
	return commandBuilder(ctx, "docker", dargs...), ctx, func() { cancel(); cleanup() }, nil
}

// sandboxArgv0 maps a path-style recipe command (for example /usr/bin/nmap) to
// its bare name, because the container has its own binaries. The result still
// goes through the sandbox bare-name check in BuildRunArgs.
func sandboxArgv0(name string) string {
	if strings.Contains(name, "/") {
		return filepath.Base(name)
	}
	return name
}

// hostExecRefusedInDocker is set by SetToolExecution so package-level launch
// paths (the shell stream) can refuse host execution in docker mode.
var hostExecRefusedInDocker atomic.Bool

// refuseHostExecInDocker returns an error when container_runtime is docker,
// for launch paths that would otherwise run directly on the host.
func (e *Executor) refuseHostExecInDocker(tool string) error {
	if e.toolExec.ContainerRuntimeEffective() == "docker" {
		return fmt.Errorf("not available while container_runtime is docker: %s", tool)
	}
	return nil
}

// dockerPTYRetryCmd rebuilds a docker run command with docker's own "-t" flag
// right after "run". It returns nil when cmd is not a docker run command.
func dockerPTYRetryCmd(ctx context.Context, cmd *exec.Cmd) *exec.Cmd {
	if len(cmd.Args) < 2 || cmd.Args[0] != "docker" || cmd.Args[1] != "run" {
		return nil
	}
	args := make([]string, 0, len(cmd.Args))
	args = append(args, "run", "-t")
	args = append(args, cmd.Args[2:]...)
	return commandBuilder(ctx, "docker", args...)
}

// NewExecutor creates a new executor
func NewExecutor(cfg *config.SecurityConfig, mcpServer *mcp.Server, logger *zap.Logger) *Executor {
	executor := &Executor{
		config:    cfg,
		toolIndex: make(map[string]*config.ToolConfig),
		mcpServer: mcpServer,
		logger:    logger,
	}
	// build the tool index
	executor.buildToolIndex()
	return executor
}

// SetShellNoOutputTimeoutSeconds configures idle termination of the exec tool when there is no output (consistent with agent.shell_no_output_timeout_seconds).
func (e *Executor) SetShellNoOutputTimeoutSeconds(sec int) {
	e.shellNoOutputTimeoutSec = sec
}

// SetToolOutputMaxBytes limits stdout/stderr retained and streamed by exec-like
// tools. It should stay aligned with MCP result normalization so every channel
// sees the same bounded payload. Oversized full output is spilled to disk first.
func (e *Executor) SetToolOutputMaxBytes(maxBytes int) {
	e.toolOutputMaxBytes = maxBytes
}

// SetToolOutputSpillRoot sets the reduction-compatible root for spilling full
// exec stdout/stderr when the in-memory bound is exceeded (empty → tmp/reduction).
func (e *Executor) SetToolOutputSpillRoot(rootDir string) {
	e.spillRootDir = strings.TrimSpace(rootDir)
}

func (e *Executor) wrapToolOutputCallback(ctx context.Context, cb ToolOutputCallback) ToolOutputCallback {
	executionID := mcp.MCPExecutionIDFromContext(ctx)
	if e == nil || e.mcpServer == nil || strings.TrimSpace(executionID) == "" {
		return cb
	}
	return func(chunk string) {
		if chunk != "" {
			e.mcpServer.AppendToolExecutionPartialOutput(executionID, chunk)
		}
		if cb != nil {
			cb(chunk)
		}
	}
}

func (e *Executor) spillOptsFromContext(ctx context.Context) tooloutput.SpillOpts {
	root := ""
	if e != nil {
		root = e.spillRootDir
	}
	opts := tooloutput.SpillOpts{RootDir: root}
	if ctx != nil {
		opts.ConversationID = mcp.MCPConversationIDFromContext(ctx)
		opts.ProjectID = mcp.MCPProjectIDFromContext(ctx)
		opts.ExecutionID = mcp.MCPExecutionIDFromContext(ctx)
	}
	if opts.ExecutionID == "" {
		opts.ExecutionID = uuid.NewString()
	}
	return opts
}

// buildToolIndex builds the tool index, optimizing O(n) lookups to O(1)
func (e *Executor) buildToolIndex() {
	e.toolIndex = make(map[string]*config.ToolConfig)
	for i := range e.config.Tools {
		if e.config.Tools[i].Enabled {
			e.toolIndex[e.config.Tools[i].Name] = &e.config.Tools[i]
		}
	}
	e.logger.Debug("tool index built",
		zap.Int("totalTools", len(e.config.Tools)),
		zap.Int("enabledTools", len(e.toolIndex)),
	)
}

// ExecuteTool executes a security tool
func (e *Executor) ExecuteTool(ctx context.Context, toolName string, args map[string]interface{}) (*mcp.ToolResult, error) {
	e.logger.Debug("ExecuteTool called",
		zap.String("toolName", toolName),
		zap.Any("args", args),
	)

	// Special case: the exec tool runs system commands directly
	if toolName == "exec" {
		e.logger.Debug("executing exec tool")
		return e.executeSystemCommand(ctx, args)
	}

	// Look up the tool config via index (O(1) lookup)
	toolConfig, exists := e.toolIndex[toolName]
	if !exists {
		e.logger.Error("tool not found or not enabled",
			zap.String("toolName", toolName),
			zap.Int("totalTools", len(e.config.Tools)),
			zap.Int("enabledTools", len(e.toolIndex)),
		)
		return nil, fmt.Errorf("tool %s not found or not enabled", toolName)
	}

	e.logger.Debug("found tool config",
		zap.String("toolName", toolName),
		zap.String("command", toolConfig.Command),
		zap.Strings("args", toolConfig.Args),
	)

	// Special case: internal tools (command starts with "internal:")
	if strings.HasPrefix(toolConfig.Command, "internal:") {
		e.logger.Debug("executing internal tool",
			zap.String("toolName", toolName),
			zap.String("command", toolConfig.Command),
		)
		return e.executeInternalTool(ctx, toolName, toolConfig.Command, args)
	}

	// Build the command - use a different argument format depending on the tool type
	cmdArgs := e.buildCommandArgs(toolName, toolConfig, args)

	e.logger.Debug("command arguments built",
		zap.String("toolName", toolName),
		zap.Strings("cmdArgs", cmdArgs),
		zap.Int("argsCount", len(cmdArgs)),
	)

	// Validate command arguments
	if len(cmdArgs) == 0 {
		e.logger.Warn("command arguments are empty",
			zap.String("toolName", toolName),
			zap.Any("inputArgs", args),
		)
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: fmt.Sprintf("Error: tool %s is missing required arguments. Received arguments: %v", toolName, args),
				},
			},
			IsError: true,
		}, nil
	}

	// Execute command
	cmd, ctx, cleanupCmd, cmdErr := e.newToolCommand(ctx, toolConfig.Command, cmdArgs)
	if cmdErr != nil {
		return &mcp.ToolResult{
			Content: []mcp.Content{{Type: "text", Text: fmt.Sprintf("tool %s not run: %v", toolName, cmdErr)}},
			IsError: true,
		}, nil
	}
	defer cleanupCmd()
	sandboxed := e.toolExec.ContainerRuntimeEffective() == "docker"
	applyDefaultTerminalEnv(cmd)
	attachNonInteractiveStdin(cmd)
	_ = prepareShellCmdSession(cmd)

	e.logger.Debug("executing security tool",
		zap.String("tool", toolName),
		zap.Strings("args", cmdArgs),
	)

	var output string
	var err error
	spill := e.spillOptsFromContext(ctx)
	// If the upper layer provided a stdout/stderr incremental callback, or we are inside an MCP execution, read and call back while executing.
	if cb, ok := ctx.Value(ToolOutputCallbackCtxKey).(ToolOutputCallback); (ok && cb != nil) || mcp.MCPExecutionIDFromContext(ctx) != "" {
		cb = e.wrapToolOutputCallback(ctx, cb)
		output, err = streamCommandOutput(ctx, cmd, cb, ResolveShellNoOutputTimeoutSeconds(e.shellNoOutputTimeoutSec), e.toolOutputMaxBytes, spill)
		if err != nil && sandboxed && shouldRetryWithPTY(output) {
			if cmd2 := dockerPTYRetryCmd(ctx, cmd); cmd2 != nil {
				e.logger.Info("tool requires a TTY, retrying with docker -t",
					zap.String("tool", toolName),
				)
				applyDefaultTerminalEnv(cmd2)
				attachNonInteractiveStdin(cmd2)
				_ = prepareShellCmdSession(cmd2)
				output, err = streamCommandOutput(ctx, cmd2, cb, ResolveShellNoOutputTimeoutSeconds(e.shellNoOutputTimeoutSec), e.toolOutputMaxBytes, spill)
			}
		} else if err != nil && !sandboxed && shouldRetryWithPTY(output) {
			e.logger.Info("tool requires a TTY, retrying with PTY",
				zap.String("tool", toolName),
			)
			cmd2 := exec.CommandContext(ctx, toolConfig.Command, cmdArgs...)
			applyDefaultTerminalEnv(cmd2)
			_ = prepareShellCmdSession(cmd2)
			output, err = runCommandWithPTY(ctx, cmd2, cb, e.toolOutputMaxBytes, spill)
		}
	} else {
		// Non-streaming: in-memory buffer + ctx cancellation kills the process group; behavior matches the original CombinedOutput, avoiding deadlocks from dual-stream pipe fan-in.
		output, err = combinedOutputCancellableWithLimit(ctx, cmd, e.toolOutputMaxBytes, spill)
		if err != nil && sandboxed && shouldRetryWithPTY(output) {
			if cmd2 := dockerPTYRetryCmd(ctx, cmd); cmd2 != nil {
				e.logger.Info("tool requires a TTY, retrying with docker -t",
					zap.String("tool", toolName),
				)
				applyDefaultTerminalEnv(cmd2)
				attachNonInteractiveStdin(cmd2)
				_ = prepareShellCmdSession(cmd2)
				output, err = combinedOutputCancellableWithLimit(ctx, cmd2, e.toolOutputMaxBytes, spill)
			}
		} else if err != nil && !sandboxed && shouldRetryWithPTY(output) {
			e.logger.Info("tool requires a TTY, retrying with PTY",
				zap.String("tool", toolName),
			)
			cmd2 := exec.CommandContext(ctx, toolConfig.Command, cmdArgs...)
			applyDefaultTerminalEnv(cmd2)
			_ = prepareShellCmdSession(cmd2)
			output, err = runCommandWithPTY(ctx, cmd2, nil, e.toolOutputMaxBytes, spill)
		}
	}
	if err != nil {
		// Check whether the exit code is in the allow list
		exitCode := getExitCode(err)
		if exitCode != nil && toolConfig.AllowedExitCodes != nil {
			for _, allowedCode := range toolConfig.AllowedExitCodes {
				if *exitCode == allowedCode {
					e.logger.Debug("tool execution completed (exit code is in the allow list)",
						zap.String("tool", toolName),
						zap.Int("exitCode", *exitCode),
						zap.String("output", string(output)),
					)
					return &mcp.ToolResult{
						Content: []mcp.Content{
							{
								Type: "text",
								Text: string(output),
							},
						},
						IsError: false,
					}, nil
				}
			}
		}

		e.logger.Error("tool execution failed",
			zap.String("tool", toolName),
			zap.Error(err),
			zap.Int("exitCode", getExitCodeValue(err)),
			zap.String("output", string(output)),
		)
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: fmt.Sprintf("tool execution failed: %v\nOutput: %s", err, string(output)),
				},
			},
			IsError: true,
		}, nil
	}

	e.logger.Debug("tool execution succeeded",
		zap.String("tool", toolName),
		zap.String("output", string(output)),
	)

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: string(output),
			},
		},
		IsError: false,
	}, nil
}

// RegisterTools registers tools with the MCP server
func (e *Executor) RegisterTools(mcpServer *mcp.Server) {
	e.logger.Debug("start registering tools",
		zap.Int("totalTools", len(e.config.Tools)),
		zap.Int("enabledTools", len(e.toolIndex)),
	)

	// Rebuild the index (in case the config was updated)
	e.buildToolIndex()

	for i, toolConfig := range e.config.Tools {
		if !toolConfig.Enabled {
			e.logger.Debug("skipping disabled tool",
				zap.String("tool", toolConfig.Name),
			)
			continue
		}

		// Copy the tool config to avoid closure capture issues
		toolName := toolConfig.Name
		toolConfigCopy := toolConfig

		// Choose the description exposed to the AI/API based on config: short_description or description
		useFullDescription := strings.TrimSpace(strings.ToLower(e.config.ToolDescriptionMode)) == "full"
		shortDesc := toolConfigCopy.ShortDescription
		if shortDesc == "" {
			// If there is no short description, take the first line or the first 10000 characters of the detailed description
			desc := toolConfigCopy.Description
			if len(desc) > 10000 {
				if idx := strings.Index(desc, "\n"); idx > 0 && idx < 10000 {
					shortDesc = strings.TrimSpace(desc[:idx])
				} else {
					shortDesc = desc[:10000] + "..."
				}
			} else {
				shortDesc = desc
			}
		}
		if useFullDescription {
			shortDesc = "" // clear ShortDescription when using description; downstream falls back to Description
		}

		tool := mcp.Tool{
			Name:             toolConfigCopy.Name,
			Description:      toolConfigCopy.Description,
			ShortDescription: shortDesc,
			InputSchema:      e.buildInputSchema(&toolConfigCopy),
		}

		handler := func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
			e.logger.Debug("tool handler called",
				zap.String("toolName", toolName),
				zap.Any("args", args),
			)
			return e.ExecuteTool(ctx, toolName, args)
		}

		mcpServer.RegisterTool(tool, handler)
		e.logger.Debug("security tool registered successfully",
			zap.String("tool", toolConfigCopy.Name),
			zap.String("command", toolConfigCopy.Command),
			zap.Int("index", i),
		)
	}

	e.logger.Debug("tool registration complete",
		zap.Int("registeredCount", len(e.config.Tools)),
	)
}

// buildCommandArgs builds command arguments
func (e *Executor) buildCommandArgs(toolName string, toolConfig *config.ToolConfig, args map[string]interface{}) []string {
	cmdArgs := make([]string, 0)

	// If a parameter mapping is defined in the config, use the mapping rules from the config
	if len(toolConfig.Parameters) > 0 {
		// Check for a scan_type parameter; if present, replace the default scan-type parameter
		hasScanType := false
		var scanTypeValue string
		if scanType, ok := args["scan_type"].(string); ok && scanType != "" {
			hasScanType = true
			scanTypeValue = scanType
		}

		// Add fixed parameters (if scan_type is specified, the default scan-type parameters may need to be filtered out)
		if hasScanType && toolName == "nmap" {
			// For nmap, if scan_type is specified, skip the default -sT -sV -sC
			// These arguments are replaced by the scan_type parameter
		} else {
			cmdArgs = append(cmdArgs, toolConfig.Args...)
		}

		// Sort by positional argument
		positionalParams := make([]config.ParameterConfig, 0)
		flagParams := make([]config.ParameterConfig, 0)

		for _, param := range toolConfig.Parameters {
			if param.Position != nil {
				positionalParams = append(positionalParams, param)
			} else {
				flagParams = append(flagParams, param)
			}
		}

		// For tools that need a subcommand (e.g. gobuster dir), position 0 must come right after the command name and before all flags
		for _, param := range positionalParams {
			if param.Name == "additional_args" || param.Name == "scan_type" || param.Name == "action" {
				continue
			}
			if param.Position != nil && *param.Position == 0 {
				value := e.getParamValue(args, param)
				if value == nil && param.Default != nil {
					value = param.Default
				}
				if value != nil {
					cmdArgs = append(cmdArgs, e.formatParamValue(param, value))
				}
				break
			}
		}

		// Process flag arguments
		for _, param := range flagParams {
			// Skip special arguments; they are handled separately below
			// The action argument is only for internal tool logic and is not passed to the command
			if param.Name == "additional_args" || param.Name == "scan_type" || param.Name == "action" {
				continue
			}

			value := e.getParamValue(args, param)
			if value == nil {
				if param.Required {
					// Required argument missing: return an empty array and let the upper layer handle the error
					e.logger.Warn("required flag argument missing",
						zap.String("tool", toolName),
						zap.String("param", param.Name),
					)
					return []string{}
				}
				continue
			}

			// Boolean special case: if false, skip; if true, only add the flag
			if param.Type == "bool" {
				var boolVal bool
				var ok bool

				// Try multiple type conversions
				if boolVal, ok = value.(bool); ok {
					// Already a boolean
				} else if numVal, ok := value.(float64); ok {
					// JSON number type (float64)
					boolVal = numVal != 0
					ok = true
				} else if numVal, ok := value.(int); ok {
					// int type
					boolVal = numVal != 0
					ok = true
				} else if strVal, ok := value.(string); ok {
					// string type
					boolVal = strVal == "true" || strVal == "1" || strVal == "yes"
					ok = true
				}

				if ok {
					if !boolVal {
						continue // when false, add no arguments
					}
					// When true, only add the flag, not a value
					if param.Flag != "" {
						cmdArgs = append(cmdArgs, param.Flag)
					}
					continue
				}
			}

			formattedValue := e.formatParamValue(param, value)
			if strings.TrimSpace(formattedValue) == "" {
				if param.Required {
					e.logger.Warn("required argument is empty",
						zap.String("tool", toolName),
						zap.String("param", param.Name),
					)
					return []string{}
				}
				continue
			}

			format := param.Format
			if format == "" {
				format = "flag" // default format
			}

			switch format {
			case "flag":
				// --flag value or -f value
				if param.Flag != "" {
					cmdArgs = append(cmdArgs, param.Flag)
				}
				cmdArgs = append(cmdArgs, formattedValue)
			case "combined":
				// --flag=value or -f=value
				if param.Flag != "" {
					cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", param.Flag, formattedValue))
				} else {
					cmdArgs = append(cmdArgs, formattedValue)
				}
			case "template":
				// Use a template string
				if param.Template != "" {
					template := param.Template
					template = strings.ReplaceAll(template, "{flag}", param.Flag)
					template = strings.ReplaceAll(template, "{value}", formattedValue)
					template = strings.ReplaceAll(template, "{name}", param.Name)
					cmdArgs = append(cmdArgs, strings.Fields(template)...)
				} else {
					// If there is no template, use the default format
					if param.Flag != "" {
						cmdArgs = append(cmdArgs, param.Flag)
					}
					cmdArgs = append(cmdArgs, formattedValue)
				}
			case "positional":
				// Positional argument (already handled above)
				cmdArgs = append(cmdArgs, formattedValue)
			default:
				// Default: add the value directly
				cmdArgs = append(cmdArgs, formattedValue)
			}
		}

		// Then process positional arguments (positional arguments usually come after flag arguments)
		// Sort positional arguments by position
		// First find the largest position value to determine how many positions need processing
		maxPosition := -1
		for _, param := range positionalParams {
			if param.Position != nil && *param.Position > maxPosition {
				maxPosition = *param.Position
			}
		}

		// Process arguments in position order, so they are passed correctly even when some positions have no argument or use defaults
		// position 0 was already inserted earlier (subcommand takes priority); start from 1 here
		for i := 0; i <= maxPosition; i++ {
			if i == 0 {
				continue
			}
			for _, param := range positionalParams {
				// Skip special arguments; they are handled separately below
				// The action argument is only for internal tool logic and is not passed to the command
				if param.Name == "additional_args" || param.Name == "scan_type" || param.Name == "action" {
					continue
				}

				if param.Position != nil && *param.Position == i {
					value := e.getParamValue(args, param)
					if value == nil {
						if param.Required {
							// Required argument missing: return an empty array and let the upper layer handle the error
							e.logger.Warn("required positional argument missing",
								zap.String("tool", toolName),
								zap.String("param", param.Name),
								zap.Int("position", *param.Position),
							)
							return []string{}
						}
						// For non-required arguments, if the value is nil, try the default value
						if param.Default != nil {
							value = param.Default
						} else {
							// If there is no default value, skip this position and continue with the next one
							break
						}
					}
					// Only add to the command arguments when the value is not nil
					if value != nil {
						cmdArgs = append(cmdArgs, e.formatParamValue(param, value))
					}
					break
				}
			}
			// If no argument is found for a position, continue with the next position
			// This keeps the positional argument order correct
		}

		// Special case: additional_args (must be split by spaces into multiple arguments)
		if additionalArgs, ok := args["additional_args"].(string); ok && additionalArgs != "" {
			// Split by spaces, but keep content inside quotes
			additionalArgsList := e.parseAdditionalArgs(additionalArgs)
			cmdArgs = append(cmdArgs, additionalArgsList...)
		}

		// Special case: scan_type (must be split by spaces and inserted at the appropriate position)
		if hasScanType {
			scanTypeArgs := e.parseAdditionalArgs(scanTypeValue)
			if len(scanTypeArgs) > 0 {
				if toolName == "nmap" {
					// Keep each option next to its value (especially --script).
					// Nmap accepts scan options before all other arguments.
					return append(scanTypeArgs, cmdArgs...)
				}
				// Preserve the existing insertion rule for other tools using scan_type.
				insertPos := len(cmdArgs)
				for i := len(cmdArgs) - 1; i >= 0; i-- {
					// target is usually the last non-flag argument
					if !strings.HasPrefix(cmdArgs[i], "-") {
						insertPos = i
						break
					}
				}
				// Insert the scan_type argument before target
				newArgs := make([]string, 0, len(cmdArgs)+len(scanTypeArgs))
				newArgs = append(newArgs, cmdArgs[:insertPos]...)
				newArgs = append(newArgs, scanTypeArgs...)
				newArgs = append(newArgs, cmdArgs[insertPos:]...)
				cmdArgs = newArgs
			}
		}

		return cmdArgs
	}

	// If no argument config is defined, use fixed arguments and generic processing
	// Add fixed arguments
	cmdArgs = append(cmdArgs, toolConfig.Args...)

	// Generic processing: convert arguments to command-line arguments
	for key, value := range args {
		if key == "_tool_name" {
			continue
		}
		// Use --key value format
		cmdArgs = append(cmdArgs, fmt.Sprintf("--%s", key))
		if strValue, ok := value.(string); ok {
			cmdArgs = append(cmdArgs, strValue)
		} else {
			cmdArgs = append(cmdArgs, fmt.Sprintf("%v", value))
		}
	}

	return cmdArgs
}

// parseAdditionalArgs parses the additional_args string, splitting by spaces but keeping content inside quotes
func (e *Executor) parseAdditionalArgs(argsStr string) []string {
	if argsStr == "" {
		return []string{}
	}

	result := make([]string, 0)
	var current strings.Builder
	inQuotes := false
	var quoteChar rune
	escapeNext := false

	runes := []rune(argsStr)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if escapeNext {
			current.WriteRune(r)
			escapeNext = false
			continue
		}

		if r == '\\' {
			// Check whether the next character is a quote
			if i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\'') {
				// Escaped quote: skip the backslash and write the quote as a normal character
				i++
				current.WriteRune(runes[i])
			} else {
				// Other escape characters: write the backslash; the next character is handled in the next iteration
				escapeNext = true
				current.WriteRune(r)
			}
			continue
		}

		if !inQuotes && (r == '"' || r == '\'') {
			inQuotes = true
			quoteChar = r
			continue
		}

		if inQuotes && r == quoteChar {
			inQuotes = false
			quoteChar = 0
			continue
		}

		if !inQuotes && (r == ' ' || r == '\t' || r == '\n') {
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			continue
		}

		current.WriteRune(r)
	}

	// Handle the last argument (if present)
	if current.Len() > 0 {
		result = append(result, current.String())
	}

	// If the parse result is empty, fall back to a simple space split
	if len(result) == 0 {
		result = strings.Fields(argsStr)
	}

	return result
}

// getParamValue gets the parameter value, with default-value support
func (e *Executor) getParamValue(args map[string]interface{}, param config.ParameterConfig) interface{} {
	// Get the value from the parameters
	if value, ok := args[param.Name]; ok && value != nil {
		return value
	}

	// If the parameter is required but not provided, return nil (let the upper layer handle the error)
	if param.Required {
		return nil
	}

	// Return the default value
	return param.Default
}

// formatParamValue formats a parameter value
func (e *Executor) formatParamValue(param config.ParameterConfig, value interface{}) string {
	switch param.Type {
	case "bool":
		// Booleans should be handled by the upper layer; this should not be called here
		if boolVal, ok := value.(bool); ok {
			return fmt.Sprintf("%v", boolVal)
		}
		return "false"
	case "array":
		// Array: convert to a comma-separated string
		if arr, ok := value.([]interface{}); ok {
			strs := make([]string, 0, len(arr))
			for _, item := range arr {
				strs = append(strs, fmt.Sprintf("%v", item))
			}
			return strings.Join(strs, ",")
		}
		return fmt.Sprintf("%v", value)
	case "object":
		// Object/dictionary: serialize to a JSON string
		if jsonBytes, err := json.Marshal(value); err == nil {
			return string(jsonBytes)
		}
		// If JSON serialization fails, fall back to the default format
		return fmt.Sprintf("%v", value)
	default:
		formattedValue := fmt.Sprintf("%v", value)
		// Special case: for the ports parameter (usually nmap-style port parameters), clean up spaces
		// nmap does not accept spaces in a port list, e.g. "80,443, 22" should become "80,443,22"
		if param.Name == "ports" {
			// Remove all spaces but keep commas and other characters
			formattedValue = strings.ReplaceAll(formattedValue, " ", "")
		}
		return formattedValue
	}
}

// IsBackgroundShellCommand detects whether a command is a fully background command (ends with a standalone &, not inside quotes).
// command1 & command2 is not fully background (command2 still runs in the foreground).
func IsBackgroundShellCommand(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}
	positions := findStandaloneAmpersandPositions(command)
	if len(positions) == 0 {
		return false
	}
	last := positions[len(positions)-1]
	afterAmpersand := strings.TrimSpace(command[last+1:])
	if afterAmpersand != "" {
		return false
	}
	beforeAmpersand := strings.TrimSpace(command[:last])
	return beforeAmpersand != ""
}

// executeSystemCommand executes a system command
func (e *Executor) executeSystemCommand(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
	if rerr := e.refuseHostExecInDocker("exec"); rerr != nil {
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: rerr.Error()}}, IsError: true}, nil
	}
	// Get the command
	command, ok := args["command"].(string)
	if !ok {
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: "Error: missing command parameter",
				},
			},
			IsError: true,
		}, nil
	}

	if command == "" {
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: "Error: command parameter cannot be empty",
				},
			},
			IsError: true,
		}, nil
	}

	// Security check: log the executed command
	e.logger.Warn("executing system command",
		zap.String("command", command),
	)

	command = PrepareShellCommandForExecute(command)

	// Get the shell type (optional, default sh)
	shell := "sh"
	if s, ok := args["shell"].(string); ok && s != "" {
		shell = s
	}

	// Get the working directory (optional)
	workDir := ""
	if wd, ok := args["workdir"].(string); ok && wd != "" {
		workDir = wd
	}

	// Detect whether this is a background command (contains an & symbol, but not inside quotes)
	isBackground := IsBackgroundShellCommand(command)

	// Build the command
	var cmd *exec.Cmd
	if workDir != "" {
		cmd = exec.CommandContext(ctx, shell, "-c", command)
		cmd.Dir = workDir
	} else {
		cmd = exec.CommandContext(ctx, shell, "-c", command)
	}
	ConfigureShellCmdForAgentExecute(cmd)

	// Execute the command
	e.logger.Info("executing system command",
		zap.String("command", command),
		zap.String("shell", shell),
		zap.String("workdir", workDir),
		zap.Bool("isBackground", isBackground),
	)

	if isBackground {
		if rerr := e.refuseHostExecInDocker("exec (background)"); rerr != nil {
			return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: rerr.Error()}}, IsError: true}, nil
		}
		job := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(command), "&"))
		session, err := StartManagedBackground(ctx, shell, job, workDir)
		if err != nil {
			return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: fmt.Sprintf("background command failed to start: %v", err)}}, IsError: true}, nil
		}
		return &mcp.ToolResult{Content: []mcp.Content{{Type: "text", Text: fmt.Sprintf("Background command started\nCommand: %s\nProcess group ID: %d\n\nThe background process is managed by the current task and is cleaned up automatically when the task ends.", command, session.rootPID)}}}, nil
	}

	// Non-background command: wait for output
	var output string
	var err error
	spill := e.spillOptsFromContext(ctx)
	// If the upper layer provided a tool output incremental callback, or we are inside an MCP execution, read streaming while executing.
	if cb, ok := ctx.Value(ToolOutputCallbackCtxKey).(ToolOutputCallback); (ok && cb != nil) || mcp.MCPExecutionIDFromContext(ctx) != "" {
		cb = e.wrapToolOutputCallback(ctx, cb)
		output, err = streamCommandOutput(ctx, cmd, cb, ResolveShellNoOutputTimeoutSeconds(e.shellNoOutputTimeoutSec), e.toolOutputMaxBytes, spill)
		if err != nil && shouldRetryWithPTY(output) {
			e.logger.Info("system command requires a TTY, retrying with PTY")
			cmd2 := exec.CommandContext(ctx, shell, "-c", command)
			if workDir != "" {
				cmd2.Dir = workDir
			}
			ConfigureShellCmdForAgentExecute(cmd2)
			output, err = runCommandWithPTY(ctx, cmd2, cb, e.toolOutputMaxBytes, spill)
		}
	} else {
		output, err = combinedOutputCancellableWithLimit(ctx, cmd, e.toolOutputMaxBytes, spill)
		if err != nil && shouldRetryWithPTY(output) {
			e.logger.Info("system command requires a TTY, retrying with PTY")
			cmd2 := exec.CommandContext(ctx, shell, "-c", command)
			if workDir != "" {
				cmd2.Dir = workDir
			}
			ConfigureShellCmdForAgentExecute(cmd2)
			output, err = runCommandWithPTY(ctx, cmd2, nil, e.toolOutputMaxBytes, spill)
		}
	}
	if err != nil {
		e.logger.Error("system command execution failed",
			zap.String("command", command),
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return &mcp.ToolResult{
			Content: []mcp.Content{
				{
					Type: "text",
					Text: FormatCommandFailureFromErr(err, output),
				},
			},
			IsError: true,
		}, nil
	}

	e.logger.Info("system command executed successfully",
		zap.String("command", command),
		zap.String("output_length", fmt.Sprintf("%d", len(output))),
	)

	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: string(output),
			},
		},
		IsError: false,
	}, nil
}

// combinedOutputCancellable behaves like cmd.CombinedOutput (stdout/stderr written to in-memory buffers),
// but on ctx cancellation terminateCmdTree kills the whole process tree.
// The non-streaming path does not use dual-stream pipe fan-in, to avoid a deadlock when stderr fills the pipe buffer and blocks stdout.
// Idle-output detection is handled by the upper-layer agent.tool_timeout_minutes; the original CombinedOutput semantics are unchanged.
func combinedOutputCancellable(ctx context.Context, cmd *exec.Cmd) (string, error) {
	return combinedOutputCancellableWithLimit(ctx, cmd, 0, tooloutput.SpillOpts{})
}

func combinedOutputCancellableWithLimit(ctx context.Context, cmd *exec.Cmd, maxBytes int, spill tooloutput.SpillOpts) (string, error) {
	var tee *tooloutput.Tee
	if maxBytes > 0 {
		tee = tooloutput.NewTee(spill)
		defer func() { _ = tee.Close() }()
	}
	stdoutBuf := newBoundedOutputCollector(maxBytes, tee)
	stderrBuf := newBoundedOutputCollector(maxBytes, tee)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	session, err := StartShellSessionContext(ctx, cmd)
	if err != nil {
		return "", err
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			TerminateShellCmdSession(session)
		case <-stopWatch:
		}
	}()
	defer close(stopWatch)

	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		waitErr = <-done
		return finalizeJoinedBoundedOutputs(stdoutBuf, stderrBuf, maxBytes, tee), ctx.Err()
	}
	return finalizeJoinedBoundedOutputs(stdoutBuf, stderrBuf, maxBytes, tee), waitErr
}

func joinCommandOutput(stdout, stderr string) string {
	if stderr == "" {
		return stdout
	}
	if stdout == "" {
		return stderr
	}
	return stdout + stderr
}

type boundedOutputCollector struct {
	builder   strings.Builder
	maxBytes  int
	seenBytes int
	truncated bool
	tee       *tooloutput.Tee
}

func newBoundedOutputCollector(maxBytes int, tee *tooloutput.Tee) *boundedOutputCollector {
	return &boundedOutputCollector{maxBytes: maxBytes, tee: tee}
}

func (b *boundedOutputCollector) Write(p []byte) (int, error) {
	b.WriteStringLimited(string(p))
	return len(p), nil
}

func (b *boundedOutputCollector) WriteStringLimited(s string) string {
	if b == nil {
		return ""
	}
	if b.tee != nil {
		_, _ = b.tee.Write([]byte(s))
	}
	if b.maxBytes <= 0 {
		b.seenBytes += len(s)
		b.builder.WriteString(s)
		return s
	}
	b.seenBytes += len(s)
	if b.builder.Len() >= b.maxBytes {
		b.truncated = true
		return ""
	}
	remaining := b.maxBytes - b.builder.Len()
	if len(s) <= remaining {
		b.builder.WriteString(s)
		return s
	}
	kept := truncateStringBytes(s, remaining)
	b.builder.WriteString(kept)
	b.truncated = true
	return kept
}

func (b *boundedOutputCollector) String() string {
	if b == nil {
		return ""
	}
	return b.builder.String()
}

func finalizeJoinedBoundedOutputs(stdout, stderr *boundedOutputCollector, maxBytes int, tee *tooloutput.Tee) string {
	if tee != nil {
		_ = tee.Close()
	}
	truncated := (stdout != nil && stdout.truncated) || (stderr != nil && stderr.truncated)
	seen := 0
	if stdout != nil {
		seen += stdout.seenBytes
	}
	if stderr != nil {
		seen += stderr.seenBytes
	}
	joined := joinCommandOutput(
		func() string {
			if stdout == nil {
				return ""
			}
			return stdout.String()
		}(),
		func() string {
			if stderr == nil {
				return ""
			}
			return stderr.String()
		}(),
	)
	if maxBytes > 0 && !truncated && len(joined) > maxBytes {
		truncated = true
		seen = len(joined)
	}
	path := ""
	if tee != nil {
		path = tee.Path()
	}
	if truncated && maxBytes > 0 {
		if path != "" {
			return tooloutput.FormatPersistedFromFile(path, seen, maxBytes)
		}
		if len(joined) > maxBytes {
			return truncateStringBytes(joined, maxBytes)
		}
		return joined
	}
	if path != "" {
		_ = os.Remove(path)
	}
	if maxBytes > 0 && len(joined) > maxBytes {
		return truncateStringBytes(joined, maxBytes)
	}
	return joined
}

func finalizeBoundedOutput(collector *boundedOutputCollector, maxBytes int, tee *tooloutput.Tee) string {
	if tee != nil {
		_ = tee.Close()
	}
	if collector == nil {
		return ""
	}
	path := ""
	if tee != nil {
		path = tee.Path()
	}
	if collector.truncated && maxBytes > 0 {
		if path != "" {
			return tooloutput.FormatPersistedFromFile(path, collector.seenBytes, maxBytes)
		}
		return truncateStringBytes(collector.String(), maxBytes)
	}
	if path != "" {
		_ = os.Remove(path)
	}
	out := collector.String()
	if maxBytes > 0 && len(out) > maxBytes {
		return tooloutput.BoundWithSpill(out, maxBytes, tooloutput.SpillOpts{})
	}
	return out
}

func limitOutputString(s string, maxBytes int, spill tooloutput.SpillOpts) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	return tooloutput.BoundWithSpill(s, maxBytes, spill)
}

func truncateStringBytes(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	if cut <= 0 {
		return ""
	}
	return s[:cut]
}

// streamCommandOutput reads command stdout/stderr while calling back as data arrives.
// It uses fixed-size chunk reads so line-based reads don't block forever on output without newlines; ctx cancellation kills the process tree.
func streamCommandOutput(ctx context.Context, cmd *exec.Cmd, cb ToolOutputCallback, noOutputSec int, maxBytes int, spill tooloutput.SpillOpts) (string, error) {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		_ = stdoutPipe.Close()
		return "", err
	}
	session, err := StartShellSessionContext(ctx, cmd)
	if err != nil {
		_ = stdoutPipe.Close()
		_ = stderrPipe.Close()
		return "", err
	}

	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			TerminateShellCmdSession(session)
		case <-stopWatch:
		}
	}()
	defer close(stopWatch)

	readStop := make(chan struct{})
	defer close(readStop)
	chunks := make(chan string, 64)
	var wg sync.WaitGroup
	readFn := func(r io.Reader) {
		defer wg.Done()
		buf := make([]byte, 8192)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				select {
				case chunks <- string(buf[:n]):
				case <-readStop:
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}

	wg.Add(2)
	go readFn(stdoutPipe)
	go readFn(stderrPipe)

	go func() {
		wg.Wait()
		close(chunks)
	}()

	tee := (*tooloutput.Tee)(nil)
	if maxBytes > 0 {
		tee = tooloutput.NewTee(spill)
		defer func() { _ = tee.Close() }()
	}
	outBuilder := newBoundedOutputCollector(maxBytes, tee)
	var deltaBuilder strings.Builder
	lastFlush := time.Now()

	flush := func() {
		if deltaBuilder.Len() == 0 {
			return
		}
		if cb != nil {
			cb(deltaBuilder.String())
		}
		deltaBuilder.Reset()
		lastFlush = time.Now()
	}

	idleWatch := NewShellInactivityWatch(noOutputSec)
	if idleWatch != nil {
		defer idleWatch.Stop()
	}

	fireInactivity := func() {
		TerminateShellCmdSession(session)
		msg := ShellNoOutputTimeoutMessage(idleWatch.Sec)
		msg = outBuilder.WriteStringLimited(msg)
		if cb != nil {
			cb(msg)
		}
		_ = session.Wait()
	}

chunksLoop:
	for {
		var idleCh <-chan struct{}
		if idleWatch != nil {
			idleCh = idleWatch.Expired
		}
		select {
		case <-ctx.Done():
			TerminateShellCmdSession(session)
			flush()
			_ = session.Wait()
			return outBuilder.String(), ctx.Err()
		case <-idleCh:
			fireInactivity()
			return finalizeBoundedOutput(outBuilder, maxBytes, tee), fmt.Errorf("shell inactivity timeout (%ds)", idleWatch.Sec)
		case chunk, ok := <-chunks:
			if !ok {
				break chunksLoop
			}
			if chunk != "" && idleWatch != nil {
				idleWatch.Bump()
			}
			keptChunk := outBuilder.WriteStringLimited(chunk)
			deltaBuilder.WriteString(keptChunk)
			if deltaBuilder.Len() >= 2048 || time.Since(lastFlush) >= 200*time.Millisecond {
				flush()
			}
		}
	}
	flush()

	// Wait for the command to finish and return the final exit status
	waitErr := session.Wait()
	return finalizeBoundedOutput(outBuilder, maxBytes, tee), waitErr
}

// applyDefaultTerminalEnv fills in common terminal environment variables for external tools.
// Note: this does not create a TTY; it only reduces "odd layout / detection failure" issues in some tools in non-interactive environments.
func applyDefaultTerminalEnv(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	// Inherit the current process environment only when Env is not explicitly set
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = ApplyNonInteractivePagerEnv(cmd.Env)
	// If the user has already set TERM/COLUMNS/LINES, do not override
	has := func(k string) bool {
		prefix := k + "="
		for _, e := range cmd.Env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	if !has("TERM") {
		cmd.Env = append(cmd.Env, "TERM=xterm-256color")
	}
	if !has("COLUMNS") {
		cmd.Env = append(cmd.Env, "COLUMNS=256")
	}
	if !has("LINES") {
		cmd.Env = append(cmd.Env, "LINES=40")
	}
}

func shouldRetryWithPTY(output string) bool {
	o := strings.ToLower(output)
	// Common autorecon / python termios error
	if strings.Contains(o, "inappropriate ioctl for device") {
		return true
	}
	if strings.Contains(o, "termios.error") {
		return true
	}
	// Fallback: stdin is not a tty
	if strings.Contains(o, "not a tty") {
		return true
	}
	return false
}

// runCommandWithPTY allocates a PTY for the child process, for tools that need an interactive terminal (such as autorecon).
// If cb != nil, incremental output is continuously passed to the callback (for SSE).
func runCommandWithPTY(ctx context.Context, cmd *exec.Cmd, cb ToolOutputCallback, maxBytes int, spill tooloutput.SpillOpts) (string, error) {
	if runtime.GOOS == "windows" {
		// The PTY approach is Unix-like; Windows uses the original logic
		if cb != nil {
			return streamCommandOutput(ctx, cmd, cb, 0, maxBytes, spill)
		}
		_ = prepareShellCmdSession(cmd)
		return combinedOutputCancellableWithLimit(ctx, cmd, maxBytes, spill)
	}

	_ = prepareShellCmdSession(cmd)
	var ptmx *os.File
	session, err := startShellSessionContext(ctx, cmd, func() error {
		var startErr error
		ptmx, startErr = pty.Start(cmd)
		return startErr
	})
	if err != nil {
		return "", err
	}
	defer func() { _ = ptmx.Close() }()

	// Terminate the child process as soon as possible when ctx is cancelled
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = ptmx.Close() // trigger read exit
			session.Terminate()
		case <-done:
		}
	}()
	defer close(done)

	tee := (*tooloutput.Tee)(nil)
	if maxBytes > 0 {
		tee = tooloutput.NewTee(spill)
		defer func() { _ = tee.Close() }()
	}
	outBuilder := newBoundedOutputCollector(maxBytes, tee)
	var deltaBuilder strings.Builder
	lastFlush := time.Now()
	flush := func() {
		if cb == nil || deltaBuilder.Len() == 0 {
			deltaBuilder.Reset()
			lastFlush = time.Now()
			return
		}
		cb(deltaBuilder.String())
		deltaBuilder.Reset()
		lastFlush = time.Now()
	}

	buf := make([]byte, 4096)
	for {
		n, readErr := ptmx.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			// Normalize line endings to \n to avoid front-end layout misalignment
			chunk = strings.ReplaceAll(chunk, "\r\n", "\n")
			chunk = strings.ReplaceAll(chunk, "\r", "\n")
			keptChunk := outBuilder.WriteStringLimited(chunk)
			deltaBuilder.WriteString(keptChunk)
			if deltaBuilder.Len() >= 2048 || time.Since(lastFlush) >= 200*time.Millisecond {
				flush()
			}
		}
		if readErr != nil {
			break
		}
	}
	flush()

	waitErr := session.Wait()
	return finalizeBoundedOutput(outBuilder, maxBytes, tee), waitErr
}

// executeInternalTool executes an internal tool (does not execute external commands)
func (e *Executor) executeInternalTool(ctx context.Context, toolName string, command string, args map[string]interface{}) (*mcp.ToolResult, error) {
	internalToolType := strings.TrimPrefix(command, "internal:")
	e.logger.Warn("unknown internal tool",
		zap.String("toolName", toolName),
		zap.String("internalToolType", internalToolType),
	)
	return &mcp.ToolResult{
		Content: []mcp.Content{
			{
				Type: "text",
				Text: fmt.Sprintf("Error: unknown internal tool type: %s", internalToolType),
			},
		},
		IsError: true,
	}, nil
}

// buildInputSchema builds the input schema
func (e *Executor) buildInputSchema(toolConfig *config.ToolConfig) map[string]interface{} {
	schema := map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
		"required":   []string{},
	}

	// If parameters are defined in the config, prefer those parameter definitions
	if len(toolConfig.Parameters) > 0 {
		properties := make(map[string]interface{})
		required := []string{}

		for _, param := range toolConfig.Parameters {
			// Skip parameters with an empty name (avoids an illegal schema caused by YAML name: null or empty)
			if strings.TrimSpace(param.Name) == "" {
				e.logger.Debug("skipping unnamed parameter",
					zap.String("tool", toolConfig.Name),
					zap.String("type", param.Type),
				)
				continue
			}
			// Convert the type to the OpenAI/JSON Schema standard type (empty type defaults to string)
			openAIType := e.convertToOpenAIType(param.Type)

			prop := map[string]interface{}{
				"type":        openAIType,
				"description": param.Description,
			}

			// JSON Schema/OpenAI requires array types to include items, otherwise the API reports invalid_function_parameters
			if openAIType == "array" {
				itemType := strings.TrimSpace(param.ItemType)
				if itemType == "" {
					itemType = "string"
				}
				prop["items"] = map[string]interface{}{
					"type": e.convertToOpenAIType(itemType),
				}
			}

			// Add default value
			if param.Default != nil {
				prop["default"] = param.Default
			}

			// Add enum options
			if len(param.Options) > 0 {
				prop["enum"] = param.Options
			}

			properties[param.Name] = prop

			// Add to the required parameter list
			if param.Required {
				required = append(required, param.Name)
			}
		}

		schema["properties"] = properties
		schema["required"] = required
		return schema
	}

	// If no parameter config is defined, return an empty schema
	// In this case the tool may only use fixed parameters (args field)
	// or parameters must be defined through the YAML configuration file
	e.logger.Warn("tool has no parameter config; returning empty schema",
		zap.String("tool", toolConfig.Name),
	)
	return schema
}

// convertToOpenAIType converts the configured type to an OpenAI/JSON Schema standard type
func (e *Executor) convertToOpenAIType(configType string) string {
	// Empty or null types are treated uniformly as string, to avoid an illegal schema causing tool calls to fail
	if strings.TrimSpace(configType) == "" {
		return "string"
	}
	switch configType {
	case "bool":
		return "boolean"
	case "int", "integer":
		return "number"
	case "float", "double":
		return "number"
	case "string", "array", "object":
		return configType
	default:
		// Default: return the original type but log a warning
		e.logger.Warn("unknown parameter type, using original type",
			zap.String("type", configType),
		)
		return configType
	}
}

// getExitCode extracts the exit code from an error; returns nil if it is not an ExitError
func getExitCode(err error) *int {
	if err == nil {
		return nil
	}
	if exitError, ok := err.(*exec.ExitError); ok {
		if exitError.ProcessState != nil {
			exitCode := exitError.ExitCode()
			return &exitCode
		}
	}
	return nil
}

// getExitCodeValue extracts the exit code value from an error; returns -1 if it is not an ExitError
func getExitCodeValue(err error) int {
	if code := getExitCode(err); code != nil {
		return *code
	}
	return -1
}
