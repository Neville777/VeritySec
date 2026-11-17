package security

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// FormatCommandFailureResult matches the exec tool ToolResult text (without ToolErrorPrefix).
func FormatCommandFailureResult(exitCode int, output string) string {
	output = strings.TrimSpace(output)
	errMsg := fmt.Sprintf("exit status %d", exitCode)
	if output == "" {
		return fmt.Sprintf("Command execution failed: %s", errMsg)
	}
	if strings.HasPrefix(output, "Command execution failed:") {
		return output
	}
	return fmt.Sprintf("Command execution failed: %s\nOutput: %s", errMsg, output)
}

// FormatCommandFailureFromErr builds the unified failure text from an error returned by exec/execute (used as the IsError body).
func FormatCommandFailureFromErr(err error, output string) string {
	if err == nil {
		return strings.TrimSpace(output)
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return FormatCommandFailureResult(exitError.ExitCode(), output)
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return fmt.Sprintf("Command execution failed: %v", err)
	}
	if strings.HasPrefix(output, "Command execution failed:") {
		return output
	}
	return fmt.Sprintf("Command execution failed: %v\nOutput: %s", err, output)
}

// ExecuteFailureStatusLine is the single status line appended when a streaming execute ends (output body was already pushed in the stream).
func ExecuteFailureStatusLine(exitCode int) string {
	return fmt.Sprintf("\nCommand execution failed: exit status %d", exitCode)
}

// IsCommandFailureResult reports whether the tool result text indicates a non-zero command exit (aligns isError for execute / exec).
func IsCommandFailureResult(content string) bool {
	return strings.Contains(content, "Command execution failed:")
}

// IsLegacyShellExitNoise filters redundant exit-code lines from the legacy shell stream.
func IsLegacyShellExitNoise(s string) bool {
	trimmed := strings.TrimSpace(s)
	return strings.HasPrefix(trimmed, "command exited with non-zero code ")
}
