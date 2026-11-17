package projectprompt

// ShellExecExecuteGuidanceSection is appended to single/multi-agent system prompts: division of labor between exec and execute (kept short).
func ShellExecExecuteGuidanceSection() string {
	return `Shell (exec/execute): prefer dedicated MCP tools when available; use exec for system commands (pipes, workdir, background &); use execute for scripts inside skills/ (with read_file, skill); split multi-step scans into separate calls, do not chain multiple scanners in a single shell command. Long scripts, request bodies or payloads must first be written to the session working directory with write_file, then run as short exec/execute commands; do not embed long content in the command argument. Downloads/temp files must be written to the "session working directory" specified in the system prompt, not /tmp.`
}

// ShellExecExecuteGuidanceReconSuffix is an optional one-line suffix for reconnaissance sub-agents.
func ShellExecExecuteGuidanceReconSuffix() string {
	return `Prefer dedicated MCP tools such as subfinder and amass for enumeration; do not chain long exec/execute pipelines.`
}
