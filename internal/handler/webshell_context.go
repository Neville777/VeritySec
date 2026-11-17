package handler

import (
	"strings"

	"veritysec/internal/database"
)

// WebshellSkillHintDefault: Skills guidance shared by the conversation page and the Eino single-agent, placed at the end of the webshell context,
// for reference when the AI chooses the skill loading entry.
const WebshellSkillHintDefault = "For Skills packages, use the built-in 'skill' tool in a 'multi-agent / Eino DeepAgent' session to load them progressively."

// WebshellSkillHintMultiAgent: Skills guidance used during the multi-agent / Eino multi-agent preparation phase
const WebshellSkillHintMultiAgent = "For Skills packages, use the built-in 'skill' tool of Eino multi-agent."

// webshellAssistantToolList: the tool list the AI assistant may use in the WebShell context (shown to the model).
// Note: this is only a display string; the real permission restriction is set in the roleTools slice passed by the caller.
const webshellAssistantToolList = "webshell_exec, webshell_file_list, webshell_file_read, webshell_file_write, record_vulnerability, list_vulnerabilities, get_vulnerability, upsert_project_fact, get_project_fact, list_project_facts, search_project_facts, deprecate_project_fact, restore_project_fact, list_knowledge_risk_types, search_knowledge_base"

// BuildWebshellAssistantContext assembles the AI assistant's context prompt from the connection info and the user's original message.
// The context includes: connection ID, note, target OS (and the matching command set suggestions), response encoding, available tool list, skills loading entry,
// and the final user request. The caller only needs to decide the skillHint text (the default is WebshellSkillHintDefault).
//
// This logic was extracted into a shared function to avoid copy-pasting it in several places such as agent.go / multi_agent_prepare.go,
// and to ensure that when OS / encoding text is updated, only one place needs to change, be tested once, and takes effect everywhere.
func BuildWebshellAssistantContext(conn *database.WebShellConnection, skillHint, userMsg string) string {
	if conn == nil {
		// Fallback: the caller guarantees conn is non-nil; this is only a defensive return of the original message
		return userMsg
	}
	remark := conn.Remark
	if remark == "" {
		remark = conn.URL
	}

	targetOS := resolveWebshellOS(conn.OS, conn.Type) // Normalize to "linux" / "windows"
	encoding := normalizeWebshellEncoding(conn.Encoding)
	if skillHint == "" {
		skillHint = WebshellSkillHintDefault
	}

	var b strings.Builder
	b.Grow(512 + len(userMsg))

	b.WriteString("[WebShell assistant context] Connection ID: ")
	b.WriteString(conn.ID)
	b.WriteString(", note: ")
	b.WriteString(remark)
	b.WriteByte('\n')

	// Target OS: state clearly which command sets the AI can and cannot use, to avoid it sending ls/cat/rm to Windows
	b.WriteString("- Target OS: ")
	b.WriteString(describeTargetOSForPrompt(targetOS))
	b.WriteByte('\n')

	// Response encoding: only stated explicitly when not auto; in auto mode the backend adapts, so the model is not disturbed
	if encHint := describeEncodingForPrompt(encoding); encHint != "" {
		b.WriteString("- Response encoding: ")
		b.WriteString(encHint)
		b.WriteByte('\n')
	}

	// Tool list and connection_id constraints: keep the existing wording, which the AI already knows
	b.WriteString("Available tools (use only when operating on this connection; set connection_id to \"")
	b.WriteString(conn.ID)
	b.WriteString("\"): ")
	b.WriteString(webshellAssistantToolList)
	b.WriteString(". Record as you go: upsert_project_fact for each new finding, record_vulnerability for each verified vulnerability; do not wait until the session ends.")
	b.WriteString(skillHint)
	b.WriteString("\n\nUser request: ")
	b.WriteString(userMsg)

	return b.String()
}

// describeTargetOSForPrompt returns the Chinese description of an OS, the recommended command set and counter-examples,
// the command list covers the 6 most common file management actions (view/read/delete/rename/create directory/find), so the AI can copy them directly.
func describeTargetOSForPrompt(targetOS string) string {
	switch targetOS {
	case "windows":
		return "Windows (recommended cmd/PowerShell: dir /a, type, del /q /f, move /y, md, ren;" +
			"To find files use `dir /s /b filter` or PowerShell `Get-ChildItem -Recurse`;" +
			"Avoid Unix commands such as ls / cat / rm / mv / find, otherwise they return `is not recognized as an internal or external command`)"
	case "linux":
		return "Linux/Unix (recommended sh/bash: ls -la, cat, rm -f, mv, mkdir -p;" +
			"To find files use `find /path -name '*pattern*'`;" +
			"Avoid Windows commands such as dir, type, del, move)"
	default:
		// In theory this path is never reached; resolveWebshellOS already falls back
		return "Unknown (run `uname || ver` to detect first, then decide the command set)"
	}
}

// describeEncodingForPrompt returns a human-readable description of the response encoding; auto returns an empty string to save tokens.
func describeEncodingForPrompt(encoding string) string {
	switch encoding {
	case "utf-8":
		return "UTF-8 (the target is natively UTF-8, no extra decoding needed)"
	case "gbk":
		return "GBK (Chinese Windows; the backend converts it to UTF-8 automatically; if many \\uFFFD replacement characters still appear, the command failed or the encoding was misdetected)"
	case "gb18030":
		return "GB18030 (the backend converts it to UTF-8 automatically)"
	default:
		return ""
	}
}
