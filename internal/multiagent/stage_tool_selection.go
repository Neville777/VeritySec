package multiagent

import "strings"

// Stage-based tool selection. For a conversation attached to an engagement, the model is sent the
// platform tools plus the tools listed for the engagement's current stage. Every other tool stays
// reachable through tool search. This only changes which definitions the model sees. Scope checks,
// approvals and every other authorization still run on each call inside the tool bridge.

// stageResolver maps a conversation ID to the name of its engagement's current stage ("" if none).
// The app sets it at startup with SetConversationStageResolver.
var stageResolver func(conversationID string) string

// SetConversationStageResolver installs the function that reports a conversation's current stage.
func SetConversationStageResolver(fn func(conversationID string) string) {
	stageResolver = fn
}

// platformToolNames are always sent: they record platform state or read evidence the agent produced.
var platformToolNames = []string{
	"engagement_stage", "record_vulnerability", "create_asset", "query_assets", "get_asset",
	"web_search", "web_fetch", "read_file", "read_evidence", "query_execution_result",
	"list_tool_installs", "tool_risk_check", "wait_tool_execution", "get_tool_execution",
}

// stageToolNames lists the tool recipes that are useful in each stage.
var stageToolNames = map[string][]string{
	"AUTHORISATION": {},
	"RECONNAISSANCE": {
		"subfinder", "amass", "dnsenum", "fierce", "nbtscan", "arp-scan", "katana", "gau",
		"waybackurls", "nmap", "masscan", "wafw00f", "fofa_search", "shodan_search",
		"quake_search", "virustotal_search", "zoomeye_search",
	},
	"ASSET_DISCOVERY": {
		"nmap", "masscan", "arp-scan", "nbtscan", "dnsenum", "subfinder", "katana",
		"enum4linux-ng", "netexec", "smbmap", "rpcclient",
	},
	"ENUMERATION": {
		"katana", "arjun", "dirsearch", "gobuster", "ffuf", "paramspider", "nikto", "wafw00f",
		"http-framework-test", "graphql-scanner", "jwt-analyzer", "api-schema-analyzer", "x8",
	},
	"VULNERABILITY_ASSESSMENT": {
		"nuclei", "nikto", "sqlmap", "dalfox", "xsser", "zap", "jaeles", "wpscan",
		"http-framework-test",
	},
	"FINDING_VALIDATION": {"sqlmap", "dalfox", "http-framework-test", "nuclei"},
	"IMPACT_ASSESSMENT":  {},
	"REPORT_GENERATION":  {},
}

// stageVisibleToolNames returns the always-visible tool names for a conversation, or nil when the
// stage cannot be resolved (the caller then keeps its configured list).
func stageVisibleToolNames(conversationID string) []string {
	if stageResolver == nil || strings.TrimSpace(conversationID) == "" {
		return nil
	}
	stage := strings.ToUpper(strings.TrimSpace(stageResolver(conversationID)))
	if stage == "" {
		stage = "RECONNAISSANCE"
	}
	extra, known := stageToolNames[stage]
	if !known {
		return nil
	}
	out := make([]string, 0, len(platformToolNames)+len(extra))
	out = append(out, platformToolNames...)
	out = append(out, extra...)
	return out
}
