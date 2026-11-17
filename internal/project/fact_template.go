package project

import (
	"fmt"
	"strings"

	"veritysec/internal/projectprompt"
)

// fact category constants (the category field written by upsert_project_fact).
const (
	FactCategoryTarget   = "target"
	FactCategoryAuth     = "auth"
	FactCategoryInfra    = "infra"
	FactCategoryBusiness = "business"
	FactCategoryFinding  = "finding"
	FactCategoryChain    = "chain"
	FactCategoryExploit  = "exploit"
	FactCategoryPOC      = "poc"
	FactCategoryNote     = "note"
)

// RequiresAttackChainBody determines whether this fact should carry a reproducible attack chain / exploit detail (written in body, not only summary).
func RequiresAttackChainBody(category, factKey string) bool {
	c := strings.ToLower(strings.TrimSpace(category))
	switch c {
	case FactCategoryFinding, FactCategoryChain, FactCategoryExploit, FactCategoryPOC, "vuln":
		return true
	}
	key := strings.ToLower(strings.TrimSpace(factKey))
	for _, prefix := range []string{"finding/", "chain/", "exploit/", "poc/"} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// IsSparseFactBody returns true when the body of an attack-chain fact is too short or lacks key sections (soft validation; does not block writes).
func IsSparseFactBody(category, factKey, body string) bool {
	if !RequiresAttackChainBody(category, factKey) {
		return false
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return true
	}
	lower := strings.ToLower(body)
	// should contain at least one reproducible clue: steps/request/command/code block
	// (both the current English keywords and the legacy Chinese ones are checked, since
	// existing stored fact bodies may still use the old wording)
	hasSteps := strings.Contains(lower, "attack chain") || strings.Contains(lower, "## attack") ||
		strings.Contains(lower, "## exploit") || strings.Contains(lower, "## poc")
	hasHTTP := strings.Contains(lower, "```http") || strings.Contains(lower, "```bash") ||
		strings.Contains(lower, "curl ") || strings.Contains(lower, "get ") || strings.Contains(lower, "post ")
	hasReq := strings.Contains(lower, "request") || strings.Contains(lower, "response") || strings.Contains(lower, "payload")
	// without attack chain/POC/request structural clues, treat as a conclusion-only description (regardless of length)
	return !(hasSteps || hasHTTP || hasReq)
}

// FactBodyTemplate returns the suggested body Markdown skeleton for the category (for the Agent to fill in real content).
func FactBodyTemplate(category, factKey string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(factKey)), "artifact/") {
		return artifactFactBodyTemplate
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(factKey)), "test/") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(factKey)), "negative/") {
		return testResultFactBodyTemplate
	}
	if RequiresAttackChainBody(category, factKey) {
		return attackChainFactBodyTemplate
	}
	return envFactBodyTemplate
}

const attackChainFactBodyTemplate = `## Conclusion (verifiable, one line)
<Do not just write "vulnerability exists"; state the type + location + trigger condition>

## Target and entry point
- Target: <URL / IP:Port / hostname>
- Entry point: <path / endpoint / parameter>
- Preconditions: <anonymous / role / cookie / other dependency>

## Attack chain (step by step, reproducible)
1. <reconnaissance/discovery>
2. <exploitation/trigger>
3. <proof of impact (file read, RCE echo, unauthorized data, etc.)>

## Exploit / POC
### Request
` + "```http\n<METHOD> <path> HTTP/1.1\nHost: ...\n...\n\n<body>\n```" + `

### Response / observation
<key response excerpt, status code, differences>

### Command / script (if any)
` + "```bash\n<command>\n```" + `

## Key evidence
- <tool output summary / screenshot path / conversation or message ID>

## Related
- related_vulnerability_id: <optional, matches the id from record_vulnerability>
- links (upsert parameter): [{ "from": "<fact_key>", "type": "discovered_on|..." }] (from → current fact)
- Dependent fact (human-readable mirror of body): <fact_key, e.g. auth/session_cookie>

## Notes and uncertainty
<unverified assumptions, environment differences, bypass attempts>`

const envFactBodyTemplate = `## Summary
<the core takeaway of this fact>

## Details
<port/version/path/credential characteristics/business rules, etc.>

## Source and evidence
<command output, response excerpt, discovery time>

## Related
- Related fact_key: <optional>`

// FactRecordingGuidanceBlock system prompt block: requires facts to record attack chain context, not just conclusions.
func FactRecordingGuidanceBlock() string {
	return projectprompt.FactRecordingGuidanceBlock()
}

// SparseBodyWarning tool-return hint when an attack-chain fact body is insufficient (does not block saving).
func SparseBodyWarning(category, factKey string) string {
	if !IsSparseFactBody(category, factKey, "") {
		return ""
	}
	return fmt.Sprintf(
		"\n\n⚠ Notice: category=%q / fact_key=%q is an attack-chain-type fact, but the body is empty or too brief. Please supply the full attack chain and POC (see template) so the audit can reproduce it later.\nSuggested body skeleton:\n%s",
		category, factKey, FactBodyTemplate(category, factKey),
	)
}

// SparseBodyWarningIfNeeded appends a warning based on the actual body.
func SparseBodyWarningIfNeeded(category, factKey, body string) string {
	if !IsSparseFactBody(category, factKey, body) {
		return ""
	}
	return SparseBodyWarning(category, factKey)
}

const artifactFactBodyTemplate = `## Result and verification status
<purpose, applicable target/entry point; verified success / failure / unverified>

## File and invocation
- Path relative to the project working directory: artifacts/<filename>
- Dependencies and version: <dependency files, install/runtime environment>
- Invocation and variable parameters: <command, input/output; reference auth/* for credentials>

## Verification evidence
<verification time, raw command/output, applicable conditions; do not infer success merely from the file existing>

## Related
<source conversation, dependent fact_key, related_vulnerability_id>`

const testResultFactBodyTemplate = `## Conditions tested
<target, entry point, parameters, identity/auth, version, test time>

## Method and evidence
<request/command, response differences, tool output; errors/timeouts must be noted separately>

## Conclusion and boundary
<success / not found under tested conditions / blocked / unverified; do not extend to untested entry points>

## Retest trigger conditions
<target/entry point/identity/version change, insufficient original evidence, or user-requested retest>

## Related
<source conversation, script artifact/*, related fact/vulnerability IDs>`
