// Package projectprompt provides project blackboard system prompt text (plain strings, no database dependency).
// Referenced by packages such as agent / multiagent, to avoid an agent → project import cycle that breaks gopls metadata.
package projectprompt

import (
	"strings"

	"veritysec/internal/mcp/builtin"
)

const (
	factRhythmCore              = "Do not wait until the session ends or wraps up to write everything in a batch. Each time you **confirm** a new finding (open ports/service versions, entry paths, auth state or credential characteristics, exploitable points or attack-surface changes), **immediately** call `upsert_project_fact` (the same fact_key overwrites and updates). Each time you **verify** a reproducible vulnerability (including POC/impact), **immediately** call `record_vulnerability`; the same finding may be recorded once as a fact and once as a vulnerability. Persist before moving on to the next step, so details are not lost after context compression. If no project is bound, state that the blackboard cannot be written and keep an evidence summary in this turn."
	factRhythmCoordinatorSuffix = "When a delegated task/sub-task returns new findings or vulnerabilities, the coordinator must write them promptly; do not assume the sub-agent already recorded them."
	factRhythmSubAgentSuffix    = "If the toolset lacks the tools above, end the deliverable with structured \"pending persistence\" entries (suggested fact_key, summary, body/POC key points) for the coordinator to write **immediately**."
)

// FactRecordingIncrementalRhythmMarkdown returns the record-while-testing rhythm (Markdown, aligned with agents/*.md and docs).
func FactRecordingIncrementalRhythmMarkdown(coordinator, subAgent bool) string {
	var b strings.Builder
	b.WriteString("- **Record while testing (mandatory rhythm)**: ")
	b.WriteString(factRhythmCore)
	if coordinator {
		b.WriteString(factRhythmCoordinatorSuffix)
	}
	if subAgent {
		b.WriteString(factRhythmSubAgentSuffix)
	}
	return b.String()
}

func factRecordingIncrementalRhythmBuiltin(coordinator, subAgent bool) string {
	var b strings.Builder
	b.WriteString("- **Record while testing (mandatory rhythm)**: Do not wait until the session ends or wraps up to write everything in a batch. Each time you **confirm** a new finding (open ports/service versions, entry paths, auth state or credential characteristics, exploitable points or attack-surface changes), **immediately** call ")
	b.WriteString(builtin.ToolUpsertProjectFact)
	b.WriteString(" (the same fact_key overwrites and updates). Each time you **verify** a reproducible vulnerability (including POC/impact), **immediately** call ")
	b.WriteString(builtin.ToolRecordVulnerability)
	b.WriteString("; the same finding may be recorded once as a fact and once as a vulnerability. Persist before moving on to the next step, so details are not lost after context compression. If no project is bound, state that the blackboard cannot be written and keep an evidence summary in this turn.")
	if coordinator {
		b.WriteString(factRhythmCoordinatorSuffix)
	}
	if subAgent {
		b.WriteString(factRhythmSubAgentSuffix)
	}
	return b.String()
}

func factEdgeRecordingGuidance() string {
	return `### Fact relationship edges (links)

- When writing **finding / chain / exploit / poc**, you **must** provide ` + "`links`" + ` in ` + "`upsert_project_fact`" + ` (**recommended ` + "`from`" + `**: the source fact points to the current fact, i.e. ` + "`from`" + ` → current ` + "`fact_key`" + `).
- **Minimum requirement**: a finding needs at least 1 edge with from=target/* + type=discovered_on (i.e. target → finding); to record an exploit on a finding, use from=exploit/* + type=exploits (i.e. exploit → finding).
- **Common types**: ` + "`discovered_on`" + ` (where it was found), ` + "`depends_on`" + ` (reproduction prerequisite), ` + "`leads_to`" + ` (knowledge progression), ` + "`enables`" + ` (expands attack surface), ` + "`exploits`" + ` (exploitation relationship), ` + "`contains`" + ` (asset containment), ` + "`part_of`" + ` (belongs to a chain/group), ` + "`supports`" + ` (evidence support).
- On update: **omit links to keep existing edges**; passing links **replaces** all relationship edges (from → current fact).
- A "dependent facts" paragraph in the body may coexist with links (for human readers); the structured relationships are defined by links.`
}

func factRecordingGuidanceBlock() string {
	return `### Fact writing guidelines (audit reproduction / knowledge retention)

- **summary**: a single index line that must cover "what + where + how to trigger/verify"; do not write only a conclusion (e.g. just "SQLi exists").
- **body**: the full reproducible context, written to the body field of ` + "`upsert_project_fact`" + `; the index does not include the body, so later sessions must retrieve it with ` + "`get_project_fact`" + `.
- **category / fact_key suggestions**:
  - Environment knowledge: ` + "`target/`" + `, ` + "`auth/`" + `, ` + "`infra/`" + `, ` + "`business/`" + ` (the environment template is enough for the body)
  - Findings and exploitation: ` + "`finding/`" + `, ` + "`chain/`" + `, ` + "`exploit/`" + `, ` + "`poc/`" + ` (you **must** fill the body using the attack-chain template: entry point, step-by-step attack chain, raw requests/responses or commands, evidence, related vulnerability ID)
- **Auto-continuation records**: ` + "`note/context-*`" + ` is a system-reserved session working summary, not a project-confirmed fact; do not overwrite that prefix with upsert_project_fact. By default the index and fact tools only provide the current session's continuation records, while ordinary project facts remain shared. For cross-session reference, explicitly use include_history=true with list_project_facts / search_project_facts / get_project_fact; list and search can use source_conversation_id to narrow the source. Historical results are labeled with source session, update time and "historical reference"; verify the current authorization, targets and credential validity, and do not automatically re-run old tasks or treat old summaries as confirmed findings. When an exact value is missing, read back by segments following the snapshot path in the body; do not guess the original value. The same session/agent updates the same key; to retain verified shared facts, use a separate key such as finding/auth and keep the source evidence.
- **Division of labor with vulnerability records**: ` + "`record_vulnerability`" + ` records deliverable findings; facts record **all context needed for reproduction** (including failed attempts, bypasses, dependent sessions); the same finding may be recorded once in each.
- When updating the same finding, keep the same ` + "`fact_key`" + ` and overwrite; do not scatter multiple keys, which causes context loss.`
}

// FactRecordingBlackboardSection is the complete system prompt block for the project blackboard and vulnerability records (shared by single- and multi-agent main agents).
func FactRecordingBlackboardSection(coordinatorDelegate bool) string {
	var b strings.Builder
	b.WriteString("## Project blackboard (facts) and vulnerability records (separate)\n\n")
	b.WriteString("If the current conversation is bound to a project, the system automatically injects a \"project blackboard index\" (only fact_key + summary). **When the summary is not enough, you must call ")
	b.WriteString(builtin.ToolGetProjectFact)
	b.WriteString("(fact_key) to get the body; do not invent details from the summary alone.**\n\n")
	b.WriteString(factRecordingIncrementalRhythmBuiltin(coordinatorDelegate, false))
	b.WriteString("\n\n")
	b.WriteString("- **Environment/target/auth knowledge** (not formal vulnerability entries): use ")
	b.WriteString(builtin.ToolUpsertProjectFact)
	b.WriteString("; the suggested fact_key is `category/slug` (e.g. target/primary_domain), and the same key overwrites and updates; the body records ports/versions/credential characteristics and evidence sources.\n")
	b.WriteString("- **Finding and exploitation context** (audit reproduction): suggested fact_key prefixes are finding/, chain/, exploit/, poc/; the **body is required** and must contain the full attack chain (entry point -> steps -> raw requests/responses or commands -> observed behavior -> related related_vulnerability_id); **do not write only a conclusion**; the summary is a one-line note of \"what + where + how to verify\".\n")
	b.WriteString("- **Deliverable vulnerabilities**: use ")
	b.WriteString(builtin.ToolRecordVulnerability)
	b.WriteString(", including title, severity, type, target, proof (POC), impact and remediation advice. Before recording, you may first use ")
	b.WriteString(builtin.ToolListVulnerabilities)
	b.WriteString(" to check for duplicates, and use ")
	b.WriteString(builtin.ToolGetVulnerability)
	b.WriteString("(id) for details (by default only the current project/session). After retesting an existing vulnerability, use update_vulnerability_status(id, status, retest_notes) to update the status and append evidence; do not record it again; if it cannot be verified, keep the original status.\n")
	b.WriteString("- The same finding may need to be recorded **once in each** (the fact holds the **full attack chain and exploit details** for reproduction; the vulnerability holds the formal finding). For false positives use ")
	b.WriteString(builtin.ToolDeprecateProjectFact)
	b.WriteString(" or the vulnerability status false_positive.\n")
	b.WriteString("- When there are many facts, search with ")
	b.WriteString(builtin.ToolListProjectFacts)
	b.WriteString(" / ")
	b.WriteString(builtin.ToolSearchProjectFacts)
	b.WriteString(".\n\n")
	b.WriteString(factEdgeRecordingGuidance())
	b.WriteString("\n\n")
	b.WriteString(factRecordingGuidanceBlock())
	b.WriteString("\n\nSeverity: critical / high / medium / low / info. Proof must include sufficient evidence (request/response, screenshots, command output, etc.).")
	return b.String()
}

// FactRecordingSubAgentSection: sub-agent record-while-testing (when no tools are available, outputs pending entries to persist).
func FactRecordingSubAgentSection() string {
	return "## Record while testing\n\n" + ProjectResultRecordingGuidance() + "\n\n" + factRecordingIncrementalRhythmBuiltin(false, true) + "\n"
}

// FactRecordingBlackboardSectionMarkdown is the Markdown equivalent of FactRecordingBlackboardSection (tool names are literals, for agents/*.md).
func FactRecordingBlackboardSectionMarkdown(coordinatorDelegate bool) string {
	var b strings.Builder
	b.WriteString("## Project blackboard (facts) and vulnerability records (separate)\n\n")
	b.WriteString("If the current conversation is bound to a project, the system automatically injects a \"project blackboard index\" (only `fact_key` + summary). **When the summary is not enough, you must call `get_project_fact(fact_key)` to get the body; do not invent details from the summary alone.**\n\n")
	b.WriteString(FactRecordingIncrementalRhythmMarkdown(coordinatorDelegate, false))
	b.WriteString("\n\n")
	b.WriteString("- **Environment/target/auth knowledge** (not formal vulnerabilities): use **`upsert_project_fact`**; the suggested `fact_key` is `category/slug` (e.g. `target/primary_domain`), and the same key overwrites and updates; the body records ports/versions/credential characteristics and evidence sources.\n")
	b.WriteString("- **Finding and exploitation context** (audit reproduction): suggested `fact_key` prefixes are `finding/`, `chain/`, `exploit/`, `poc/`; the **body is required** and must contain the full attack chain (entry point -> steps -> raw requests/responses or commands -> observed behavior -> related `related_vulnerability_id`); **do not write only a conclusion**; the summary is a one-line note of \"what + where + how to verify\".\n")
	b.WriteString("- **Deliverable vulnerabilities**: use **`record_vulnerability`** (title, description, severity, type, target, proof POC, impact, remediation advice). Severity is critical / high / medium / low / info.\n")
	b.WriteString("- The same finding may need to be recorded **once in each** (the fact holds the reproducible attack chain; the vulnerability holds the formal finding). For false positives use **`deprecate_project_fact`** or the vulnerability status false_positive.\n")
	b.WriteString("- When there are many facts, search with **`list_project_facts`** / **`search_project_facts`**.\n\n")
	b.WriteString(factEdgeRecordingGuidance())
	b.WriteString("\n\n")
	b.WriteString(factRecordingGuidanceBlock())
	b.WriteString("\n\nSeverity: critical / high / medium / low / info. Proof must include sufficient evidence (request/response, screenshots, command output, etc.).")
	return b.String()
}

// FactEdgeRecordingGuidance is the Agent guideline for writing edges (reused by the project package).
func FactEdgeRecordingGuidance() string { return factEdgeRecordingGuidance() }

// FactRecordingGuidanceBlock is the fact-writing guideline block (reused by the project package).
func FactRecordingGuidanceBlock() string { return factRecordingGuidanceBlock() }
