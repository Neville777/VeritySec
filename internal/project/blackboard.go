package project

import (
	"fmt"
	"strings"

	"veritysec/internal/config"
	"veritysec/internal/database"
)

// AppendSystemPromptBlock appends an extra block to the system prompt.
func AppendSystemPromptBlock(base, block string) string {
	base = strings.TrimSpace(base)
	block = strings.TrimSpace(block)
	if block == "" {
		return base
	}
	if base == "" {
		return block
	}
	return base + "\n\n" + block
}

const (
	factIndexFooterGetDetail = "For full content (attack chain, POC, request/response) call get_project_fact(fact_key); never invent details from the summary."
	factIndexFooterWriteHint = "Write links via from (source fact_key → current fact), e.g. on a finding: {from:target/*, type:discovered_on}; body should be reproducible (finding|chain|exploit|poc/ prefix recommended)."
	factIndexFooterEmpty     = "To write a fact use upsert_project_fact; for details call get_project_fact(fact_key)."
)

// BuildFactIndexBlock generates the project blackboard index for the Agent system prompt (key + summary + relation edges + attack paths, without body).
func BuildFactIndexBlock(db *database.DB, projectID string, cfg config.ProjectConfig, conversationIDs ...string) (string, error) {
	if db == nil || !cfg.Enabled {
		return "", nil
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return "", nil
	}

	proj, err := db.GetProject(projectID)
	if err != nil {
		return "", err
	}

	conversationID := ""
	if len(conversationIDs) > 0 {
		conversationID = strings.TrimSpace(conversationIDs[0])
	}
	facts, err := db.ListProjectFactsForIndex(projectID, cfg.DefaultInjectDeprecated, conversationID)
	if err != nil {
		return "", err
	}
	allEdges, _ := db.ListProjectFactEdgesByProject(projectID)
	allEdges = FilterCheckpointEdges(allEdges, facts)
	_, incomingByTarget := indexEdgeGroupMaps(allEdges)
	resume := buildResumeSection(db, projectID, facts)

	maxRunes := cfg.FactIndexMaxRunesEffective()
	header := fmt.Sprintf("## Project Blackboard Index (project: %s, id: %s)\n", indexField(proj.Name), proj.ID)
	if len(facts) == 0 {
		content := header + "(no facts yet)\n" + factIndexFooterEmpty
		if len([]rune(wrapFactIndexBlock(content+"\n\n"+resume))) <= maxRunes {
			return wrapFactIndexBlock(content + "\n\n" + resume), nil
		}
		block := wrapFactIndexBlock(content)
		if len([]rune(block)) <= maxRunes {
			return block, nil
		}
		return minimalFactIndexBlock(maxRunes), nil
	}

	sortFactsForIndex(facts)

	pathMaxRunes := cfg.FactIndexPathMaxRunesEffective()
	footer := factIndexFooterGetDetail + "\n" + factIndexFooterWriteHint
	// Continuation data shares the host index cap. Reserve space for fact rows;
	// tiny budgets retain tool retrieval guidance.
	if len([]rune(resume)) <= maxRunes-len([]rune(wrapFactIndexBlock(header+footer)))-800 {
		footer += "\n\n" + resume
	}
	// Include markers, separators and the worst-case omission notice in the cap.
	omissionReserve := len([]rune(factIndexOmissionNotice(len(facts))))
	framingRunes := len([]rune(wrapFactIndexBlock(header+footer))) + omissionReserve
	available := maxRunes - framingRunes
	if available <= 0 {
		return minimalFactIndexBlock(maxRunes), nil
	}
	if pathMaxRunes > available {
		pathMaxRunes = available
	}
	factsBudget := available - pathMaxRunes
	if factsBudget < 800 {
		factsBudget = available
		pathMaxRunes = 0
	}

	indexedKeys := make(map[string]struct{}, len(facts))
	var b strings.Builder
	b.WriteString(header)
	used := 0
	omitted := 0

	for _, f := range facts {
		// Category and confidence are only defaulted, never validated, so either can
		// carry a newline that would inject a fake index line into the system prompt.
		line := fmt.Sprintf("- [%s] %s — %s (%s)", f.FactKey,
			indexField(f.Category),
			truncateIndexSummary(indexField(f.Summary), cfg.FactSummaryMaxRunesEffective()),
			indexField(f.Confidence))
		if database.IsContextCheckpointKey(f.FactKey) {
			line += " [current session working memory]"
		}
		line += FormatFactIndexLinksHint(f.FactKey, incomingByTarget[f.FactKey])
		line += "\n"
		lineRunes := len([]rune(line))
		if used+lineRunes > factsBudget {
			omitted++
			continue
		}
		indexedKeys[f.FactKey] = struct{}{}
		b.WriteString(line)
		used += lineRunes
	}

	if omitted > 0 {
		b.WriteString(factIndexOmissionNotice(omitted))
	}

	if pathSection := BuildFactPathOverviewSection(allEdges, indexedKeys, pathMaxRunes-1); pathSection != "" {
		b.WriteString("\n")
		b.WriteString(pathSection)
	}

	b.WriteString(footer)
	return wrapFactIndexBlock(b.String()), nil
}

// A hidden checkpoint must not reappear via a visible fact's relationship hint.
func FilterCheckpointEdges(edges []*database.ProjectFactEdge, visibleFacts []*database.ProjectFact) []*database.ProjectFactEdge {
	visible := make(map[string]bool)
	for _, f := range visibleFacts {
		visible[f.FactKey] = true
	}
	var out []*database.ProjectFactEdge
	for _, e := range edges {
		if database.IsContextCheckpointKey(e.SourceFactKey) && !visible[e.SourceFactKey] ||
			database.IsContextCheckpointKey(e.TargetFactKey) && !visible[e.TargetFactKey] {
			continue
		}
		out = append(out, e)
	}
	return out
}

// indexField flattens free-text fact fields: newlines could forge index lines, and host delimiters could close the index block early.
func indexField(s string) string {
	return factIndexSafeText(strings.Join(strings.Fields(s), " "))
}

func truncateIndexSummary(s string, maxRunes int) string {
	runes := []rune(s)
	if maxRunes > 0 && len(runes) > maxRunes {
		return string(runes[:maxRunes-1]) + "…"
	}
	return s
}

func factIndexOmissionNotice(count int) string {
	return fmt.Sprintf("\n(%d more not included in the index; use list_project_facts or search_project_facts to query them.)\n", count)
}

func minimalFactIndexBlock(maxRunes int) string {
	block := wrapFactIndexBlock("## Project Blackboard Index\nIndex budget insufficient; use list_project_facts or search_project_facts to query as needed.")
	if len([]rune(block)) > maxRunes {
		return ""
	}
	return block
}
