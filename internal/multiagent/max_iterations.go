package multiagent

import "veritysec/internal/config"

// defaultAgentMaxIterations is the emergency iteration ceiling used when agent.max_iterations is 0.
// Context size is managed by reduction/summarization and agent.run_token_budget, not by this limit.
const defaultAgentMaxIterations = 1000000000

// agentMaxIterations global cap: only config.agent.max_iterations is used; when ≤0 it defaults to defaultAgentMaxIterations (200).
func agentMaxIterations(appCfg *config.Config) int {
	if appCfg != nil && appCfg.Agent.MaxIterations > 0 {
		return appCfg.Agent.MaxIterations
	}
	return defaultAgentMaxIterations
}

// resolveMaxIterations unifies the iteration cap: max_iterations>0 in Markdown/sub-agent front matter can override it individually; otherwise agent.max_iterations is used.
// multi_agent.max_iteration and sub_agent_max_iterations are deprecated and no longer take part in the calculation.
func resolveMaxIterations(appCfg *config.Config, markdownOverride int) int {
	if markdownOverride > 0 {
		return markdownOverride
	}
	return agentMaxIterations(appCfg)
}
