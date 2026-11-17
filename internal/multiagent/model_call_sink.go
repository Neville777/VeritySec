package multiagent

import "github.com/cloudwego/eino/schema"

// ModelCallUsageSink receives the token usage of every model call, in order, within a run, plus
// the JSON size manifest recorded before that call (empty when none). The app sets it once at
// startup to persist per-call records. Nil means no recording.
var ModelCallUsageSink func(conversationID string, callIndex int, usage *schema.TokenUsage, manifestJSON string, costUSD *float64)
