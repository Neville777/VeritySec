package multiagent

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"veritysec/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/adk/prebuilt/planexecute"
	"github.com/cloudwego/eino/schema"
)

// RunStatusTokenBudgetExhausted is the RunResult.Status / progress event name used when a run is
// ended because its cumulative provider-reported tokens exceeded agent.run_token_budget.
const RunStatusTokenBudgetExhausted = "token_budget_exhausted"

var errRunTokenBudgetExhausted = errors.New("run token budget exhausted")

// runTokenGuard enforces agent.run_token_budget. One guard exists per run; it reads the run's
// einoRunUsageAccumulator (provider-reported usage, never estimated from characters), which the
// run loop binds once the event drain exists. All methods are nil-safe (nil = budget off).
type runTokenGuard struct {
	budget  int
	usage   atomic.Pointer[einoRunUsageAccumulator]
	tripped atomic.Bool
	used    atomic.Int64
}

// newRunTokenGuard returns nil when agent.run_token_budget is 0 (off) or unset.
func newRunTokenGuard(appCfg *config.Config) *runTokenGuard {
	if appCfg == nil || appCfg.Agent.RunTokenBudget <= 0 {
		return nil
	}
	return &runTokenGuard{budget: appCfg.Agent.RunTokenBudget}
}

func (g *runTokenGuard) Bind(acc *einoRunUsageAccumulator) {
	if g != nil {
		g.usage.Store(acc)
	}
}

// Check returns errRunTokenBudgetExhausted (wrapped) when the cumulative provider-reported total
// tokens of this run already exceed the budget; it is called before every model call.
func (g *runTokenGuard) Check() error {
	if g == nil {
		return nil
	}
	if g.tripped.Load() {
		return fmt.Errorf("%w: used %d of %d tokens", errRunTokenBudgetExhausted, g.used.Load(), g.budget)
	}
	acc := g.usage.Load()
	if acc == nil {
		return nil
	}
	total := acc.Summary().TotalTokens
	if total > g.budget {
		g.used.Store(int64(total))
		g.tripped.Store(true)
		return fmt.Errorf("%w: used %d of %d tokens", errRunTokenBudgetExhausted, total, g.budget)
	}
	return nil
}

// Tripped reports whether the budget stopped the run, with the used/budget numbers.
func (g *runTokenGuard) Tripped() (used, budget int, ok bool) {
	if g == nil || !g.tripped.Load() {
		return 0, 0, false
	}
	return int(g.used.Load()), g.budget, true
}

// Middleware returns the agentic handler that calls Check in BeforeModelRewriteState (i.e. before
// every model call of the agent it is mounted on); nil when the budget is off.
func (g *runTokenGuard) Middleware() adk.TypedChatModelAgentMiddleware[*schema.AgenticMessage] {
	if g == nil {
		return nil
	}
	return &runTokenGuardMiddleware{
		TypedBaseChatModelAgentMiddleware: &adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]{},
		guard:                             g,
	}
}

type runTokenGuardMiddleware struct {
	*adk.TypedBaseChatModelAgentMiddleware[*schema.AgenticMessage]
	guard *runTokenGuard
}

func (m *runTokenGuardMiddleware) BeforeModelRewriteState(
	ctx context.Context,
	state *adk.TypedChatModelAgentState[*schema.AgenticMessage],
	mc *adk.TypedModelContext[*schema.AgenticMessage],
) (context.Context, *adk.TypedChatModelAgentState[*schema.AgenticMessage], error) {
	_ = mc
	if err := m.guard.Check(); err != nil {
		return ctx, state, err
	}
	return ctx, state, nil
}

func runTokenBudgetExplanation(used, budget int) string {
	return fmt.Sprintf("Run stopped: the token budget for this run was exhausted (%d tokens used, run_token_budget=%d). "+
		"Work completed so far is preserved above; send a follow-up message to continue, or raise agent.run_token_budget.", used, budget)
}

// capMaxTotalTokens applies agent.max_input_tokens_per_call (0 = off) as an upper bound on the
// per-call input window used by summarization / compaction (OpenAI.MaxTotalTokens).
func capMaxTotalTokens(appCfg *config.Config) *config.Config {
	if appCfg == nil || appCfg.Agent.MaxInputTokensPerCall <= 0 {
		return appCfg
	}
	cur := appCfg.OpenAI.MaxTotalTokens
	if cur > 0 && cur <= appCfg.Agent.MaxInputTokensPerCall {
		return appCfg
	}
	cp := *appCfg
	cp.OpenAI.MaxTotalTokens = appCfg.Agent.MaxInputTokensPerCall
	return &cp
}

// tokenGuardedPlannerGenInput / tokenGuardedReplannerGenInput check the run token budget before the
// plan_execute planner and replanner model calls (they are not ChatModelAgents with middleware chains).
func tokenGuardedPlannerGenInput(g *runTokenGuard, fn planexecute.GenPlannerModelInputFn) planexecute.GenPlannerModelInputFn {
	if g == nil || fn == nil {
		return fn
	}
	return func(ctx context.Context, userInput []adk.Message) ([]adk.Message, error) {
		if err := g.Check(); err != nil {
			return nil, err
		}
		return fn(ctx, userInput)
	}
}

func tokenGuardedReplannerGenInput(g *runTokenGuard, fn planexecute.GenModelInputFn) planexecute.GenModelInputFn {
	if g == nil || fn == nil {
		return fn
	}
	return func(ctx context.Context, in *planexecute.ExecutionContext) ([]adk.Message, error) {
		if err := g.Check(); err != nil {
			return nil, err
		}
		return fn(ctx, in)
	}
}
