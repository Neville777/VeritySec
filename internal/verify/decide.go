package verify

import "fmt"

// strictness orders stances when one role gave several verdicts for a claim:
// the most conservative wins.
var strictness = map[string]int{StanceSupports: 0, StanceInsufficient: 1, StanceDisputes: 2}

// sanitize drops invalid verdicts and returns the effective stance per claim.
// Dropped verdicts are recorded in reasons. A claim with no surviving verdict
// is absent from the result (treated as "not supported").
func sanitize(role string, claims []ClaimInput, verdicts []ReviewerVerdict, reasons *[]string) map[string]string {
	ids := make(map[string]map[string]bool, len(claims))
	for _, c := range claims {
		set := make(map[string]bool, len(c.Evidence))
		for _, e := range c.Evidence {
			set[e.ID] = true
		}
		ids[c.ClaimID] = set
	}
	out := map[string]string{}
	for _, v := range verdicts {
		set, ok := ids[v.ClaimID]
		if !ok {
			*reasons = append(*reasons, fmt.Sprintf("%s verdict discarded: unknown claim %q", role, v.ClaimID))
			continue
		}
		if _, ok := strictness[v.Stance]; !ok {
			*reasons = append(*reasons, fmt.Sprintf("%s verdict discarded for claim %s: invalid stance %q", role, v.ClaimID, v.Stance))
			continue
		}
		bad := ""
		for _, id := range v.EvidenceIDs {
			if !set[id] {
				bad = id
				break
			}
		}
		if bad != "" {
			*reasons = append(*reasons, fmt.Sprintf("%s verdict discarded for claim %s: cites unknown evidence id %q", role, v.ClaimID, bad))
			continue
		}
		if v.Stance != StanceInsufficient && len(v.EvidenceIDs) == 0 {
			*reasons = append(*reasons, fmt.Sprintf("%s %s verdict discarded for claim %s: cites no evidence", role, v.Stance, v.ClaimID))
			continue
		}
		if prev, seen := out[v.ClaimID]; !seen || strictness[v.Stance] > strictness[prev] {
			out[v.ClaimID] = v.Stance
		}
	}
	return out
}

func hasToolEvidence(c ClaimInput) bool {
	for _, e := range c.Evidence {
		if e.Origin == OriginTool {
			return true
		}
	}
	return false
}

// hasTraceableToolEvidence requires a tool-origin item with SHA256 and ToolExecutionID.
func hasTraceableToolEvidence(c ClaimInput) bool {
	for _, e := range c.Evidence {
		if e.Origin == OriginTool && e.SHA256 != "" && e.ToolExecutionID != "" {
			return true
		}
	}
	return false
}

// Decide is pure and deterministic. Order of rules:
//  1. no claims -> INCONCLUSIVE
//  2. claims lacking tool-origin evidence cap the result at NEEDS_MANUAL_REVIEW
//  3. verdicts citing unknown evidence/claims (or supports/disputes citing
//     nothing) are discarded and recorded
//  4. a challenger dispute makes the finding NEEDS_MANUAL_REVIEW; if the
//     primary also disputes that claim, REJECTED
//  5. both reviewers support every claim and every claim has traceable tool
//     evidence (SHA256 + ToolExecutionID) -> CONFIRMABLE
//  6. any remaining "insufficient" verdict -> INCONCLUSIVE
//  7. otherwise NEEDS_MANUAL_REVIEW (including missing/discarded verdicts)
//
// It never returns CONFIRMED; a human sets that.
func Decide(claims []ClaimInput, primary, challenger []ReviewerVerdict) Decision {
	if len(claims) == 0 {
		return Decision{Status: StatusInconclusive, Reasons: []string{"no claims to verify"}}
	}
	var reasons []string
	capped := false
	for _, c := range claims {
		if !hasToolEvidence(c) {
			capped = true
			reasons = append(reasons, fmt.Sprintf("no tool evidence for claim %s", c.ClaimID))
		}
	}
	p := sanitize(RolePrimary, claims, primary, &reasons)
	ch := sanitize(RoleChallenger, claims, challenger, &reasons)

	rejected, disputed, insufficient := false, false, false
	allSupport, allTraceable := true, true
	for _, c := range claims {
		ps, pok := p[c.ClaimID]
		cs, cok := ch[c.ClaimID]
		if cok && cs == StanceDisputes {
			if pok && ps == StanceDisputes {
				rejected = true
				reasons = append(reasons, fmt.Sprintf("claim %s disputed by primary and challenger", c.ClaimID))
			} else {
				disputed = true
				reasons = append(reasons, fmt.Sprintf("claim %s disputed by challenger", c.ClaimID))
			}
		}
		if ps == StanceInsufficient || cs == StanceInsufficient {
			insufficient = true
			reasons = append(reasons, fmt.Sprintf("insufficient evidence reported for claim %s", c.ClaimID))
		}
		if !(pok && cok && ps == StanceSupports && cs == StanceSupports) {
			allSupport = false
		}
		if !hasTraceableToolEvidence(c) {
			allTraceable = false
		}
	}

	switch {
	case rejected:
		return Decision{Status: StatusRejected, Reasons: reasons}
	case disputed:
		return Decision{Status: StatusNeedsManualReview, Reasons: reasons}
	case allSupport && allTraceable && !capped:
		return Decision{Status: StatusConfirmable, Reasons: append(reasons, "primary and challenger support every claim with traceable tool evidence")}
	case insufficient && !capped:
		return Decision{Status: StatusInconclusive, Reasons: reasons}
	}
	if allSupport && !allTraceable && !capped {
		reasons = append(reasons, "tool evidence lacks sha256 or tool execution id")
	} else if !allSupport && !insufficient {
		reasons = append(reasons, "not every claim is supported by both reviewers")
	}
	return Decision{Status: StatusNeedsManualReview, Reasons: reasons}
}
