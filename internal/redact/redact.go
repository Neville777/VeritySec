// Package redact masks sensitive values (credentials, keys, card numbers, e-mail addresses) in
// text that is shown to people or sent to a model.
//
// IMPORTANT: redaction is always applied to a COPY of the text. Stored evidence is never
// rewritten: its bytes and SHA-256 stay exactly as captured, so integrity checks keep working.
// Callers redact on the way out (reports, model prompts, previews), not on the way in.
//
// Limits: this is pattern matching. It will miss secret formats it does not know, secrets
// without a recognisable key name, and values split across lines. Treat it as a safety net, not
// a guarantee.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Finding reports how many values of one kind were masked. It never carries the values.
type Finding struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// Kinds of redaction.
const (
	KindPrivateKey = "private_key"
	KindJWT        = "jwt"
	KindBearer     = "bearer_token"
	KindAWSKey     = "aws_access_key"
	KindAPIKey     = "api_key"
	KindPassword   = "password"
	KindCreditCard = "credit_card"
	KindEmail      = "email"
)

type rule struct {
	kind string
	re   *regexp.Regexp
	// keepPrefix: group 1 is a key name and separator that stays in the output.
	keepPrefix bool
	// accept, when set, must return true for a match to be redacted.
	accept func(match string) bool
}

// Order matters: earlier rules consume text that later rules would otherwise match again.
var rules = []rule{
	{kind: KindPrivateKey, re: regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)},
	{kind: KindJWT, re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`)},
	{kind: KindBearer, re: regexp.MustCompile(`(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}`), keepPrefix: true},
	{kind: KindAWSKey, re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b`)},
	{kind: KindAPIKey, re: regexp.MustCompile(`(?i)(\bapi[_-]?key["']?\s*[:=]\s*["']?)[A-Za-z0-9._~+/=-]{8,}`), keepPrefix: true},
	{kind: KindPassword, re: regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token)["']?\s*[:=]\s*["']?)[^\s"'&,;\[]+`), keepPrefix: true},
	{kind: KindCreditCard, re: regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`), accept: luhnOK},
	{kind: KindEmail, re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b`)},
}

// Redact returns text with every match replaced by "[REDACTED:<kind>]" and a list of findings
// (kind and count only). The input string is not modified; stored originals are unaffected.
func Redact(text string) (string, []Finding) {
	counts := map[string]int{}
	for _, r := range rules {
		r := r
		text = r.re.ReplaceAllStringFunc(text, func(m string) string {
			if r.accept != nil && !r.accept(m) {
				return m
			}
			counts[r.kind]++
			tag := "[REDACTED:" + r.kind + "]"
			if r.keepPrefix {
				if sub := r.re.FindStringSubmatch(m); len(sub) > 1 {
					return sub[1] + tag
				}
			}
			return tag
		})
	}
	return text, toFindings(counts)
}

// Summary turns findings into a kind -> count map (never nil).
func Summary(fs []Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Kind] += f.Count
	}
	return out
}

// Add adds findings into an existing kind -> count map.
func Add(into map[string]int, fs []Finding) {
	for _, f := range fs {
		into[f.Kind] += f.Count
	}
}

func toFindings(counts map[string]int) []Finding {
	out := make([]Finding, 0, len(counts))
	for k, n := range counts {
		out = append(out, Finding{Kind: k, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// luhnOK reports whether the digits in s (13-19 of them) pass the Luhn checksum.
func luhnOK(s string) bool {
	digits := make([]int, 0, 19)
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		} else if c != ' ' && c != '-' {
			return false
		}
	}
	if len(digits) < 13 || len(digits) > 19 || strings.Trim(s, "0 -") == "" {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}
