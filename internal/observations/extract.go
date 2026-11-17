// Package observations extracts structured facts from tool output by deterministic rules.
// It never calls a model, never contacts anything, and never keeps the raw output.
package observations

import (
	"regexp"
	"strings"

	"veritysec/internal/inputs"
)

const (
	KindHTTPStatus = "http_status"
	KindURL        = "url"
	KindHostname   = "hostname"
	KindIPv4       = "ipv4"
	KindOpenPort   = "open_port"
	KindTechnology = "technology"
	KindTLSInfo    = "tls_info"
	KindOther      = "other"

	ConfidenceDeterministic = "deterministic"

	// MaxPerExecution caps rows stored for one tool execution.
	MaxPerExecution = 200

	maxInput    = 2 << 20
	maxValueLen = 200
)

// Observation is a fact about a tool output, not a conclusion.
type Observation struct {
	Kind       string `json:"kind"`
	Subject    string `json:"subject"`
	Attribute  string `json:"attribute"`
	Value      string `json:"value"`
	Confidence string `json:"confidence"`
}

var (
	httpStatusRe = regexp.MustCompile(`(?m)^[ \t]*HTTP/\d(?:\.\d)?[ \t]+(\d{3})(?:[ \t]+([^\r\n]*))?`)
	nmapPortRe   = regexp.MustCompile(`(?m)^[ \t]*(\d{1,5})/(tcp|udp|sctp)[ \t]+open(?:\|filtered)?[ \t]*(\S+)?`)
	nmapHostRe   = regexp.MustCompile(`(?m)^Nmap scan report for ([^\r\n]+)`)
	techRe       = regexp.MustCompile(`(?mi)^[ \t]*(server|x-powered-by):[ \t]*([^\r\n]+)`)
	tlsRe        = regexp.MustCompile(`(?mi)^[^\r\n]*(?:\bTLS\b|certificate)[^\r\n]*`)
)

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxValueLen {
		s = s[:maxValueLen]
	}
	return s
}

// ExtractObservations returns at most max observations (never more than MaxPerExecution) found in
// output. toolName is used as the subject fallback only for lines that name no target.
func ExtractObservations(toolName string, output string, max int) []Observation {
	if max <= 0 || max > MaxPerExecution {
		max = MaxPerExecution
	}
	if len(output) > maxInput {
		output = output[:maxInput]
	}
	var out []Observation
	add := func(kind, subject, attr, value string) bool {
		if len(out) >= max {
			return false
		}
		out = append(out, Observation{Kind: kind, Subject: clip(subject), Attribute: clip(attr), Value: clip(value), Confidence: ConfidenceDeterministic})
		return len(out) < max
	}
	subject := strings.TrimSpace(toolName)

	for _, m := range httpStatusRe.FindAllStringSubmatch(output, -1) {
		if !add(KindHTTPStatus, subject, "status", strings.TrimSpace(m[1]+" "+m[2])) {
			return out
		}
	}
	// Track the most recent "Nmap scan report for" host while scanning port lines in order.
	hosts := nmapHostRe.FindAllStringSubmatchIndex(output, -1)
	for _, m := range nmapPortRe.FindAllStringSubmatchIndex(output, -1) {
		host := subject
		for _, h := range hosts {
			if h[0] < m[0] {
				host = output[h[2]:h[3]]
			}
		}
		svc := ""
		if m[6] >= 0 {
			svc = output[m[6]:m[7]]
		}
		if !add(KindOpenPort, host, output[m[2]:m[3]]+"/"+output[m[4]:m[5]], "open "+svc) {
			return out
		}
	}
	for _, m := range techRe.FindAllStringSubmatch(output, -1) {
		if !add(KindTechnology, subject, strings.ToLower(m[1]), m[2]) {
			return out
		}
	}
	for _, l := range tlsRe.FindAllString(output, -1) {
		if !add(KindTLSInfo, subject, "line", l) {
			return out
		}
	}
	for _, in := range inputs.ExtractIndicators(output, max) {
		var kind string
		switch in.Kind {
		case inputs.IndicatorURL:
			kind = KindURL
		case inputs.IndicatorHostname:
			kind = KindHostname
		case inputs.IndicatorIPv4:
			kind = KindIPv4
		default:
			continue
		}
		if !add(kind, subject, "", in.Value) {
			return out
		}
	}
	return out
}
