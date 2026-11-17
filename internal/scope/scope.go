// Package scope is a deterministic, pure scope engine. It decides whether a target (hostname,
// URL, host:port, IP or CIDR) is inside the authorised scope of an engagement.
//
// It is a restriction layer only: it never runs a tool, sends traffic or resolves names. Every
// function here is free of I/O (no DNS, no clock reads; callers pass "now"), and the engine never
// defaults to "in scope": anything it cannot positively match against an included rule is refused.
package scope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

// Result is the outcome class of a scope decision.
type Result string

const (
	InScope          Result = "IN_SCOPE"
	OutOfScope       Result = "OUT_OF_SCOPE"
	RequiresApproval Result = "REQUIRES_APPROVAL"
	Unknown          Result = "UNKNOWN"
)

// Decision is the verdict for one target.
type Decision struct {
	Result Result `json:"result"`
	Reason string `json:"reason"`
	Target string `json:"target"`
}

// Allowed reports whether the decision permits acting on the target (only IN_SCOPE does).
func (d Decision) Allowed() bool { return d.Result == InScope }

type ruleKind int

const (
	kindHost   ruleKind = iota // exact hostname
	kindDomain                 // domain and every subdomain
	kindIP                     // single IP
	kindCIDR                   // address range
	kindURL                    // URL prefix
)

type rule struct {
	kind   ruleKind
	raw    string
	host   string // kindHost/kindDomain: normalised name; kindURL: normalised host
	addr   netip.Addr
	prefix netip.Prefix
	scheme string // kindURL
	port   string // kindURL (effective port)
	path   string // kindURL (cleaned path)
}

// Scope is a parsed engagement scope.
type Scope struct {
	included  []rule
	excluded  []rule
	ExpiresAt time.Time // zero = no expiry recorded
}

// IncludedCount returns the number of included rules (0 means nothing is in scope).
func (s *Scope) IncludedCount() int {
	if s == nil {
		return 0
	}
	return len(s.included)
}

// rawScope is the scope_json wire format. Entries are plain strings or {"type","value"} objects.
type rawScope struct {
	Included  []json.RawMessage `json:"included"`
	Excluded  []json.RawMessage `json:"excluded"`
	ExpiresAt *string           `json:"expires_at"`
}

// Parse strictly parses scope_json. Unknown keys, non-string entries, empty entries and entries
// that are not a valid hostname, domain, IP, CIDR or URL prefix are errors: a malformed scope is
// never silently treated as an empty (or wider) scope.
//
// String entries: "10.0.0.1" IP, "10.0.0.0/24" CIDR, "https://a.example/app" URL prefix,
// "*.example.com" or ".example.com" domain (the domain itself and all subdomains), anything else a
// hostname matched exactly. Typed entries {"type":"host|domain|ip|cidr|url","value":"..."} are
// explicit. An optional "expires_at" (RFC 3339) marks the end of the authorisation.
func Parse(raw []byte) (*Scope, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, errors.New("scope: empty scope_json")
	}
	var rs rawScope
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("scope: malformed scope_json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("scope: trailing data after scope_json object")
	}
	s := &Scope{}
	var err error
	if s.included, err = parseRules(rs.Included, "included"); err != nil {
		return nil, err
	}
	if s.excluded, err = parseRules(rs.Excluded, "excluded"); err != nil {
		return nil, err
	}
	if rs.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(*rs.ExpiresAt))
		if err != nil {
			return nil, fmt.Errorf("scope: expires_at must be RFC 3339: %w", err)
		}
		s.ExpiresAt = t.UTC()
	}
	return s, nil
}

func parseRules(items []json.RawMessage, list string) ([]rule, error) {
	out := make([]rule, 0, len(items))
	for i, it := range items {
		var typ, val string
		itt := bytes.TrimSpace(it)
		if len(itt) > 0 && itt[0] == '{' {
			var obj struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			}
			d := json.NewDecoder(bytes.NewReader(itt))
			d.DisallowUnknownFields()
			if err := d.Decode(&obj); err != nil {
				return nil, fmt.Errorf("scope: %s[%d]: %w", list, i, err)
			}
			typ, val = strings.ToLower(strings.TrimSpace(obj.Type)), obj.Value
		} else if err := json.Unmarshal(itt, &val); err != nil {
			return nil, fmt.Errorf("scope: %s[%d] must be a string or object", list, i)
		}
		r, err := parseRule(typ, val)
		if err != nil {
			return nil, fmt.Errorf("scope: %s[%d] %q: %w", list, i, val, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func parseRule(typ, val string) (rule, error) {
	v := strings.TrimSpace(val)
	if v == "" {
		return rule{}, errors.New("empty entry")
	}
	r := rule{raw: v}
	if typ == "" {
		switch {
		case strings.Contains(v, "://"):
			typ = "url"
		case strings.Contains(v, "/"):
			typ = "cidr"
		case strings.HasPrefix(v, "*.") || strings.HasPrefix(v, "."):
			typ = "domain"
		default:
			if _, err := netip.ParseAddr(stripBrackets(v)); err == nil {
				typ = "ip"
			} else {
				typ = "host"
			}
		}
	}
	switch typ {
	case "ip":
		a, err := netip.ParseAddr(stripBrackets(v))
		if err != nil {
			return rule{}, errors.New("invalid IP")
		}
		r.kind, r.addr = kindIP, canonAddr(a)
	case "cidr":
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return rule{}, errors.New("invalid CIDR")
		}
		a := canonAddr(p.Addr())
		if a.Is4() && p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return rule{}, errors.New("invalid IPv4-mapped CIDR")
			}
			p = netip.PrefixFrom(a, p.Bits()-96)
		} else {
			p = netip.PrefixFrom(a, p.Bits())
		}
		r.kind, r.prefix = kindCIDR, p.Masked()
	case "host", "domain":
		name := strings.TrimPrefix(strings.TrimPrefix(v, "*"), ".")
		if typ == "host" && name != v {
			return rule{}, errors.New("wildcard in host rule (use a domain rule)")
		}
		h, ok := normalizeHost(name)
		if !ok {
			return rule{}, errors.New("invalid hostname")
		}
		if _, err := netip.ParseAddr(h); err == nil || looksNumeric(h) {
			return rule{}, errors.New("IP literal is not a hostname")
		}
		r.kind, r.host = kindHost, h
		if typ == "domain" {
			r.kind = kindDomain
		}
	case "url":
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" || u.Hostname() == "" {
			return rule{}, errors.New("invalid URL prefix")
		}
		h, ok := normalizeHost(u.Hostname())
		if !ok {
			return rule{}, errors.New("invalid URL host")
		}
		r.kind, r.host, r.scheme = kindURL, h, strings.ToLower(u.Scheme)
		r.port = effectivePort(r.scheme, u.Port())
		r.path = cleanPath(u.Path)
	default:
		return rule{}, fmt.Errorf("unknown rule type %q", typ)
	}
	return r, nil
}

// Evaluate decides whether target may be acted on. It is pure: no DNS, no clock (now is passed
// in). Precedence: expired authorisation, unparseable target, excluded rules, included rules, and
// otherwise OUT_OF_SCOPE. IP literals are matched only by IP/CIDR rules and names only by
// name rules; a name is never resolved here, so a name that happens to resolve into an included
// CIDR is not in scope by that route.
func Evaluate(s *Scope, target string, now time.Time) Decision {
	d := Decision{Target: target}
	if s == nil {
		d.Result, d.Reason = Unknown, "no scope available"
		return d
	}
	if !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt) {
		d.Result, d.Reason = OutOfScope, "authorization expired"
		return d
	}
	p, ok := parseTarget(target)
	if !ok {
		d.Result, d.Reason = Unknown, "target could not be parsed"
		return d
	}
	for _, r := range s.excluded {
		if r.matches(p) || (p.isCIDR && r.overlaps(p)) {
			d.Result, d.Reason = OutOfScope, "matches excluded rule "+r.raw
			return d
		}
	}
	for _, r := range s.included {
		if r.matches(p) {
			d.Result, d.Reason = InScope, "matches included rule "+r.raw
			return d
		}
	}
	d.Result, d.Reason = OutOfScope, "matches no included rule"
	return d
}

// parsed is a normalised target.
type parsed struct {
	host   string // normalised name (empty for IPs)
	addr   netip.Addr
	prefix netip.Prefix
	isIP   bool
	isCIDR bool
	// URL fields (only when the target was an absolute URL)
	isURL  bool
	scheme string
	port   string
	path   string
}

func (r rule) matches(p parsed) bool {
	switch r.kind {
	case kindHost:
		return !p.isIP && !p.isCIDR && p.host == r.host
	case kindDomain:
		return !p.isIP && !p.isCIDR && (p.host == r.host || strings.HasSuffix(p.host, "."+r.host))
	case kindIP:
		return p.isIP && p.addr == r.addr
	case kindCIDR:
		if p.isIP {
			return r.prefix.Contains(p.addr)
		}
		if p.isCIDR { // fully contained
			return r.prefix.Bits() <= p.prefix.Bits() && r.prefix.Contains(p.prefix.Addr())
		}
		return false
	case kindURL:
		if !p.isURL {
			return false
		}
		hostOK := (!p.isIP && p.host == r.host) || (p.isIP && p.addr.String() == r.host)
		if !hostOK || p.scheme != r.scheme || p.port != r.port {
			return false
		}
		if r.path == "/" || r.path == "" {
			return true
		}
		return p.path == r.path || strings.HasPrefix(p.path, strings.TrimSuffix(r.path, "/")+"/")
	}
	return false
}

// overlaps reports whether a rule intersects a CIDR target (used so an excluded host range inside
// an otherwise included CIDR target refuses the whole range).
func (r rule) overlaps(p parsed) bool {
	switch r.kind {
	case kindIP:
		return p.prefix.Contains(r.addr)
	case kindCIDR:
		return r.prefix.Overlaps(p.prefix)
	}
	return false
}

func parseTarget(raw string) (parsed, bool) {
	t := strings.TrimSpace(raw)
	if t == "" || strings.ContainsAny(t, " \t\r\n\x00") {
		return parsed{}, false
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil || u.Scheme == "" || u.Hostname() == "" {
			return parsed{}, false
		}
		p, ok := hostToParsed(u.Hostname())
		if !ok {
			return parsed{}, false
		}
		p.isURL = true
		p.scheme = strings.ToLower(u.Scheme)
		p.port = effectivePort(p.scheme, u.Port())
		p.path = cleanPath(u.Path)
		return p, true
	}
	if strings.Contains(t, "/") {
		if pre, err := netip.ParsePrefix(t); err == nil {
			a := canonAddr(pre.Addr())
			bits := pre.Bits()
			if a.Is4() && pre.Addr().Is4In6() {
				if bits < 96 {
					return parsed{}, false
				}
				bits -= 96
			}
			return parsed{isCIDR: true, prefix: netip.PrefixFrom(a, bits).Masked()}, true
		}
	}
	if a, err := netip.ParseAddr(stripBrackets(t)); err == nil {
		return parsed{isIP: true, addr: canonAddr(a)}, true
	}
	// host, host:port, user@host, host/path
	u, err := url.Parse("//" + t)
	if err != nil || u.Hostname() == "" {
		return parsed{}, false
	}
	return hostToParsed(u.Hostname())
}

func hostToParsed(h string) (parsed, bool) {
	if ip := net.ParseIP(h); ip != nil {
		if a, ok := netip.AddrFromSlice(ip); ok {
			return parsed{isIP: true, addr: canonAddr(a)}, true
		}
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return parsed{isIP: true, addr: canonAddr(a)}, true
	}
	n, ok := normalizeHost(h)
	if !ok || looksNumeric(n) { // odd IPv4 forms (decimal, hex, short) are refused, not guessed
		return parsed{}, false
	}
	return parsed{host: n}, true
}

// canonAddr drops IPv6 zones and unmaps IPv4-mapped IPv6 so one address has one form.
func canonAddr(a netip.Addr) netip.Addr {
	return a.WithZone("").Unmap()
}

func stripBrackets(s string) string {
	if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

// normalizeHost lowercases, strips one trailing dot and validates ASCII LDH labels
// (underscore tolerated). Non-ASCII names are rejected rather than guessed at.
func normalizeHost(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return h, true
}

// looksNumeric reports names whose last label is numeric or 0x-hex: legacy IPv4 spellings such as
// 2130706433, 0x7f.1 or 127.1 that some resolvers accept as addresses.
func looksNumeric(h string) bool {
	last := h[strings.LastIndex(h, ".")+1:]
	if last == "" {
		return false
	}
	if strings.HasPrefix(last, "0x") {
		return true
	}
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return false
		}
	}
	return true
}

func effectivePort(scheme, port string) string {
	if port != "" {
		return port
	}
	switch scheme {
	case "http", "ws":
		return "80"
	case "https", "wss":
		return "443"
	case "ftp":
		return "21"
	case "ssh":
		return "22"
	}
	return ""
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean("/" + p)
	return c
}
