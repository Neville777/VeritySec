package scope

import (
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// NonNetworkTools are built-in tools that only read or write the platform's own records (or, for
// web_search, query a search engine). They never contact a target, so no target is extracted from
// their arguments. In particular the web_search query is NOT a target: searching does not touch
// the target host.
var NonNetworkTools = map[string]bool{
	"web_search": true,
	// findings, assets and project memory: bookkeeping that merely names a target
	"record_vulnerability": true, "list_vulnerabilities": true, "get_vulnerability": true, "update_vulnerability_status": true,
	"create_asset": true, "get_asset": true, "query_assets": true, "update_asset": true, "delete_asset": true, "complete_asset_scan": true,
	"upsert_project_fact": true, "get_project_fact": true, "list_project_facts": true, "search_project_facts": true,
	"deprecate_project_fact": true, "restore_project_fact": true,
	"list_knowledge_risk_types": true, "search_knowledge_base": true,
	"get_tool_execution": true, "wait_tool_execution": true, "cancel_tool_execution": true,
	"manage_webshell_list": true, "manage_webshell_add": true, "manage_webshell_update": true, "manage_webshell_delete": true,
	"engagement_stage": true,
}

// targetKeys are argument names that always carry a target (compared case-insensitively).
var targetKeys = map[string]bool{
	"target": true, "targets": true, "host": true, "hostname": true, "url": true, "urls": true,
	"domain": true, "ip": true, "address": true, "start": true, "base_url": true,
}

// fileExts are suffixes that make a bare dotted word a file name rather than a host, for values
// found under keys that are not target keys.
var fileExts = map[string]bool{
	"txt": true, "md": true, "go": true, "py": true, "js": true, "ts": true, "json": true, "yaml": true,
	"yml": true, "xml": true, "html": true, "htm": true, "css": true, "csv": true, "log": true, "sh": true,
	"conf": true, "cfg": true, "ini": true, "toml": true, "pdf": true, "png": true, "jpg": true, "jpeg": true,
	"gif": true, "zip": true, "gz": true, "tar": true, "db": true, "sql": true, "pem": true, "key": true,
	"crt": true, "bin": true, "exe": true, "so": true, "rb": true, "php": true, "java": true, "c": true,
	"h": true, "rs": true, "lock": true, "tmp": true, "bak": true, "out": true, "sum": true, "mod": true,
}

// ExtractTargets returns the de-duplicated, sorted targets a tool call names. Conservative rule:
//
//  1. any string (or list of strings) under a key in {target, targets, host, hostname, url, urls,
//     domain, ip, address, start, base_url} (case-insensitive, at any nesting depth);
//  2. any other string value that is by itself an absolute URL (scheme://), an IP, a CIDR, a
//     host:port, or a bare hostname with a non-file-extension last label.
//
// web_search (and the other NonNetworkTools) yield no targets. Values in free text (for example a
// shell command line) are additionally tokenised (see freeTextTargets): every token that parses
// as a URL, IP, CIDR, host:port or hostname is a target. This over-matches on purpose: a false
// positive only causes a refusal, a false negative would let an out-of-scope target through. A call that yields no
// targets is not treated as a network action and proceeds unchanged.
func ExtractTargets(toolName string, args map[string]interface{}) []string {
	if NonNetworkTools[strings.TrimSpace(toolName)] {
		return nil
	}
	set := map[string]struct{}{}
	walk(args, false, set, 0)
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func walk(v interface{}, keyed bool, set map[string]struct{}, depth int) {
	if depth > 8 {
		return
	}
	switch x := v.(type) {
	case string:
		t := strings.TrimSpace(x)
		if t == "" {
			return
		}
		if keyed || looksLikeTarget(t) {
			set[t] = struct{}{}
			return
		}
		for _, c := range freeTextTargets(t) {
			set[c] = struct{}{}
		}
	case []interface{}:
		for _, e := range x {
			walk(e, keyed, set, depth+1)
		}
	case []string:
		for _, e := range x {
			walk(e, keyed, set, depth+1)
		}
	case map[string]interface{}:
		for k, e := range x {
			walk(e, targetKeys[strings.ToLower(strings.TrimSpace(k))], set, depth+1)
		}
	}
}

func looksLikeTarget(s string) bool {
	if len(s) > 2048 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	if i := strings.Index(s, "://"); i > 0 {
		return isScheme(s[:i])
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(stripBrackets(s)); err == nil {
		return true
	}
	if strings.ContainsAny(s, "/\\") {
		return false // paths and the like
	}
	host := s
	if u, err := url.Parse("//" + s); err == nil && u.Port() != "" {
		if _, err := netip.ParseAddr(u.Hostname()); err == nil {
			return true // ip:port
		}
		n, ok := normalizeHost(u.Hostname())
		return ok && !looksNumeric(n) // host:port ("12:30" is not a target)
	}
	h, ok := normalizeHost(host)
	if !ok || !strings.Contains(h, ".") {
		return false
	}
	return !fileExts[h[strings.LastIndex(h, ".")+1:]]
}

func isScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || (i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'))) {
			return false
		}
	}
	return s != ""
}

const maxFreeTextLen = 1 << 20

// freeTextTargets tokenises free text (a shell command line, a prose argument) and returns every
// token that looks like a target. Tokens are split on whitespace and ; | & , quotes ` ( ) < > { }
// [ ] is kept for IPv6 literals. Each token is also tried after splitting on '=' (so --url=http://x
// and Host=x yield x), on '@' (user@host), and with a trailing path, port or punctuation removed.
// Long all-digit and 0x-hex tokens are returned too, since curl and friends accept them as IPv4
// addresses (2130706433); Evaluate refuses them as unparseable.
func freeTextTargets(s string) []string {
	if len(s) > maxFreeTextLen {
		s = s[:maxFreeTextLen]
	}
	coarse := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '\n', ';', '|', '&', ',', '"', '\'', '`', '(', ')', '<', '>', '{', '}', '\\':
			return true
		}
		return false
	})
	seen := map[string]struct{}{}
	var out []string
	add := func(c string) {
		if _, ok := seen[c]; !ok {
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	var try func(tok string, depth int)
	try = func(tok string, depth int) {
		tok = strings.Trim(tok, ".,:;!?*#$-+")
		if tok == "" || depth > 3 {
			return
		}
		if looksLikeTarget(tok) || looksLikeLegacyIP(tok) {
			add(tok)
		}
		if strings.HasPrefix(tok, "[") { // [v6]:port
			if i := strings.Index(tok, "]"); i > 1 {
				if _, err := netip.ParseAddr(tok[1:i]); err == nil {
					add(tok[1:i])
				}
			}
		}
		if i := strings.Index(tok, "://"); i > 0 && isScheme(tok[:i]) {
			if rest := tok[i+3:]; rest != "" { // also the bare authority, e.g. user@host:port
				try(rest, depth+1)
			}
		}
		if i := strings.Index(tok, "/"); i > 0 && !strings.Contains(tok[:i], "://") && !strings.HasSuffix(tok[:i], ":") {
			try(tok[:i], depth+1) // host/path
		}
		if i := strings.Index(tok, "="); i >= 0 && i+1 < len(tok) {
			try(tok[i+1:], depth+1) // --url=http://x/?a=b keeps the full value
		}
		for _, sep := range []string{"=", "@", ":", "?", "#"} {
			if strings.Contains(tok, sep) {
				for _, part := range strings.Split(tok, sep) {
					if part != tok {
						try(part, depth+1)
					}
				}
			}
		}
	}
	for _, tok := range coarse {
		try(tok, 0)
	}
	sort.Strings(out)
	return out
}

func looksLikeLegacyIP(s string) bool {
	if len(s) >= 8 && len(s) <= 10 {
		allDigits := true
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	if len(s) > 2 && len(s) <= 10 && (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) {
		for i := 2; i < len(s); i++ {
			c := s[i] | 0x20
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	return false
}
