package inputs

import (
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// StatusDiscovered is the only status this package ever assigns. An indicator
// being discovered says nothing about permission to touch it: authorization is
// decided later by the scope engine, never here. Authorized is always false.
const StatusDiscovered = "discovered"

const (
	IndicatorURL      = "url"
	IndicatorHostname = "hostname"
	IndicatorIPv4     = "ipv4"
	IndicatorCIDR     = "cidr"
)

const (
	MaxIndicatorInput   = 2 << 20 // 2 MB of text examined
	DefaultMaxIndicator = 1000
	HardMaxIndicator    = 10000
)

// Indicator is something that looks like a target, found in text.
type Indicator struct {
	Kind       string // url, hostname, ipv4, cidr
	Value      string
	Offset     int    // byte offset in the input text (after the 2 MB cap)
	Status     string // always StatusDiscovered
	Authorized bool   // always false; scope engine decides later
}

func newIndicator(kind, value string, off int) Indicator {
	return Indicator{Kind: kind, Value: value, Offset: off, Status: StatusDiscovered, Authorized: false}
}

var (
	urlRe  = regexp.MustCompile("(?i)\\bhttps?://[^\\s<>\"'`\\\\^{}|\\[\\]]+")
	hostRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b`)
	ipRe   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
)

// Not hostnames: common file extensions that look like TLDs.
var fileTLDs = map[string]bool{
	"txt": true, "md": true, "go": true, "py": true, "js": true, "ts": true, "json": true, "yaml": true,
	"yml": true, "xml": true, "html": true, "htm": true, "css": true, "csv": true, "log": true, "sh": true,
	"conf": true, "cfg": true, "ini": true, "toml": true, "pdf": true, "png": true, "jpg": true, "jpeg": true,
	"gif": true, "zip": true, "gz": true, "tar": true, "db": true, "sql": true, "pem": true, "key": true,
	"crt": true, "bin": true, "exe": true, "so": true, "rb": true, "php": true, "java": true, "rs": true,
	"lock": true, "tmp": true, "bak": true, "out": true, "sum": true, "mod": true, "dll": true, "pcap": true,
	"docx": true, "xlsx": true, "svg": true, "webp": true,
}

// stripControl replaces control characters with spaces of equal byte length so
// offsets stay valid.
func stripControl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) {
			b.WriteString(strings.Repeat(" ", len(string(r))))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ExtractIndicators finds http/https URLs, hostnames, IPv4 addresses and CIDRs
// in text. Input is capped at 2 MB and control characters are neutralised
// first. Results are deduplicated, ordered by offset, and capped at max
// (default 1000, never above 10000). Nothing is resolved or contacted.
func ExtractIndicators(text string, max int) []Indicator {
	if max <= 0 {
		max = DefaultMaxIndicator
	}
	if max > HardMaxIndicator {
		max = HardMaxIndicator
	}
	if len(text) > MaxIndicatorInput {
		text = text[:MaxIndicatorInput]
	}
	text = stripControl(text)

	var all []Indicator
	for _, m := range urlRe.FindAllStringIndex(text, -1) {
		raw := strings.TrimRight(text[m[0]:m[1]], ".,;:!?)")
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		all = append(all, newIndicator(IndicatorURL, raw, m[0]))
	}
	for _, m := range hostRe.FindAllStringIndex(text, -1) {
		h := strings.ToLower(text[m[0]:m[1]])
		if fileTLDs[h[strings.LastIndex(h, ".")+1:]] || len(h) > 253 {
			continue
		}
		// skip tails of longer dotted tokens like 1.2.3.4.5 handled by ipRe; skip emails' local parts irrelevant
		all = append(all, newIndicator(IndicatorHostname, h, m[0]))
	}
	for _, m := range ipRe.FindAllStringIndex(text, -1) {
		if m[0] > 0 && text[m[0]-1] == '.' || m[1] < len(text) && text[m[1]] == '.' && m[1]+1 < len(text) && text[m[1]+1] >= '0' && text[m[1]+1] <= '9' {
			continue
		}
		tok := text[m[0]:m[1]]
		if strings.Contains(tok, "/") {
			p, err := netip.ParsePrefix(tok)
			if err != nil || !p.Addr().Is4() {
				continue
			}
			all = append(all, newIndicator(IndicatorCIDR, p.String(), m[0]))
		} else {
			a, err := netip.ParseAddr(tok)
			if err != nil || !a.Is4() {
				continue
			}
			all = append(all, newIndicator(IndicatorIPv4, a.String(), m[0]))
		}
	}

	sort.SliceStable(all, func(i, j int) bool { return all[i].Offset < all[j].Offset })
	seen := map[string]struct{}{}
	out := make([]Indicator, 0, len(all))
	for _, in := range all {
		k := in.Kind + "\x00" + in.Value
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, in)
		if len(out) >= max {
			break
		}
	}
	return out
}
