package report

import (
	"bytes"
	"fmt"
	"html"
	"regexp"
	"strings"
)

// mdEscape neutralises markdown syntax in database text and flattens it to one line.
func mdEscape(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '<', '>', '#', '{', '}', '|':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// notRecorded escapes s, or returns the placeholder when s is blank.
func notRecorded(s string) string {
	if strings.TrimSpace(s) == "" {
		return NotRecorded
	}
	return mdEscape(s)
}

var unsafeID = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// safeID restricts identifiers to characters that are safe in anchors and link targets.
func safeID(s string) string { return unsafeID.ReplaceAllString(s, "_") }

// fenceText renders multi-line text as a fenced code block whose fence is longer than any
// backtick run inside it. The NotRecorded placeholder stays plain text.
func fenceText(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n")
	if s == "" || s == NotRecorded {
		return "Not recorded"
	}
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + "\n" + s + "\n" + fence
}

// ---- minimal markdown subset -> blocks (used by HTML and DOCX output) ----

type mdBlock struct {
	Kind     string // h1..h6, li, li2, code, p, hr
	Text     string
	AnchorID string
}

var headingID = regexp.MustCompile(`^(.*?)\s*\{#([A-Za-z0-9_-]+)\}$`)

// parseMarkdown understands exactly the subset the report templates emit.
func parseMarkdown(md string) []mdBlock {
	var out []mdBlock
	var para []string
	flush := func() {
		if len(para) > 0 {
			out = append(out, mdBlock{Kind: "p", Text: strings.Join(para, " ")})
			para = nil
		}
	}
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "```"):
			flush()
			fence := trimmed[:len(trimmed)-len(strings.TrimLeft(trimmed, "`"))]
			var code []string
			for i++; i < len(lines) && strings.TrimSpace(lines[i]) != fence; i++ {
				code = append(code, lines[i])
			}
			out = append(out, mdBlock{Kind: "code", Text: strings.Join(code, "\n")})
		case trimmed == "":
			flush()
		case trimmed == "---":
			flush()
			out = append(out, mdBlock{Kind: "hr"})
		case strings.HasPrefix(trimmed, "#"):
			flush()
			n := len(trimmed) - len(strings.TrimLeft(trimmed, "#"))
			text := strings.TrimSpace(trimmed[n:])
			b := mdBlock{Kind: fmt.Sprintf("h%d", min(n, 6)), Text: text}
			if m := headingID.FindStringSubmatch(text); m != nil {
				b.Text, b.AnchorID = m[1], m[2]
			}
			out = append(out, b)
		case strings.HasPrefix(trimmed, "- "):
			flush()
			kind := "li"
			if strings.HasPrefix(line, "  ") {
				kind = "li2"
			}
			out = append(out, mdBlock{Kind: kind, Text: strings.TrimPrefix(trimmed, "- ")})
		default:
			para = append(para, trimmed)
		}
	}
	flush()
	return out
}

type span struct {
	Text, Href string
	Bold, Code bool
}

// parseInline handles backslash escapes, **bold**, `code` and [text](href).
func parseInline(s string) []span {
	var spans []span
	var cur strings.Builder
	bold := false
	flush := func() {
		if cur.Len() > 0 {
			spans = append(spans, span{Text: cur.String(), Bold: bold})
			cur.Reset()
		}
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch {
		case rs[i] == '\\' && i+1 < len(rs):
			i++
			cur.WriteRune(rs[i])
		case rs[i] == '*' && i+1 < len(rs) && rs[i+1] == '*':
			flush()
			bold = !bold
			i++
		case rs[i] == '[':
			if end, href, text := matchLink(rs, i); end > 0 {
				flush()
				spans = append(spans, span{Text: text, Href: href, Bold: bold})
				i = end
				continue
			}
			cur.WriteRune(rs[i])
		default:
			cur.WriteRune(rs[i])
		}
	}
	flush()
	return spans
}

// matchLink parses "[text](href)" at rs[i]; text keeps backslash escapes resolved. It returns the
// index of the closing parenthesis, or 0 when there is no link.
func matchLink(rs []rune, i int) (int, string, string) {
	var text strings.Builder
	j := i + 1
	for ; j < len(rs) && rs[j] != ']'; j++ {
		if rs[j] == '\\' && j+1 < len(rs) {
			j++
		}
		text.WriteRune(rs[j])
	}
	if j+1 >= len(rs) || rs[j+1] != '(' {
		return 0, "", ""
	}
	k := j + 2
	for ; k < len(rs) && rs[k] != ')'; k++ {
	}
	if k >= len(rs) {
		return 0, "", ""
	}
	return k, string(rs[j+2 : k]), text.String()
}

func safeHref(h string) bool {
	return strings.HasPrefix(h, "#") || strings.HasPrefix(h, "/") || strings.HasPrefix(h, "https://") || strings.HasPrefix(h, "http://")
}

func inlineHTML(s string) string {
	var b strings.Builder
	for _, sp := range parseInline(s) {
		t := html.EscapeString(sp.Text)
		if sp.Bold {
			t = "<strong>" + t + "</strong>"
		}
		if sp.Href != "" && safeHref(sp.Href) {
			t = `<a href="` + html.EscapeString(sp.Href) + `">` + t + "</a>"
		}
		b.WriteString(t)
	}
	return b.String()
}

// inlinePlain flattens inline markup to text for DOCX; links keep their target in parentheses.
func inlinePlain(s string) string {
	var b strings.Builder
	for _, sp := range parseInline(s) {
		b.WriteString(sp.Text)
		if sp.Href != "" {
			b.WriteString(" (" + sp.Href + ")")
		}
	}
	return b.String()
}

// markdownToHTML renders the subset as a standalone HTML page. All text is escaped; no raw
// HTML from the markdown is ever passed through.
func markdownToHTML(title, md string) []byte {
	var b bytes.Buffer
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + html.EscapeString(title) + "</title>\n")
	b.WriteString("<style>body{font-family:sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;line-height:1.5}pre{background:#f4f4f4;padding:.75rem;overflow:auto;white-space:pre-wrap}li li{margin-left:1rem}</style></head><body>\n")
	inList := false
	closeList := func() {
		if inList {
			b.WriteString("</ul>\n")
			inList = false
		}
	}
	for _, blk := range parseMarkdown(md) {
		if blk.Kind != "li" && blk.Kind != "li2" {
			closeList()
		}
		switch {
		case blk.Kind == "li" || blk.Kind == "li2":
			if !inList {
				b.WriteString("<ul>\n")
				inList = true
			}
			cls := ""
			if blk.Kind == "li2" {
				cls = ` class="sub"`
			}
			b.WriteString("<li" + cls + ">" + inlineHTML(blk.Text) + "</li>\n")
		case blk.Kind == "code":
			b.WriteString("<pre>" + html.EscapeString(blk.Text) + "</pre>\n")
		case blk.Kind == "hr":
			b.WriteString("<hr>\n")
		case blk.Kind == "p":
			b.WriteString("<p>" + inlineHTML(blk.Text) + "</p>\n")
		default: // heading
			id := ""
			if blk.AnchorID != "" {
				id = ` id="` + html.EscapeString(blk.AnchorID) + `"`
			}
			b.WriteString("<" + blk.Kind + id + ">" + inlineHTML(blk.Text) + "</" + blk.Kind + ">\n")
		}
	}
	closeList()
	b.WriteString("</body></html>\n")
	return b.Bytes()
}
