package report

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// Audience selects the template.
type Audience string

// Supported audiences.
const (
	Executive Audience = "executive"
	Technical Audience = "technical"
	Developer Audience = "developer"
)

// Format selects the output encoding.
type Format string

// Supported formats.
const (
	Markdown Format = "md"
	HTML     Format = "html"
	DOCX     Format = "docx"
)

// ParseAudience validates an audience name.
func ParseAudience(s string) (Audience, error) {
	switch a := Audience(strings.ToLower(strings.TrimSpace(s))); a {
	case Executive, Technical, Developer:
		return a, nil
	}
	return "", fmt.Errorf("audience must be executive, technical or developer")
}

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(strings.TrimSpace(s))); f {
	case Markdown, HTML, DOCX:
		return f, nil
	}
	return "", fmt.Errorf("format must be md, html or docx")
}

// ContentType returns the HTTP content type and file extension of a format.
func (f Format) ContentType() (contentType, ext string) {
	switch f {
	case HTML:
		return "text/html; charset=utf-8", "html"
	case DOCX:
		return MIME, "docx"
	}
	return "text/markdown; charset=utf-8", "md"
}

var funcs = template.FuncMap{"inline": mdEscape, "fenced": fenceText, "id": safeID, "nr": notRecorded}

var audienceTemplates = map[Audience]*template.Template{
	Executive: template.Must(template.New("executive").Funcs(funcs).Parse(executiveTemplate)),
	Technical: template.Must(template.New("technical").Funcs(funcs).Parse(technicalTemplate)),
	Developer: template.Must(template.New("developer").Funcs(funcs).Parse(developerTemplate)),
}

type renderInput struct {
	Data        *Dataset
	Audience    Audience
	GeneratedAt string
}

// RenderMarkdown renders the dataset for an audience. The same dataset and time always give
// byte-identical output.
func RenderMarkdown(d *Dataset, a Audience, generatedAt time.Time) ([]byte, error) {
	tpl, ok := audienceTemplates[a]
	if !ok {
		return nil, fmt.Errorf("unknown audience %q", a)
	}
	var buf bytes.Buffer
	in := renderInput{Data: d, Audience: a, GeneratedAt: generatedAt.UTC().Format("2006-01-02T15:04:05Z")}
	if err := tpl.Execute(&buf, in); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RenderEngagement renders the dataset in the requested audience and format. HTML and DOCX are
// derived from the same markdown, so all formats show identical content.
func RenderEngagement(d *Dataset, a Audience, f Format, generatedAt time.Time) ([]byte, error) {
	return RenderEngagementNarrative(d, a, f, generatedAt, "", "")
}

// RenderEngagementNarrative is RenderEngagement with an optional narrative (or a note saying
// it is missing) appended after the findings.
func RenderEngagementNarrative(d *Dataset, a Audience, f Format, generatedAt time.Time, narrative, note string) ([]byte, error) {
	md, err := RenderMarkdown(d, a, generatedAt)
	if err != nil {
		return nil, err
	}
	if extra := narrativeMarkdown(narrative, note); extra != "" {
		md = append(md, extra...)
	}
	switch f {
	case Markdown:
		return md, nil
	case HTML:
		return markdownToHTML("Engagement report: "+d.Engagement.Name, string(md)), nil
	case DOCX:
		return markdownToDocx(string(md))
	}
	return nil, fmt.Errorf("unknown format %q", f)
}

// markdownToDocx converts the template markdown subset to paragraphs and packages them.
func markdownToDocx(md string) ([]byte, error) {
	var body strings.Builder
	p := func(style, text string) {
		for _, line := range strings.Split(text, "\n") {
			body.WriteString(`<w:p><w:pPr><w:pStyle w:val="` + style + `"/></w:pPr><w:r><w:t xml:space="preserve">` + escaped(line) + `</w:t></w:r></w:p>`)
		}
	}
	for _, b := range parseMarkdown(md) {
		switch b.Kind {
		case "h1":
			p("Title", inlinePlain(b.Text))
		case "h2":
			p("Heading1", inlinePlain(b.Text))
		case "h3", "h4", "h5", "h6":
			p("Heading2", inlinePlain(b.Text))
		case "li":
			p("Normal", "• "+inlinePlain(b.Text))
		case "li2":
			p("Normal", "    - "+inlinePlain(b.Text))
		case "code":
			p("Normal", b.Text)
		case "hr":
		default:
			p("Normal", inlinePlain(b.Text))
		}
	}
	return packageDocx(body.String())
}
