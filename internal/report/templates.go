package report

// Templates only print dataset fields. They never compute numbers; every figure comes from
// Dataset. Text taken from the database passes through the inline/block functions so it cannot
// inject markdown structure.

const commonHeader = `{{define "scope"}}## Engagement
- Target: {{nr .Engagement.Target}}
- Objective: {{nr .Engagement.Objective}}
- Status: {{inline .Engagement.Status}}
- Authorization: {{nr .Engagement.AuthorizationNote}}
- Scope, included:{{range .Engagement.ScopeIncluded}}
  - {{inline .}}{{else}} none recorded{{end}}
- Scope, excluded:{{range .Engagement.ScopeExcluded}}
  - {{inline .}}{{else}} none recorded{{end}}
- Limits:{{range .Engagement.Limits}}
  - {{inline .}}{{else}} none recorded{{end}}
{{end}}{{define "counts"}}## Findings by severity and status
Total findings: {{.Counts.Total}} (open or confirmed: {{.Counts.Open}})

{{range .Counts.BySeverity}}- {{inline .Name}}: {{.Count}}
{{end}}
{{range .Counts.ByStatus}}- Status {{inline .Name}}: {{.Count}}
{{else}}- No findings recorded
{{end}}{{end}}{{define "confidence"}}## Findings by confidence
{{range .ConfidenceGroups}}- {{inline .Name}}: {{.Count}}
{{end}}{{end}}{{define "coverage"}}## Coverage
Categories without evidence are reported as not tested. No category is reported as passing.

{{range .Coverage}}- {{inline .Category}}: {{.StateLabel}} ({{.FindingCount}} finding(s), {{.EvidenceCount}} evidence item(s))
{{end}}
Evidence items: {{.Evidence.Total}} ({{.Evidence.Linked}} linked to findings, {{.Evidence.Unlinked}} not linked)
{{end}}{{define "stages"}}## Assessment stages
{{range .Stages}}- {{.Order}}. {{inline .Title}}: {{inline .Status}} ({{.EvidenceCount}} evidence item(s)){{if .Attention}} - {{inline .Attention}}{{end}}
{{else}}- No stage data
{{end}}{{end}}{{define "tools"}}## Tool activity
Tool executions: {{.Tools.Total}}, failed or blocked: {{.Tools.Failed}}
{{range .Tools.Tools}}- {{inline .Name}}: {{.Count}} call(s)
{{else}}- No tool executions recorded for conversations attached to this engagement
{{end}}{{end}}{{define "assets"}}## Assets
{{range .Assets}}- {{inline .Name}} (protocol {{inline .Protocol}}, criticality {{inline .Criticality}}, status {{inline .Status}})
{{else}}- No assets linked
{{end}}{{end}}{{define "footer"}}
---
Generated: {{.GeneratedAt}} | Engagement: {{.Data.Engagement.ID}} | Dataset hash: {{.Data.Hash}} | Audience: {{.Audience}}
{{end}}`

const executiveTemplate = commonHeader + `{{with .Data}}# Executive summary: {{inline .Engagement.Name}}

## Overall risk
**{{.Risk.Overall}}**. {{inline .Risk.Basis}}

{{template "scope" .}}
{{template "stages" .}}
{{template "counts" .}}
{{template "confidence" .}}
## Top risks
{{range .TopRisks}}- **{{inline .Severity}}**: {{inline .Title}} (affects {{inline .AffectedAsset}}). {{inline .Summary}}
{{else}}- No open or confirmed findings
{{end}}
## Decisions needed
{{range .Decisions}}- {{inline .}}
{{else}}- None identified from the recorded data
{{end}}
{{template "coverage" .}}
## All findings
{{range .Findings}}- [{{.Index}}. {{inline .Title}}](/api/vulnerabilities/{{id .ID}}) ({{inline .Severity}}, {{inline .Status}}, {{inline .ConfidenceLabel}})
{{else}}- No findings recorded
{{end}}{{end}}{{template "footer" .}}`

const technicalTemplate = commonHeader + `{{with .Data}}# Technical report: {{inline .Engagement.Name}}

{{template "scope" .}}
{{template "stages" .}}
{{template "counts" .}}
{{template "assets" .}}
{{template "tools" .}}
{{template "coverage" .}}
## Findings
{{range .Findings}}
### {{.Index}}. {{inline .Title}} {#finding-{{id .ID}}}
- ID: {{id .ID}}
- Severity: {{inline .Severity}}
- Status: {{inline .Status}}
- Confidence: {{inline .ConfidenceLabel}}
- Type: {{inline .Type}}
- Affected asset: {{inline .AffectedAsset}}
- Evidence references:{{range .Evidence}}
  - {{id .ID}} ({{id .Kind}}, sha256 {{.SHA256}}): {{inline .Title}}{{else}} none attached{{end}}
- Claims: {{inline .ClaimsNote}}{{range .Claims}}
  - [{{inline .Status}}] {{inline .Text}} (evidence:{{range .EvidenceIDs}} {{id .}}{{else}} none{{end}}){{if .Reason}} - reason: {{inline .Reason}}{{end}}{{end}}{{with .Verification}}
- Verification: {{inline .Status}} ({{inline .At}}){{range .Reasons}}
  - {{inline .}}{{end}}{{end}}

Description:

{{fenced .Description}}

Preconditions:

{{fenced .Preconditions}}

Reproduction notes:

{{fenced .ReproSteps}}

Impact:

{{fenced .Impact}}

Retest notes:

{{fenced .RetestNotes}}
{{else}}No findings recorded.
{{end}}{{end}}{{template "footer" .}}`

const developerTemplate = commonHeader + `{{with .Data}}# Fix tickets: {{inline .Engagement.Name}}

Open or confirmed findings: {{.Counts.Open}} of {{.Counts.Total}} recorded. Closed findings (fixed, ignored, false positive) are not ticketed: {{.Counts.Closed}}.
{{range .Findings}}{{if .Open}}
## Ticket {{.Index}}: {{inline .Title}} {#finding-{{id .ID}}}
- Finding ID: {{id .ID}}
- Severity: {{inline .Severity}}
- Status: {{inline .Status}}
- Affected component: {{inline .AffectedAsset}}
- Evidence references:{{range .Evidence}}
  - {{id .ID}} (sha256 {{.SHA256}})
{{else}} none attached{{end}}

Actual behaviour:

{{fenced .Description}}

Expected behaviour: the weakness described above is not reproducible against the affected component.

Reproduction:

{{fenced .ReproSteps}}

Suggested fix:

{{fenced .Recommendation}}

Acceptance criteria:
- The reproduction steps above no longer demonstrate the weakness.
- Retest evidence is attached to finding {{id .ID}}.
- The finding status is set to fixed after retest.
{{end}}{{else}}
No findings recorded.
{{end}}{{end}}{{template "footer" .}}`
