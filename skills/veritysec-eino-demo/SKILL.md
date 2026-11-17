---
name: veritysec-eino-demo
description: >-
  Fully-featured example skill package: SKILL.md + optional scripts/, references/, assets/ directories; verifies Eino skill and HTTP in-package paths (for authorized security testing and teaching only).
---

# VeritySec × Eino Full-Featured Skill Demo

This package conforms to [Agent Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview): **`SKILL.md` is the manifest + main instructions** (there is no separate `SKILL.yaml`). The same directory may contain **`scripts/`**, **`references/`**, **`assets/`** and other subdirectories (as long as paths are safe and do not exceed package depth/file count limits), which are read via **`ListPackageFiles` / `resource_path`** and the Eino local tools. See `FORMS.md` and `REFERENCE.md` for supplementary notes.

## Overview

Used for one-time verification of:

- HTTP `GET /api/skills` listing (`script_count`, `file_count`, `progressive`, etc. are derived/scanned results)
- `GET /api/skills/veritysec-eino-demo?depth=summary|full`
- `section=` maps to the **`##` headings** in `SKILL.md` or to the short ASCII-based id of the heading (e.g. `## Payload Samples` corresponds to `section=payload-samples`)
- The ADK **`skill`** tool within multi-agent sessions (and the optional local file tools) reading package-relative resources
- Eino `FilesystemSkillsRetriever` retrieval over package summaries, `##` chunks, and script entries

**Hard requirement**: any testing must have written authorization and must be limited to the agreed scope and time window.

## Authorized Testing Workflow

1. **Scope confirmation**: domains / IPs, endpoint list, prohibited actions (DoS, bulk data exfiltration, etc.).
2. **Baseline recording**: perform read-only probing of the agreed assets; save timestamps and summaries of raw requests/responses.
3. **Categorized testing**: split tasks by vulnerability type; reconfirm authorization boundaries before high-risk operations.
4. **Evidence and reporting**: attach reproduction steps, impact, and remediation advice to each finding; redact sensitive data.
5. **Wrap-up**: delete temporary accounts, clean up test data, hand over the report.

## Payload Samples

The following are **teaching placeholders**. Real testing must replace them with the target context and must not be used against unauthorized systems:

- SQLi probe (error-based): `"'` (observe whether a database error message is leaked)
- Reflected XSS (harmless form): `<script>alert(1)</script>` → in a lab environment it should be encoded or blocked by CSP
- Path traversal (read-only verification): `....//....//etc/passwd` (only in an authorized file-read scenario)

For the detailed list see `scripts/payloads.txt`.

## references/ and assets/

Used to verify that subdirectories other than `scripts/` are treated equally:

| Path | Purpose |
|------|------|
| `references/citations.md` | Citations and HTTP `resource_path` test notes |
| `assets/README.txt` | Placeholder resource (can be replaced with a real binary for file-read size limit testing) |

## Recommended Toolchain

| Phase | Tool examples |
|------|-----------|
| Proxying and replay | Burp Suite, mitmproxy |
| Scanning and directories | ffuf, nuclei (lower concurrency to comply with authorization) |
| Vulnerability verification | Custom PoCs, official CLIs (sqlmap, etc.) only within the authorized scope |
| Recording | Markdown + JSON snippet templates (see `scripts/report-snippet.json`) |

## Checklist and Verification

- [ ] Written authorization and test window are saved
- [ ] Files under `scripts/` match the references in the body
- [ ] The web UI or `GET /api/skills?...` can be used to verify the index; within multi-agent sessions, load the package with the **`skill`** tool to save tokens
- [ ] When details are needed, fetch the full text via the **`skill`** tool, or HTTP `depth=full`, `section=<heading or short id>`
- [ ] To get the original script text, use the local file tools or HTTP `resource_path=scripts/check-env.sh`
- [ ] `resource_path=references/citations.md` and `resource_path=assets/README.txt` are readable
