# API / Reference (Example)

## HTTP `/api/skills/{id}`

- `resource_path`: package-relative path, e.g. `FORMS.md`, `scripts/payloads.txt`.
- `depth=summary`: returns only the summary and directory listing, suitable for the first retrieval pass.

## Multi-Agent Runtime

- Use the Eino ADK **`skill`** tool to load skill packages progressively. Optionally enable `multi_agent.eino_skills.filesystem_tools` to access files inside the package.

## Links

- [Agent Skills Overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
