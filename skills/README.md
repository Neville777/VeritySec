# Skills Directory (Agent Skills / Eino)

- Each skill is a **subdirectory**. The root must contain **`SKILL.md`** (YAML front matter: `name`, `description`, plus a Markdown body). See [agentskills.io](https://agentskills.io/specification.md).
- **The directory name must match `name`**.
- **Runtime loading**: In **Eino DeepAgent (multi-agent)** sessions, the ADK **`skill` middleware** discloses skills progressively (the system prompt lists each skill's name/description, and the model then calls the **`skill`** tool to fetch the full `SKILL.md`). Optionally enable **`multi_agent.eino_skills.filesystem_tools`** to use the same `read_file` / `execute` etc. to access package scripts and resources on this machine.
- **Web management**: HTTP `/api/skills/*` is still used for listing, editing, and uploading package files (implemented in `internal/skillpackage`, not MCP).
- **Runtime**: Within multi-agent (DeepAgent) sessions, skills are loaded progressively via the ADK **`skill`** tool. The single-agent MCP loop does not include Skills; enable multi-agent mode or wait for a future single-agent Eino path.
