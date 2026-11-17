# Citations and External Links (Example)

This file verifies that the skill package's **`references/`** directory is correctly recognized by the list API, the HTTP `resource_path` parameter, and the multi-agent local file tools.

## Test Method (within an authorized environment)

1. The `package_files` in the response of `GET /api/skills/veritysec-eino-demo` should include `references/citations.md`.
2. `GET /api/skills/veritysec-eino-demo?resource_path=references/citations.md` should return the contents of this file.
3. In multi-agent mode with `eino_skills.filesystem_tools` enabled, this file should be readable via its relative path.

## Placeholder Reference

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) (link format example only)
