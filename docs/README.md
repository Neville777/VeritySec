# VeritySec Documentation

VeritySec documentation is organized by user journey. Start with deployment, then move to the topic that matches your task.

## Documentation

### Choose a path

- **Try locally**: [Deployment](en-US/deployment.md) → [Configuration](en-US/configuration.md) → [Troubleshooting](en-US/troubleshooting.md)
- **Run in production**: [Configuration Profiles](en-US/configuration-profiles.md) → [Security Hardening](en-US/security-hardening.md) → [Runbooks](en-US/runbooks.md) → [Audit and Monitoring](en-US/audit-and-monitoring.md)
- **Integrate and automate**: [API Reference](en-US/api-reference.md) → [API Recipes](en-US/api-recipes.md) → [MCP Federation](en-US/mcp-federation.md)
- **Contribute code**: [Developer Guide](en-US/developer-guide.md) → [Testing](en-US/testing.md) → [Contributing](en-US/contributing-guide.md)

### Concepts and orchestration

- [Architecture](en-US/architecture.md)
- [Security Model](en-US/security-model.md)
- [Agents and Roles](en-US/agent-and-role-guide.md)
- [Skills](en-US/skills-guide.md)
- [Eino Multi-Agent](en-US/MULTI_AGENT_EINO.md)
- [Blackboard and Context Memory](en-US/blackboard-context-memory.md)
- [Agent Finalization](en-US/agent-finalization-best-practices.md)
- [Workflows](en-US/workflow-graph.md)
- [Tool Call Guard](en-US/tool-call-guard.md)
- [Tool Execution Governance](en-US/tool-execution-governance.md)
- [HITL Best Practices](en-US/hitl-best-practices.md)

### Feature guides

- [Asset Management](en-US/asset-management.md)
- [Resuming Project Tasks](en-US/project-resume.md)
- [Token Usage Analysis](en-US/token-usage-monitoring.md)
- [Knowledge Base](en-US/knowledge-base.md)
- [RBAC Administration](en-US/rbac.md)
- [Robot / Chatbot](en-US/robot.md)
- [Vision Analysis](en-US/VISION.md)
- [WebShell Management](en-US/webshell.md)
- [C2 Guide](en-US/c2.md)

### Development and release

- [Developer Guide](en-US/developer-guide.md)
- [Plugin Development](en-US/plugin-development.md)
- [Frontend i18n](en-US/frontend-i18n.md)
- [Testing](en-US/testing.md)
- [Contributing](en-US/contributing-guide.md)
- [Release Process](en-US/release-process.md)

## Documentation conventions

- Commands assume the repository root unless stated otherwise.
- Examples use placeholders; never commit real credentials or target systems without explicit authorization.
- Runtime behavior and configuration defaults are authoritative in `config.example.yaml` and the source code. If a document differs, report it as documentation drift.

### Public documentation scope

- Public docs serve users and contributors: usage guides, stable API and architecture references, compatibility notes, and release records. Keep internal task journals, conversation approvals, one-off review sheets, and local verification logs outside the repository.
