# Changelog

## Unreleased

### Added

- AI channels now support custom HTTP request headers, environment variable and session ID placeholders; saved authentication headers can be safely used for connection testing, with independent audit identity isolation from the main channel request headers, and custom headers do not follow cross-origin redirects.

- Support configuring single-agent, multi-agent, workflow, and async task execution timeout via `agent.task_timeout_minutes`: unconfigured defaults to 600 minutes, `0` means no limit, negative values reject loading; resumed runs restart the timer, individual tool timeouts remain independent.

- The single-item download button on the vulnerability list now includes a format selection dialog, supporting Markdown and Word (.docx); Word download reuses the vulnerability read permission and includes only the selected vulnerability (#365).

- Added single-agent and multi-agent async conversation API: returns a task receipt upon acceptance, client disconnection does not stop execution; supports per-user isolated idempotent submission, persistent status and result queries, explicit cancellation, and interrupted status after service restart. Synchronous interfaces remain compatible.

- At startup, automatically check all project management tables using the unified latest SQLite definitions: create missing tables, add missing columns, no need to maintain per-column migration lists; preserves existing data and extra tables/columns, rolls back and blocks startup on structure completion failure. HITL and notification tables are included in unified initialization; historical vulnerability foreign key migration preserves extra columns, indexes, triggers, and dependent records.

### Fixed

- Fixed WebShell batch liveness check getting stuck in “checking” due to request construction errors; use the connection's own ID to read saved credentials and restore the button after probe failure, continuing to process other connections.

- Fixed audit Agent failing to send requests to compatible gateways that do not support the thinking field; supports independent compatibility profiles, identifying default behavior by model and address.

- Fixed known officially-supported `none` OpenAI models still using server-default reasoning after disabling reasoning (#366): send by provider, endpoint, and model while preserving explicit disable parameters, overriding Planner and forced tool selection; preserves DeepSeek and third-party compatible gateway behavior, and clearly indicates tool call limitations requiring Responses.

- Prevent built-in admin from losing privileges: refuse to deactivate the built-in `admin` or remove its system administrator role; on failure, preserve original profile, permissions, and sessions; UI synchronously disables corresponding actions.

- Fixed asset management information-gathering sending unsupported `province` response field to FOFA default request causing query failure, unified to use `region`; compatible with legacy form/API field aliases, preserves imported asset provinces, and corrects intelligence field preset to `asn/org`.

- Fixed single-agent, multi-agent, role workflow, and batch tasks misidentifying lower-level call timeouts as whole task timeouts: only mark task timeout when the task context's own deadline expires, lower-level failures preserve original diagnostics; total time limit and existing retry strategy remain unchanged.

- C2 Profile and WebShell deletion of non-existent objects now uniformly returns 404; database failure during deletion returns a generic 500 message without exposing SQL errors; vulnerability and batch task lists return `[]` when no matching records exist, with HTTP contract regression tests added.

- Fixed multi-user editing of interception rules where old drafts overwrite others' modifications: same version can only be saved once successfully, conflicts preserve the draft and prompt refresh; API save must include the ETag/If-Match from the read.

- Fixed platform role update/deletion disconnecting all users: only revoke sessions of affected role members; name, description, and equivalent permission set updates keep sessions valid.

- Fixed Russian and other long-text causing dashboard status card, risk badge, and queue label overflow; sidebar and risk names wrap completely, layout adapts to card available width.

- Self-update recovery strictly validates recovery records, state, commits, and binary pairing before overwriting files; rejects missing, duplicate, or contradictory evidence, preserving recoverable state.
- Editing a stopped external MCP no longer unexpectedly starts the connection; start/stop, configuration editing, and app restart maintain consistent start/stop status.

- Login password show/hide button changed to an eye icon inside the input field; unified input field width and height, supports keyboard focus, 44px touch target, multilingual accessibility labels, and light/dark themes.
