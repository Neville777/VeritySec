-- Latest SQLite structure. Update these definitions when adding tables or columns.

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    dedup_key TEXT NOT NULL UNIQUE,
    project_id TEXT,
    host TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    domain TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    server TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    province TEXT NOT NULL DEFAULT '',
    city TEXT NOT NULL DEFAULT '',
    responsible_person TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    business_system TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    source_query TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'unassessed',
    tags_json TEXT NOT NULL DEFAULT '[]',
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    owner_user_id TEXT,
    last_scan_at DATETIME,
    last_scan_conversation_id TEXT NOT NULL DEFAULT '',
    last_scan_queue_id TEXT NOT NULL DEFAULT '',
    last_scan_task_id TEXT NOT NULL DEFAULT '',
    engagement_id TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);

CREATE TABLE attack_chain_edges (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    weight INTEGER DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (source_node_id) REFERENCES attack_chain_nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (target_node_id) REFERENCES attack_chain_nodes(id) ON DELETE CASCADE
);

CREATE TABLE attack_chain_nodes (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    node_type TEXT NOT NULL,
    node_name TEXT NOT NULL,
    tool_execution_id TEXT,
    metadata TEXT,
    risk_score INTEGER DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (tool_execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL
);

CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    created_at DATETIME NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'admin',
    session_hint TEXT,
    client_ip TEXT,
    user_agent TEXT,
    resource_type TEXT,
    resource_id TEXT,
    message TEXT NOT NULL,
    detail_json TEXT
);

CREATE TABLE batch_task_queues (
    id TEXT PRIMARY KEY,
    title TEXT,
    role TEXT,
    agent_mode TEXT NOT NULL DEFAULT 'eino_single',
    hitl_policy TEXT NOT NULL DEFAULT '',
    schedule_mode TEXT NOT NULL DEFAULT 'manual',
    cron_expr TEXT,
    next_run_at DATETIME,
    schedule_enabled INTEGER NOT NULL DEFAULT 1,
    last_schedule_trigger_at DATETIME,
    last_schedule_error TEXT,
    last_run_error TEXT,
    project_id TEXT,
    concurrency INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    started_at DATETIME,
    completed_at DATETIME,
    current_index INTEGER NOT NULL DEFAULT 0,
    owner_user_id TEXT
);

CREATE TABLE batch_tasks (
    id TEXT PRIMARY KEY,
    queue_id TEXT NOT NULL,
    message TEXT NOT NULL,
    conversation_id TEXT,
    status TEXT NOT NULL,
    started_at DATETIME,
    completed_at DATETIME,
    error TEXT,
    result TEXT,
    FOREIGN KEY (queue_id) REFERENCES batch_task_queues(id) ON DELETE CASCADE
);

CREATE TABLE c2_events (
    id TEXT PRIMARY KEY,
    level TEXT NOT NULL DEFAULT 'info',
    category TEXT NOT NULL,
    session_id TEXT,
    task_id TEXT,
    message TEXT NOT NULL,
    data_json TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE c2_files (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    task_id TEXT,
    direction TEXT NOT NULL,
    remote_path TEXT NOT NULL,
    local_path TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    sha256 TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES c2_sessions(id) ON DELETE CASCADE
);

CREATE TABLE c2_http_session_auth (
    implant_uuid TEXT PRIMARY KEY,
    listener_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    FOREIGN KEY (listener_id) REFERENCES c2_listeners(id) ON DELETE CASCADE
);

CREATE TABLE c2_listeners (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    bind_host TEXT NOT NULL DEFAULT '127.0.0.1',
    bind_port INTEGER NOT NULL,
    profile_id TEXT,
    encryption_key TEXT NOT NULL DEFAULT '',
    implant_token TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'stopped',
    config_json TEXT NOT NULL DEFAULT '{}',
    remark TEXT NOT NULL DEFAULT '',
    owner_user_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at DATETIME,
    last_error TEXT
);

CREATE TABLE c2_payload_artifacts (
    filename TEXT PRIMARY KEY,
    payload_id TEXT NOT NULL,
    listener_id TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE c2_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    uris_json TEXT NOT NULL DEFAULT '[]',
    request_headers_json TEXT,
    response_headers_json TEXT,
    body_template TEXT,
    jitter_min_ms INTEGER DEFAULT 0,
    jitter_max_ms INTEGER DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE c2_sessions (
    id TEXT PRIMARY KEY,
    listener_id TEXT NOT NULL,
    implant_uuid TEXT NOT NULL UNIQUE,
    hostname TEXT,
    username TEXT,
    os TEXT,
    arch TEXT,
    pid INTEGER DEFAULT 0,
    process_name TEXT,
    is_admin INTEGER DEFAULT 0,
    internal_ip TEXT,
    external_ip TEXT,
    user_agent TEXT,
    sleep_seconds INTEGER NOT NULL DEFAULT 5,
    jitter_percent INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_check_in DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata_json TEXT DEFAULT '{}',
    note TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (listener_id) REFERENCES c2_listeners(id) ON DELETE CASCADE
);

CREATE TABLE c2_tasks (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    task_type TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued',
    result_text TEXT,
    result_blob_path TEXT,
    error TEXT,
    source TEXT NOT NULL DEFAULT 'manual',
    conversation_id TEXT,
    approval_status TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at DATETIME,
    started_at DATETIME,
    completed_at DATETIME,
    duration_ms INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES c2_sessions(id) ON DELETE CASCADE
);

CREATE TABLE chat_upload_artifacts (
    relative_path TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    role_name TEXT NOT NULL DEFAULT 'default',
    agent_mode TEXT NOT NULL DEFAULT 'eino_single',
    last_react_input TEXT,
    last_react_output TEXT,
    pinned INTEGER DEFAULT 0,
    webshell_connection_id TEXT,
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    owner_user_id TEXT,
    engagement_id TEXT
);

CREATE TABLE engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    objective TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    scope_json TEXT NOT NULL DEFAULT '{}',
    limits_json TEXT NOT NULL DEFAULT '{}',
    authorization_note TEXT NOT NULL DEFAULT '',
    owner_user_id TEXT,
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE assessment_stages (
    engagement_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at DATETIME,
    finished_at DATETIME,
    note TEXT NOT NULL DEFAULT '',
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    initiated_by TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (engagement_id, stage),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE TABLE stage_tasks (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    required INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','done','skipped')),
    reason TEXT NOT NULL DEFAULT '',
    proposed_by TEXT NOT NULL CHECK (proposed_by IN ('model','human')),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX idx_stage_tasks_engagement_stage ON stage_tasks(engagement_id, stage);

CREATE TABLE run_checkpoints (
    id TEXT PRIMARY KEY,
    message_id TEXT,
    conversation_id TEXT,
    engagement_id TEXT,
    stage TEXT,
    kind TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE run_events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    conversation_id TEXT,
    engagement_id TEXT,
    seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    stage TEXT,
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL,
    UNIQUE(run_id, seq)
);

CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    finding_id TEXT,
    asset_id TEXT,
    kind TEXT NOT NULL DEFAULT 'other',
    source_tool TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    storage_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    origin TEXT NOT NULL DEFAULT 'manual',
    tool_execution_id TEXT,
    stage TEXT,
    storage_deleted INTEGER DEFAULT 0,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE TABLE finding_claims (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL DEFAULT 0,
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified','supported','disputed','unsupported')),
    status_reason TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE finding_claim_evidence (
    claim_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (claim_id, evidence_id)
);

CREATE TABLE finding_verifications (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reasons TEXT NOT NULL DEFAULT '[]',
    primary_verdicts TEXT NOT NULL DEFAULT '[]',
    challenger_verdicts TEXT NOT NULL DEFAULT '[]',
    primary_model TEXT NOT NULL DEFAULT '',
    challenger_model TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);

CREATE TABLE hitl_conversation_configs (
    conversation_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    mode TEXT NOT NULL DEFAULT 'off',
    sensitive_tools TEXT NOT NULL DEFAULT '[]',
    timeout_seconds INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL,
    reviewer TEXT NOT NULL DEFAULT 'human'
);

CREATE TABLE hitl_interrupts (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    message_id TEXT,
    mode TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_call_id TEXT,
    payload TEXT,
    status TEXT NOT NULL,
    reviewer TEXT NOT NULL DEFAULT 'human',
    decision TEXT,
    decision_comment TEXT,
    created_at DATETIME NOT NULL,
    decided_at DATETIME,
    decided_by TEXT NOT NULL DEFAULT 'human'
);

CREATE TABLE knowledge_retrieval_logs (
    id TEXT PRIMARY KEY,
    conversation_id TEXT,
    message_id TEXT,
    query TEXT NOT NULL,
    risk_type TEXT,
    retrieved_items TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE SET NULL
);

CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    mcp_execution_ids TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    reasoning_content TEXT,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE model_token_usage (
    id TEXT PRIMARY KEY,
    process_detail_id TEXT NOT NULL UNIQUE,
    message_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    project_id TEXT,
    source TEXT NOT NULL DEFAULT '',
    orchestration TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    model_calls INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (process_detail_id) REFERENCES process_details(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);

CREATE TABLE notification_reads_by_user (
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    read_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id, event_id)
);

CREATE TABLE process_details (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT,
    data TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE project_fact_edges (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    source_fact_key TEXT NOT NULL,
    target_fact_key TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'tentative',
    source_conversation_id TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(project_id, source_fact_key, target_fact_key, edge_type)
);

CREATE TABLE project_facts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    fact_key TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'note',
    summary TEXT NOT NULL DEFAULT '',
    body TEXT,
    confidence TEXT NOT NULL DEFAULT 'tentative',
    source_conversation_id TEXT,
    source_message_id TEXT,
    pinned INTEGER NOT NULL DEFAULT 0,
    related_vulnerability_id TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    UNIQUE(project_id, fact_key)
);

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    scope_json TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    pinned INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    owner_user_id TEXT
);

CREATE TABLE rbac_permissions (
    key TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);

CREATE TABLE rbac_resource_assignments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE,
    UNIQUE(user_id, resource_type, resource_id)
);

CREATE TABLE rbac_role_permissions (
    role_id TEXT NOT NULL,
    permission_key TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (role_id, permission_key),
    FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_key) REFERENCES rbac_permissions(key) ON DELETE CASCADE
);

CREATE TABLE rbac_roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT 'assigned',
    is_system INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE rbac_user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE
);

CREATE TABLE rbac_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    is_builtin INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE user_api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, provider),
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE
);

CREATE TABLE access_requests (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    reviewed_by TEXT NOT NULL DEFAULT '',
    reviewed_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE report_snapshots (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    format TEXT NOT NULL,
    audience TEXT NOT NULL,
    dataset_json TEXT NOT NULL,
    dataset_sha256 TEXT NOT NULL,
    rendered_path TEXT NOT NULL DEFAULT '',
    narrative_text TEXT NOT NULL DEFAULT '',
    narrative_note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);

CREATE TABLE robot_binding_codes (
    code_hash TEXT PRIMARY KEY,
    rbac_user_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (rbac_user_id) REFERENCES rbac_users(id) ON DELETE CASCADE
);

CREATE TABLE robot_user_bindings (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    rbac_user_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (rbac_user_id) REFERENCES rbac_users(id) ON DELETE CASCADE,
    UNIQUE(platform, external_user_id)
);

CREATE TABLE robot_user_sessions (
    session_key TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    role_name TEXT NOT NULL DEFAULT 'default',
    agent_mode TEXT NOT NULL DEFAULT 'eino_single',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE skill_stats (
    skill_name TEXT PRIMARY KEY,
    total_calls INTEGER NOT NULL DEFAULT 0,
    success_calls INTEGER NOT NULL DEFAULT 0,
    failed_calls INTEGER NOT NULL DEFAULT 0,
    last_call_time DATETIME,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tool_executions (
    id TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL,
    arguments TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    error TEXT,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    duration_ms INTEGER,
    partial_output TEXT,
    partial_output_bytes INTEGER NOT NULL DEFAULT 0,
    partial_output_truncated INTEGER NOT NULL DEFAULT 0,
    partial_output_updated_at DATETIME,
    owner_user_id TEXT,
    conversation_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tool_stats (
    tool_name TEXT PRIMARY KEY,
    total_calls INTEGER NOT NULL DEFAULT 0,
    success_calls INTEGER NOT NULL DEFAULT 0,
    failed_calls INTEGER NOT NULL DEFAULT 0,
    last_call_time DATETIME,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,
    conversation_id TEXT,
    conversation_tag TEXT,
    task_tag TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    vulnerability_type TEXT,
    target TEXT,
    preconditions TEXT,
    reproduction_steps TEXT,
    evidence TEXT,
    impact TEXT,
    recommendation TEXT,
    retest_notes TEXT,
    retest_log TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'potential',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    project_id TEXT,
    owner_user_id TEXT,
    engagement_id TEXT,
    source_status TEXT NOT NULL DEFAULT 'unlinked',
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL
);

CREATE TABLE vulnerability_alert_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vulnerability_id, platform, external_user_id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE
);

CREATE TABLE vulnerability_alert_subscriptions (
    user_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    min_severity TEXT NOT NULL DEFAULT 'high',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE
);

CREATE TABLE vulnerability_retests (
    conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    source_conversation_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    source_project_id TEXT NOT NULL DEFAULT '',
    pending_prompt TEXT NOT NULL DEFAULT ''
);

CREATE TABLE webshell_connection_states (
    connection_id TEXT PRIMARY KEY,
    state_json TEXT NOT NULL DEFAULT '{}',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (connection_id) REFERENCES webshell_connections(id) ON DELETE CASCADE
);

CREATE TABLE webshell_connections (
    id TEXT PRIMARY KEY,
    project_id TEXT,
    url TEXT NOT NULL,
    password TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'php',
    method TEXT NOT NULL DEFAULT 'post',
    cmd_param TEXT NOT NULL DEFAULT '',
    remark TEXT NOT NULL DEFAULT '',
    encoding TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    owner_user_id TEXT
);

CREATE TABLE workflow_definitions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    graph_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE workflow_node_runs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL,
    input_json TEXT,
    output_json TEXT,
    error TEXT,
    started_at DATETIME NOT NULL,
    finished_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
);

CREATE TABLE workflow_package_imports (
    id TEXT PRIMARY KEY,
    inspection_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('create','keep_existing','overwrite','rename')),
    source_workflow_id TEXT NOT NULL,
    target_workflow_id TEXT NOT NULL,
    resulting_workflow_id TEXT,
    result TEXT NOT NULL CHECK (result IN ('created','overwritten','renamed','kept_existing','skipped_identical','failed')),
    error_code TEXT,
    error_message TEXT,
    created_at DATETIME NOT NULL,
    applied_at DATETIME,
    FOREIGN KEY (inspection_id) REFERENCES workflow_package_inspections(id)
);

CREATE TABLE workflow_package_inspections (
    id TEXT PRIMARY KEY,
    package_hash TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    workflow_payload_json TEXT NOT NULL,
    inspection_json TEXT NOT NULL,
    source_workflow_id TEXT NOT NULL,
    source_revision INTEGER NOT NULL,
    source_content_hash TEXT NOT NULL,
    source_graph_hash TEXT NOT NULL,
    local_conflict_state TEXT NOT NULL CHECK (local_conflict_state IN ('none','identical','id_conflict')),
    local_workflow_id TEXT,
    local_content_hash TEXT,
    local_graph_hash TEXT,
    created_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('ready','consumed','expired')),
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME
);

CREATE TABLE workflow_runs (
    id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    workflow_version INTEGER NOT NULL DEFAULT 1,
    conversation_id TEXT,
    project_id TEXT,
    role_id TEXT,
    status TEXT NOT NULL,
    input_json TEXT,
    output_json TEXT,
    error TEXT,
    pending_hitl_node_id TEXT,
    pending_hitl_json TEXT,
    started_at DATETIME NOT NULL,
    finished_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL
);

CREATE INDEX idx_assets_domain ON assets(domain);

CREATE INDEX idx_assets_ip ON assets(ip);

CREATE INDEX idx_assets_last_scan ON assets(last_scan_at);

CREATE INDEX idx_assets_last_seen ON assets(last_seen_at);

CREATE INDEX idx_assets_owner ON assets(owner_user_id);

CREATE INDEX idx_assets_project ON assets(project_id);

CREATE INDEX idx_assets_risk_level ON assets(risk_level);

CREATE INDEX idx_assets_risk_score ON assets(risk_score);

CREATE INDEX idx_assets_status ON assets(status);

CREATE INDEX idx_assets_vulnerability_count ON assets(vulnerability_count);

CREATE INDEX idx_audit_logs_action ON audit_logs(action);

CREATE INDEX idx_audit_logs_category ON audit_logs(category);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

CREATE INDEX idx_audit_logs_result ON audit_logs(result);

CREATE INDEX idx_batch_task_queues_created_at ON batch_task_queues(created_at);

CREATE INDEX idx_batch_task_queues_title ON batch_task_queues(title);

CREATE INDEX idx_batch_tasks_queue_id ON batch_tasks(queue_id);

CREATE INDEX idx_c2_events_category ON c2_events(category);

CREATE INDEX idx_c2_events_created_at ON c2_events(created_at);

CREATE INDEX idx_c2_events_session ON c2_events(session_id);

CREATE INDEX idx_c2_files_session ON c2_files(session_id);

CREATE INDEX idx_c2_listeners_created_at ON c2_listeners(created_at);

CREATE INDEX idx_c2_listeners_project_id ON c2_listeners(project_id);

CREATE INDEX idx_c2_listeners_status ON c2_listeners(status);

CREATE INDEX idx_c2_payload_artifacts_listener ON c2_payload_artifacts(listener_id);

CREATE INDEX idx_c2_sessions_last_check_in ON c2_sessions(last_check_in);

CREATE INDEX idx_c2_sessions_listener ON c2_sessions(listener_id);

CREATE INDEX idx_c2_sessions_status ON c2_sessions(status);

CREATE INDEX idx_c2_tasks_conversation ON c2_tasks(conversation_id);

CREATE INDEX idx_c2_tasks_created_at ON c2_tasks(created_at);

CREATE INDEX idx_c2_tasks_session ON c2_tasks(session_id);

CREATE INDEX idx_c2_tasks_status ON c2_tasks(status);

CREATE INDEX idx_chain_edges_conversation ON attack_chain_edges(conversation_id);

CREATE INDEX idx_chain_edges_source ON attack_chain_edges(source_node_id);

CREATE INDEX idx_chain_edges_target ON attack_chain_edges(target_node_id);

CREATE INDEX idx_chain_nodes_conversation ON attack_chain_nodes(conversation_id);

CREATE INDEX idx_chat_upload_artifacts_conversation ON chat_upload_artifacts(conversation_id);

CREATE INDEX idx_chat_upload_artifacts_owner ON chat_upload_artifacts(owner_user_id);

CREATE INDEX idx_conversations_pinned ON conversations(pinned);

CREATE INDEX idx_conversations_project_id ON conversations(project_id);

CREATE INDEX idx_engagements_project_id ON engagements(project_id);

CREATE INDEX idx_conversations_updated_at ON conversations(updated_at);

CREATE INDEX idx_knowledge_retrieval_logs_conversation ON knowledge_retrieval_logs(conversation_id);

CREATE INDEX idx_knowledge_retrieval_logs_created_at ON knowledge_retrieval_logs(created_at);

CREATE INDEX idx_knowledge_retrieval_logs_message ON knowledge_retrieval_logs(message_id);

CREATE INDEX idx_messages_conversation_id ON messages(conversation_id);

CREATE INDEX idx_model_token_usage_conversation ON model_token_usage(conversation_id);

CREATE INDEX idx_model_token_usage_created_at ON model_token_usage(created_at);

CREATE INDEX idx_model_token_usage_model ON model_token_usage(model);

CREATE INDEX idx_model_token_usage_project ON model_token_usage(project_id);

CREATE INDEX idx_notification_reads_user_read_at ON notification_reads_by_user(user_id, read_at DESC);

CREATE INDEX idx_process_details_conversation_id ON process_details(conversation_id);

CREATE INDEX idx_process_details_message_id ON process_details(message_id);

CREATE INDEX idx_project_fact_edges_project ON project_fact_edges(project_id);

CREATE INDEX idx_project_fact_edges_source ON project_fact_edges(project_id, source_fact_key);

CREATE INDEX idx_project_fact_edges_target ON project_fact_edges(project_id, target_fact_key);

CREATE INDEX idx_project_facts_confidence ON project_facts(confidence);

CREATE INDEX idx_project_facts_project_id ON project_facts(project_id);

CREATE INDEX idx_project_facts_related_vuln ON project_facts(related_vulnerability_id);

CREATE INDEX idx_projects_status ON projects(status);

CREATE INDEX idx_projects_updated_at ON projects(updated_at);

CREATE INDEX idx_rbac_assignments_resource ON rbac_resource_assignments(resource_type, resource_id);

CREATE INDEX idx_rbac_assignments_user_resource ON rbac_resource_assignments(user_id, resource_type, resource_id);

CREATE INDEX idx_rbac_role_permissions_role ON rbac_role_permissions(role_id);

CREATE INDEX idx_rbac_user_roles_user ON rbac_user_roles(user_id);

CREATE INDEX idx_report_snapshots_engagement ON report_snapshots(engagement_id, created_at);

CREATE INDEX idx_robot_binding_codes_expiry ON robot_binding_codes(expires_at);

CREATE INDEX idx_robot_user_bindings_user ON robot_user_bindings(rbac_user_id);

CREATE INDEX idx_robot_user_sessions_updated_at ON robot_user_sessions(updated_at);

CREATE INDEX idx_run_checkpoints_message ON run_checkpoints(message_id);

CREATE INDEX idx_run_events_conversation ON run_events(conversation_id);

CREATE INDEX idx_run_events_engagement ON run_events(engagement_id);

CREATE INDEX idx_run_checkpoints_engagement ON run_checkpoints(engagement_id);

CREATE INDEX idx_tool_executions_conversation ON tool_executions(conversation_id);

CREATE INDEX idx_tool_executions_owner ON tool_executions(owner_user_id);

CREATE INDEX idx_tool_executions_start_time ON tool_executions(start_time);

CREATE INDEX idx_tool_executions_status ON tool_executions(status);

CREATE INDEX idx_tool_executions_tool_name ON tool_executions(tool_name);

CREATE INDEX idx_vulnerabilities_conversation_id ON vulnerabilities(conversation_id);

CREATE INDEX idx_vulnerabilities_conversation_tag ON vulnerabilities(conversation_tag);

CREATE INDEX idx_vulnerabilities_created_at ON vulnerabilities(created_at);

CREATE INDEX idx_vulnerabilities_project_id ON vulnerabilities(project_id);

CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);

CREATE INDEX idx_vulnerabilities_status ON vulnerabilities(status);

CREATE INDEX idx_vulnerabilities_task_tag ON vulnerabilities(task_tag);

CREATE INDEX idx_webshell_connection_states_updated_at ON webshell_connection_states(updated_at);

CREATE INDEX idx_webshell_connections_created_at ON webshell_connections(created_at);

CREATE INDEX idx_webshell_connections_project_id ON webshell_connections(project_id);

CREATE INDEX idx_workflow_definitions_enabled ON workflow_definitions(enabled);

CREATE INDEX idx_workflow_definitions_updated_at ON workflow_definitions(updated_at);

CREATE INDEX idx_workflow_node_runs_run ON workflow_node_runs(run_id);

CREATE INDEX idx_workflow_package_inspections_creator_expiry ON workflow_package_inspections(created_by, expires_at);

CREATE INDEX idx_workflow_runs_conversation ON workflow_runs(conversation_id);

CREATE INDEX idx_workflow_runs_status ON workflow_runs(status);

CREATE INDEX idx_workflow_runs_workflow ON workflow_runs(workflow_id);

CREATE UNIQUE INDEX uq_workflow_package_imports_actor_key ON workflow_package_imports(actor_user_id, idempotency_key);

CREATE UNIQUE INDEX uq_workflow_package_imports_inspection_success ON workflow_package_imports(inspection_id) WHERE result IN ('created','overwritten','renamed','kept_existing','skipped_identical');

CREATE INDEX idx_engagements_owner ON engagements(owner_user_id);

CREATE INDEX idx_evidence_engagement ON evidence(engagement_id);

CREATE INDEX idx_evidence_finding ON evidence(finding_id);

CREATE INDEX idx_finding_claims_vulnerability ON finding_claims(vulnerability_id, position);

CREATE INDEX idx_finding_claims_engagement ON finding_claims(engagement_id);

CREATE INDEX idx_finding_claim_evidence_evidence ON finding_claim_evidence(evidence_id);

CREATE INDEX idx_finding_verifications_vulnerability ON finding_verifications(vulnerability_id, created_at);

CREATE INDEX idx_conversations_engagement ON conversations(engagement_id);

CREATE INDEX idx_vulnerabilities_engagement ON vulnerabilities(engagement_id);
CREATE INDEX idx_assets_engagement ON assets(engagement_id);

CREATE TABLE asset_relationships (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    from_asset_id TEXT NOT NULL,
    to_asset_id TEXT NOT NULL,
    relation_type TEXT NOT NULL CHECK (relation_type IN ('RESOLVES_TO','HOSTS_SERVICE','RUNS_TECHNOLOGY','SUBDOMAIN_OF','EXPOSES_PORT','CONNECTS_TO')),
    confidence TEXT NOT NULL CHECK (confidence IN ('inferred','observed','manual','verified')),
    evidence_id TEXT,
    tool_execution_id TEXT,
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    UNIQUE (engagement_id, from_asset_id, to_asset_id, relation_type),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (from_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (to_asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
);

CREATE INDEX idx_asset_relationships_engagement ON asset_relationships(engagement_id);
CREATE INDEX idx_asset_relationships_from ON asset_relationships(from_asset_id);
CREATE INDEX idx_asset_relationships_to ON asset_relationships(to_asset_id);

CREATE TABLE approval_requests (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL DEFAULT '',
    message_id TEXT NOT NULL DEFAULT '',
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    arguments_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired')),
    requested_at DATETIME NOT NULL,
    decided_at DATETIME,
    decided_by TEXT NOT NULL DEFAULT '',
    decision_reason TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX idx_approval_requests_engagement ON approval_requests(engagement_id, status, requested_at);

-- Multimodal intake (phase 2). Uploaded material is stored byte-for-byte and never
-- executed, opened or decompressed. Indicators are only 'discovered' on insert;
-- 'authorized' is reserved for the scope engine path.
CREATE TABLE engagement_inputs (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    original_name TEXT NOT NULL DEFAULT '',
    detected_kind TEXT NOT NULL DEFAULT '',
    mime TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    storage_path TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    ocr_text TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX idx_engagement_inputs_engagement ON engagement_inputs(engagement_id, created_at);

CREATE TABLE input_indicators (
    id TEXT PRIMARY KEY,
    input_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    byte_offset INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'discovered' CHECK (status IN ('discovered','rejected','authorized')),
    authorized INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    UNIQUE (input_id, kind, value),
    FOREIGN KEY (input_id) REFERENCES engagement_inputs(id) ON DELETE CASCADE,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX idx_input_indicators_input ON input_indicators(input_id);
CREATE INDEX idx_input_indicators_engagement ON input_indicators(engagement_id, status);

CREATE TABLE stage_plans (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    objective TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','done')),
    created_by TEXT NOT NULL CHECK (created_by IN ('model','human')),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX idx_stage_plans_engagement_stage ON stage_plans(engagement_id, stage);

CREATE TABLE stage_plan_tasks (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    title TEXT NOT NULL,
    rationale TEXT NOT NULL DEFAULT '',
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','done','skipped','blocked')),
    reason TEXT NOT NULL DEFAULT '',
    stage_task_id TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    UNIQUE (plan_id, position),
    FOREIGN KEY (plan_id) REFERENCES stage_plans(id) ON DELETE CASCADE
);

CREATE INDEX idx_stage_plan_tasks_plan ON stage_plan_tasks(plan_id, position);

CREATE TABLE input_observations (
    id TEXT PRIMARY KEY,
    input_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('file_type','indicator_summary','text_excerpt','pcap_summary','ocr_text','mismatch')),
    summary TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL,
    FOREIGN KEY (input_id) REFERENCES engagement_inputs(id) ON DELETE CASCADE
);

CREATE INDEX idx_input_observations_input ON input_observations(input_id);

CREATE TABLE tool_observations (
    id TEXT PRIMARY KEY,
    tool_execution_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL DEFAULT '',
    engagement_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('http_status','url','hostname','ipv4','open_port','technology','tls_info','other')),
    subject TEXT NOT NULL DEFAULT '',
    attribute TEXT NOT NULL DEFAULT '',
    value TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'deterministic',
    created_at DATETIME NOT NULL
);

CREATE INDEX idx_tool_observations_execution ON tool_observations(tool_execution_id);

CREATE TABLE hypotheses (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','supported','refuted','inconclusive','promoted')),
    created_by TEXT NOT NULL CHECK (created_by IN ('model','human')),
    status_reason TEXT NOT NULL DEFAULT '',
    vulnerability_id TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX idx_hypotheses_engagement ON hypotheses(engagement_id, status);

CREATE TABLE hypothesis_evidence (
    hypothesis_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    stance TEXT NOT NULL CHECK (stance IN ('supports','refutes','context')),
    PRIMARY KEY (hypothesis_id, evidence_id),
    FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE
);

CREATE INDEX idx_hypothesis_evidence_evidence ON hypothesis_evidence(evidence_id);

CREATE TABLE applicability_checks (
    id TEXT PRIMARY KEY,
    hypothesis_id TEXT NOT NULL,
    check_kind TEXT NOT NULL,
    target_observation_id TEXT,
    result TEXT NOT NULL CHECK (result IN ('applies','does_not_apply','unknown')),
    reason TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id) ON DELETE CASCADE
);

CREATE INDEX idx_applicability_checks_hypothesis ON applicability_checks(hypothesis_id, result);

CREATE TABLE model_call_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL,
    call_index INTEGER NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    manifest_json TEXT,
    cost_usd REAL
);

CREATE INDEX idx_model_call_usage_conversation ON model_call_usage(conversation_id);

CREATE TABLE openrouter_key_usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    usage_usd REAL NOT NULL,
    checked_at DATETIME NOT NULL
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Feature tables borrowed from competitor platforms (HexStrike, Strix, CyberStrike, ARTEX)
-- ═══════════════════════════════════════════════════════════════════════════════

-- 1. MITRE ATT&CK mapping (from CyberStrike)
CREATE TABLE IF NOT EXISTS mitre_attack_techniques (
    id TEXT PRIMARY KEY,
    tactic TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vulnerability_attack_mappings (
    vulnerability_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium' CHECK (confidence IN ('low','medium','high')),
    mapped_by TEXT NOT NULL DEFAULT 'ai',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vulnerability_id, technique_id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- 2. OWASP test case library (from CyberStrike)
CREATE TABLE IF NOT EXISTS owasp_test_cases (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    subcategory TEXT NOT NULL DEFAULT '',
    test_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity_default TEXT NOT NULL DEFAULT 'medium',
    test_procedure TEXT NOT NULL DEFAULT '',
    expected_evidence TEXT NOT NULL DEFAULT '',
    references_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS engagement_test_results (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    test_case_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','pass','fail','skipped','error')),
    findings_summary TEXT NOT NULL DEFAULT '',
    vulnerability_id TEXT,
    executed_by TEXT NOT NULL DEFAULT '',
    executed_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (test_case_id) REFERENCES owasp_test_cases(id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_engagement_test_results_engagement ON engagement_test_results(engagement_id, status);

-- 3. Engagement scope gates + noise governor (from ARTEX)
CREATE TABLE IF NOT EXISTS engagement_scope_rules (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    rule_type TEXT NOT NULL CHECK (rule_type IN ('allow','deny')),
    target_type TEXT NOT NULL CHECK (target_type IN ('ip','cidr','domain','url_prefix','port_range')),
    target_value TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_engagement_scope_rules_engagement ON engagement_scope_rules(engagement_id, rule_type);

CREATE TABLE IF NOT EXISTS engagement_noise_config (
    engagement_id TEXT PRIMARY KEY,
    max_requests_per_minute INTEGER NOT NULL DEFAULT 60,
    max_concurrent_tools INTEGER NOT NULL DEFAULT 3,
    max_agent_turns INTEGER NOT NULL DEFAULT 500,
    max_tokens_budget INTEGER NOT NULL DEFAULT 1000000,
    quiet_hours_start TEXT,
    quiet_hours_end TEXT,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

-- 4. CVE feed + exploitability scoring (from HexStrike)
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    cvss_score REAL,
    cvss_vector TEXT NOT NULL DEFAULT '',
    epss_score REAL,
    epss_percentile REAL,
    kev_known_exploited INTEGER NOT NULL DEFAULT 0,
    cwe_ids TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'other',
    affected_vendor TEXT NOT NULL DEFAULT '',
    affected_product TEXT NOT NULL DEFAULT '',
    affected_versions TEXT NOT NULL DEFAULT '',
    cpe_json TEXT NOT NULL DEFAULT '[]',
    ai_analysis TEXT NOT NULL DEFAULT '',
    published_at DATETIME,
    modified_at DATETIME,
    references_json TEXT NOT NULL DEFAULT '[]',
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cve_cache_category ON cve_cache(category);
CREATE INDEX IF NOT EXISTS idx_cve_cache_vendor ON cve_cache(affected_vendor);
CREATE INDEX IF NOT EXISTS idx_cve_cache_cvss ON cve_cache(cvss_score);

CREATE TABLE IF NOT EXISTS vulnerability_cve_links (
    vulnerability_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    linked_by TEXT NOT NULL DEFAULT 'ai',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vulnerability_id, cve_id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- 5. PoC validation (from Strix)
CREATE TABLE IF NOT EXISTS poc_validations (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    engagement_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','confirmed','failed','error')),
    exploit_code TEXT NOT NULL DEFAULT '',
    exploit_type TEXT NOT NULL DEFAULT '',
    sandbox_log TEXT NOT NULL DEFAULT '',
    result_summary TEXT NOT NULL DEFAULT '',
    confirmed_at DATETIME,
    executed_by TEXT NOT NULL DEFAULT 'agent',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_poc_validations_vuln ON poc_validations(vulnerability_id, status);

-- 6. Knowledge graph — target + progress (from ARTEX)
CREATE TABLE IF NOT EXISTS knowledge_nodes (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    node_type TEXT NOT NULL CHECK (node_type IN ('host','service','endpoint','credential','vulnerability','finding','tool_output','note')),
    label TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}',
    discovered_by TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_knowledge_nodes_engagement ON knowledge_nodes(engagement_id, node_type);

CREATE TABLE IF NOT EXISTS knowledge_edges (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    edge_type TEXT NOT NULL CHECK (edge_type IN ('hosts','exposes','exploits','leads_to','authenticates','discovered','related','blocks')),
    data_json TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (source_node_id) REFERENCES knowledge_nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (target_node_id) REFERENCES knowledge_nodes(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_knowledge_edges_engagement ON knowledge_edges(engagement_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_edges_source ON knowledge_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_edges_target ON knowledge_edges(target_node_id);

-- 7. CI/CD pipeline integration (from Strix)
CREATE TABLE IF NOT EXISTS cicd_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    engagement_id TEXT,
    project_id TEXT,
    permissions_json TEXT NOT NULL DEFAULT '["vulnerability:read","vulnerability:write"]',
    last_used_at DATETIME,
    expires_at DATETIME,
    created_by TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE SET NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS cicd_runs (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    trigger_type TEXT NOT NULL DEFAULT 'webhook' CHECK (trigger_type IN ('webhook','api','scheduled')),
    repo_url TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','cancelled')),
    findings_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL DEFAULT '{}',
    started_at DATETIME,
    completed_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (token_id) REFERENCES cicd_tokens(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cicd_runs_token ON cicd_runs(token_id, status);

-- 8. Auto-fix suggestions (from Strix)
CREATE TABLE IF NOT EXISTS autofix_suggestions (
    id TEXT PRIMARY KEY,
    vulnerability_id TEXT NOT NULL,
    file_path TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT '',
    original_code TEXT NOT NULL DEFAULT '',
    fixed_code TEXT NOT NULL DEFAULT '',
    explanation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','accepted','rejected','applied')),
    generated_by TEXT NOT NULL DEFAULT 'agent',
    reviewed_by TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_autofix_suggestions_vuln ON autofix_suggestions(vulnerability_id);

-- 9. Goal-driven autonomous decomposition (from ARTEX)
CREATE TABLE IF NOT EXISTS autonomous_goals (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    parent_goal_id TEXT,
    goal_text TEXT NOT NULL,
    goal_type TEXT NOT NULL DEFAULT 'assessment' CHECK (goal_type IN ('assessment','recon','exploit','report','custom')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','completed','failed','cancelled')),
    priority INTEGER NOT NULL DEFAULT 0,
    decomposed_by TEXT NOT NULL DEFAULT 'planner',
    result_summary TEXT NOT NULL DEFAULT '',
    conversation_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_goal_id) REFERENCES autonomous_goals(id) ON DELETE CASCADE,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_autonomous_goals_engagement ON autonomous_goals(engagement_id, status);
CREATE INDEX IF NOT EXISTS idx_autonomous_goals_parent ON autonomous_goals(parent_goal_id);
