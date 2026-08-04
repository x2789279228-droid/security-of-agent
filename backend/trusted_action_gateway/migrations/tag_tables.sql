-- ============================================================
-- Trusted Action Gateway — 数据表迁移脚本
-- 新增 4 张表:
--   action_grants       — 分步提权授权 (ActionGrant)
--   action_ledger       — 动作幂等账本 (ActionLedger)
--   tag_audit_trail     — 统一审计日志 (TagAuditTrail)
--   action_budget_state — 预算与熔断状态 (ActionBudgetState)
-- ============================================================

-- 启用 pgvector 扩展 (若尚未启用)
-- CREATE EXTENSION IF NOT EXISTS vector;

-- 1. action_grants — 分步提权授权
CREATE TABLE IF NOT EXISTS action_grants (
    id                    VARCHAR(64)  PRIMARY KEY,
    subject               VARCHAR(100) NOT NULL,
    incident_id           VARCHAR(100) NOT NULL,
    tool_name             VARCHAR(100) NOT NULL,
    target_scope          JSONB        NOT NULL,
    parameter_constraints JSONB        NOT NULL DEFAULT '{}'::jsonb,
    max_executions        INTEGER      NOT NULL DEFAULT 1,
    expires_at            TIMESTAMPTZ  NOT NULL,
    evidence_ids          JSONB        DEFAULT '[]'::jsonb,
    approval_level        VARCHAR(20)  NOT NULL DEFAULT 'basic',
    approval_record       JSONB        DEFAULT '{}'::jsonb,
    revocable             BOOLEAN      NOT NULL DEFAULT TRUE,
    used_count            INTEGER      NOT NULL DEFAULT 0,
    revoked_at            TIMESTAMPTZ,
    revoked_by            VARCHAR(100) DEFAULT '',
    status                VARCHAR(20)  NOT NULL DEFAULT 'active',
    created_at            TIMESTAMPTZ  DEFAULT NOW(),
    created_by            VARCHAR(100) DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_grants_subject        ON action_grants(subject);
CREATE INDEX IF NOT EXISTS ix_grants_incident_id    ON action_grants(incident_id);
CREATE INDEX IF NOT EXISTS ix_grants_tool_name       ON action_grants(tool_name);
CREATE INDEX IF NOT EXISTS ix_grants_status          ON action_grants(status);
CREATE INDEX IF NOT EXISTS ix_grants_created_at      ON action_grants(created_at);
CREATE INDEX IF NOT EXISTS ix_grants_incident_tool   ON action_grants(incident_id, tool_name);
CREATE INDEX IF NOT EXISTS ix_grants_subject_status  ON action_grants(subject, status);

-- 2. action_ledger — 动作幂等账本 (idempotency_key 唯一约束防并发)
CREATE TABLE IF NOT EXISTS action_ledger (
    id                        SERIAL       PRIMARY KEY,
    action_id                 VARCHAR(64)  NOT NULL UNIQUE,
    idempotency_key           VARCHAR(128) NOT NULL UNIQUE,
    incident_id               VARCHAR(100) NOT NULL,
    plan_version              VARCHAR(64)  NOT NULL DEFAULT 'v1',
    tool_name                 VARCHAR(100) NOT NULL,
    target                    VARCHAR(255) NOT NULL,
    normalized_parameters     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    parameter_hash            VARCHAR(64)  NOT NULL,
    status                    VARCHAR(30)  NOT NULL DEFAULT 'proposed',
    request_count             INTEGER      NOT NULL DEFAULT 0,
    execution_started_at      TIMESTAMPTZ,
    execution_finished_at     TIMESTAMPTZ,
    result                    JSONB        DEFAULT '{}'::jsonb,
    error                     TEXT         DEFAULT '',
    rollback_action_id        VARCHAR(64),
    rollback_idempotency_key  VARCHAR(128),
    rollback_result           JSONB        DEFAULT '{}'::jsonb,
    verification_result       JSONB        DEFAULT '{}'::jsonb,
    verification_passed       BOOLEAN,
    grant_id                  VARCHAR(64)  REFERENCES action_grants(id),
    trace_id                  VARCHAR(64)  DEFAULT '',
    created_at                TIMESTAMPTZ  DEFAULT NOW(),
    updated_at                TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_ledger_action_id         ON action_ledger(action_id);
CREATE INDEX IF NOT EXISTS ix_ledger_idempotency_key    ON action_ledger(idempotency_key);
CREATE INDEX IF NOT EXISTS ix_ledger_incident_id        ON action_ledger(incident_id);
CREATE INDEX IF NOT EXISTS ix_ledger_tool_name          ON action_ledger(tool_name);
CREATE INDEX IF NOT EXISTS ix_ledger_status             ON action_ledger(status);
CREATE INDEX IF NOT EXISTS ix_ledger_grant_id           ON action_ledger(grant_id);
CREATE INDEX IF NOT EXISTS ix_ledger_trace_id           ON action_ledger(trace_id);
CREATE INDEX IF NOT EXISTS ix_ledger_rollback_action_id ON action_ledger(rollback_action_id);
CREATE INDEX IF NOT EXISTS ix_ledger_incident_tool_target ON action_ledger(incident_id, tool_name, target);

-- 3. tag_audit_trail — 统一审计日志 (不记录明文 Token/密码/私钥)
CREATE TABLE IF NOT EXISTS tag_audit_trail (
    id                      SERIAL       PRIMARY KEY,
    trace_id                VARCHAR(64)  NOT NULL,
    incident_id             VARCHAR(100) DEFAULT '',
    action_id               VARCHAR(64)  DEFAULT '',
    idempotency_key         VARCHAR(128) DEFAULT '',
    grant_id                VARCHAR(64)  DEFAULT '',
    agent_identity          VARCHAR(100) DEFAULT '',
    tool_name               VARCHAR(100) DEFAULT '',
    server_id               VARCHAR(100) DEFAULT '',
    transport_type          VARCHAR(20)  DEFAULT '',
    server_identity         VARCHAR(255) DEFAULT '',
    tool_schema_hash        VARCHAR(64)  DEFAULT '',
    target                  VARCHAR(255) DEFAULT '',
    normalized_parameters   JSONB        DEFAULT '{}'::jsonb,
    evidence_ids            JSONB        DEFAULT '[]'::jsonb,
    risk_score              DOUBLE PRECISION DEFAULT 0.0,
    risk_level              VARCHAR(20)  DEFAULT '',
    policy_decision         VARCHAR(30)  DEFAULT '',
    approval_record         JSONB        DEFAULT '{}'::jsonb,
    request_id              VARCHAR(64)  DEFAULT '',
    token_jti               VARCHAR(64)  DEFAULT '',
    execution_result        JSONB        DEFAULT '{}'::jsonb,
    verification_result     JSONB        DEFAULT '{}'::jsonb,
    rollback_result         JSONB        DEFAULT '{}'::jsonb,
    timestamps              JSONB        DEFAULT '{}'::jsonb,
    action_state            VARCHAR(30)  DEFAULT 'proposed',
    blocked_by              VARCHAR(50)  DEFAULT '',
    block_reason            TEXT         DEFAULT '',
    created_at              TIMESTAMPTZ  DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_audit_trace_id         ON tag_audit_trail(trace_id);
CREATE INDEX IF NOT EXISTS ix_audit_incident_id      ON tag_audit_trail(incident_id);
CREATE INDEX IF NOT EXISTS ix_audit_action_id        ON tag_audit_trail(action_id);
CREATE INDEX IF NOT EXISTS ix_audit_idempotency_key  ON tag_audit_trail(idempotency_key);
CREATE INDEX IF NOT EXISTS ix_audit_grant_id         ON tag_audit_trail(grant_id);
CREATE INDEX IF NOT EXISTS ix_audit_tool_name        ON tag_audit_trail(tool_name);
CREATE INDEX IF NOT EXISTS ix_audit_action_state     ON tag_audit_trail(action_state);
CREATE INDEX IF NOT EXISTS ix_audit_created_at       ON tag_audit_trail(created_at);
CREATE INDEX IF NOT EXISTS ix_audit_trace_incident   ON tag_audit_trail(trace_id, incident_id);
CREATE INDEX IF NOT EXISTS ix_audit_tool_state       ON tag_audit_trail(tool_name, action_state);

-- 4. action_budget_state — 预算与熔断状态
CREATE TABLE IF NOT EXISTS action_budget_state (
    id              SERIAL       PRIMARY KEY,
    scope_type      VARCHAR(20)  NOT NULL,
    scope_key       VARCHAR(200) NOT NULL,
    action_count    INTEGER      NOT NULL DEFAULT 0,
    target_count    INTEGER      NOT NULL DEFAULT 0,
    success_count   INTEGER      NOT NULL DEFAULT 0,
    failure_count   INTEGER      NOT NULL DEFAULT 0,
    window_start    TIMESTAMPTZ  DEFAULT NOW(),
    window_end      TIMESTAMPTZ,
    circuit_state   VARCHAR(20)  NOT NULL DEFAULT 'closed',
    tripped_reason  VARCHAR(200) DEFAULT '',
    tripped_at      TIMESTAMPTZ,
    tripped_count   INTEGER      NOT NULL DEFAULT 0,
    reset_by        VARCHAR(100) DEFAULT '',
    reset_at        TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  DEFAULT NOW(),
    CONSTRAINT uq_budget_scope UNIQUE (scope_type, scope_key)
);
CREATE INDEX IF NOT EXISTS ix_budget_scope_type   ON action_budget_state(scope_type);
CREATE INDEX IF NOT EXISTS ix_budget_scope_key    ON action_budget_state(scope_key);
CREATE INDEX IF NOT EXISTS ix_budget_circuit      ON action_budget_state(circuit_state);

-- ============================================================
-- 迁移完成
-- ============================================================
