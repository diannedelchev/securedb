CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    ip_address  TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE database_connections (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    environment         TEXT NOT NULL CHECK (environment IN ('development','staging','production')),
    db_type             TEXT NOT NULL CHECK (db_type IN ('postgres','mysql','mssql')),
    host                TEXT NOT NULL,
    port                INTEGER NOT NULL,
    database_name       TEXT NOT NULL,
    username            TEXT NOT NULL,
    password_encrypted  TEXT NOT NULL DEFAULT '',
    secrets_reference   TEXT NOT NULL DEFAULT '',
    ssl_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    read_only           BOOLEAN NOT NULL DEFAULT FALSE,
    owner_id            UUID NOT NULL REFERENCES users(id),
    tags                TEXT NOT NULL DEFAULT '',
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE connection_permissions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id       UUID REFERENCES roles(id) ON DELETE CASCADE,
    can_write     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE query_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','finished','cancelled','error')),
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE query_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id UUID REFERENCES database_connections(id) ON DELETE SET NULL,
    query_text    TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('success','error','blocked','pending_approval','cancelled')),
    error_message TEXT NOT NULL DEFAULT '',
    row_count     INTEGER NOT NULL DEFAULT 0,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_query_history_user ON query_history(user_id, created_at DESC);

CREATE TABLE audit_logs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    action        TEXT NOT NULL,
    entity_type   TEXT NOT NULL DEFAULT '',
    entity_id     TEXT NOT NULL DEFAULT '',
    connection_id UUID REFERENCES database_connections(id) ON DELETE SET NULL,
    ip_address    TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    query_text    TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'success',
    error_message TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

CREATE TABLE approval_requests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    environment   TEXT NOT NULL,
    query_text    TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    risk_score    INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','expired')),
    approver_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    comments      TEXT NOT NULL DEFAULT '',
    executed_at   TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_approval_requests_status ON approval_requests(status, created_at DESC);

CREATE TABLE security_policies (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment              TEXT NOT NULL UNIQUE CHECK (environment IN ('development','staging','production')),
    max_rows                 INTEGER NOT NULL DEFAULT 500,
    timeout_seconds          INTEGER NOT NULL DEFAULT 30,
    allow_export             BOOLEAN NOT NULL DEFAULT TRUE,
    require_approval_writes  BOOLEAN NOT NULL DEFAULT FALSE,
    allow_write_queries      BOOLEAN NOT NULL DEFAULT TRUE,
    mask_sensitive_columns   BOOLEAN NOT NULL DEFAULT TRUE,
    allowed_schemas          TEXT NOT NULL DEFAULT '',
    blocked_keywords         TEXT NOT NULL DEFAULT 'DROP,TRUNCATE,ALTER,CREATE,GRANT,REVOKE',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE masking_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    column_pattern TEXT NOT NULL,
    strategy      TEXT NOT NULL CHECK (strategy IN ('email','phone','card','redact','partial')),
    description   TEXT NOT NULL DEFAULT '',
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE saved_queries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id UUID REFERENCES database_connections(id) ON DELETE SET NULL,
    name          TEXT NOT NULL,
    query_text    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
