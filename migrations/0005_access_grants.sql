-- Privileged Access Management: just-in-time, time-bound access windows.
-- An active grant lets its holder run production writes on one connection
-- without per-query approval until it expires or is revoked.
CREATE TABLE access_grants (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id      UUID NOT NULL REFERENCES database_connections(id) ON DELETE CASCADE,
    level              TEXT NOT NULL DEFAULT 'write' CHECK (level IN ('write')),
    reason             TEXT NOT NULL DEFAULT '',
    duration_minutes   INTEGER NOT NULL DEFAULT 60,
    status             TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','rejected','expired','revoked')),
    approver_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    comments           TEXT NOT NULL DEFAULT '',
    starts_at          TIMESTAMPTZ,
    expires_at         TIMESTAMPTZ,
    revoked_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_at         TIMESTAMPTZ,
    request_expires_at TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_access_grants_active ON access_grants(user_id, connection_id, status);
CREATE INDEX idx_access_grants_status ON access_grants(status, created_at DESC);
