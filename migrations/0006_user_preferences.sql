-- Per-user UI preferences (e.g. SQL editor pane sizes). Keyed per user so
-- future preferences reuse the same table.
CREATE TABLE user_preferences (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);
