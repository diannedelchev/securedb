-- Multi-database support: one connection (server + credentials) can be used
-- against any database on that server. Track which database each query and
-- approval targeted.
ALTER TABLE query_history    ADD COLUMN database_name TEXT NOT NULL DEFAULT '';
ALTER TABLE approval_requests ADD COLUMN database_name TEXT NOT NULL DEFAULT '';
