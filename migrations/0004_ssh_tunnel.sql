-- SSH tunnel support: reach databases through a bastion/jump host.
-- Credentials (password / private key) are AES-256-GCM encrypted like the
-- database password.
ALTER TABLE database_connections ADD COLUMN ssh_enabled            BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE database_connections ADD COLUMN ssh_host               TEXT    NOT NULL DEFAULT '';
ALTER TABLE database_connections ADD COLUMN ssh_port               INTEGER NOT NULL DEFAULT 22;
ALTER TABLE database_connections ADD COLUMN ssh_user               TEXT    NOT NULL DEFAULT '';
ALTER TABLE database_connections ADD COLUMN ssh_auth               TEXT    NOT NULL DEFAULT 'password' CHECK (ssh_auth IN ('password','key'));
ALTER TABLE database_connections ADD COLUMN ssh_password_encrypted TEXT    NOT NULL DEFAULT '';
ALTER TABLE database_connections ADD COLUMN ssh_key_encrypted      TEXT    NOT NULL DEFAULT '';
ALTER TABLE database_connections ADD COLUMN ssh_host_key           TEXT    NOT NULL DEFAULT '';
