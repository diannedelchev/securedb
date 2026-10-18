-- A durable execution intent survives target-side failures and process crashes.
-- Unresolved running rows must be reconciled against the target before retrying.
ALTER TABLE query_history DROP CONSTRAINT query_history_status_check;
ALTER TABLE query_history ADD CONSTRAINT query_history_status_check
    CHECK (status IN ('running','success','error','blocked','pending_approval','cancelled'));
CREATE INDEX idx_audit_logs_execution ON audit_logs(entity_id) WHERE entity_type='query';
