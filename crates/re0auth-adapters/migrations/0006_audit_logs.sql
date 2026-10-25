-- Security facts, written in the same transaction as the change they describe
-- (ADR-0025 / INV-AUDIT-01). Rows outlive the actor: `actor_user_id` is set to
-- NULL when the user is deleted (INV-FK-01).
--
-- `detail_json` defaults to '{}' rather than 'null': `json_valid('null')` is 1,
-- so a 'null' default would satisfy the CHECK while carrying no detail at all.
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    occurred_at INTEGER NOT NULL,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    client_id TEXT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    outcome TEXT NOT NULL,
    request_id TEXT,
    severity TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail_json))
);

CREATE INDEX idx_audit_occurred ON audit_logs (occurred_at);
CREATE INDEX idx_audit_actor ON audit_logs (actor_user_id);
CREATE INDEX idx_audit_client ON audit_logs (client_id);
