-- Cleanup queries OR one column at a time; each OR term needs its own index or
-- SQLite gives up and scans the whole table. Partial indexes keep the write
-- cost near zero: most rows never have a consumed/revoked timestamp.
CREATE INDEX IF NOT EXISTS idx_sessions_absolute ON sessions (absolute_expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON sessions (revoked_at)
    WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_codes_consumed ON auth_codes (consumed_at)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_consumed ON refresh_tokens (consumed_at)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_revoked ON refresh_tokens (revoked_at)
    WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_device_codes_consumed ON device_codes (consumed_at)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_login_transactions_consumed ON login_transactions (consumed_at)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_approval_tickets_consumed ON approval_tickets (consumed_at)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pending_authorizations_consumed ON pending_authorizations (consumed_at)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pending_bindings_consumed ON pending_bindings (consumed_at)
    WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bindings_revoked ON bindings (revoked_at)
    WHERE status = 'revoked';
