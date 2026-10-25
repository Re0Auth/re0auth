-- Retention tiers and revoked-binding anonymization.
--
-- `tier` is a property of the write path (ADR-0025), not of urgency: facts are
-- written with their state change and kept a year; access telemetry is
-- best-effort and kept 90 days (Q-032). A default of 'fact' makes every existing
-- row a security fact, which is the safe direction — a fact purge must never
-- remove telemetry, but leaving a fact a while longer only costs disk.
ALTER TABLE audit_logs ADD COLUMN tier TEXT NOT NULL DEFAULT 'fact'
    CHECK (tier IN ('fact', 'telemetry'));

-- The retention sweep filters on both columns together.
CREATE INDEX idx_audit_tier_time ON audit_logs (tier, occurred_at);

-- When a binding was revoked, so the anonymization window can be measured from
-- the revoke rather than from `updated_at`, which any later write may move.
ALTER TABLE bindings ADD COLUMN revoked_at INTEGER;
