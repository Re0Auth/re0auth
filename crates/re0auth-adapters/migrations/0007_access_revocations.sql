-- Revoked access tokens (RFC 7009).
--
-- Access tokens are self-contained JWTs, so revocation cannot work by deleting
-- a row: nothing is stored per token at issue time. Instead the `jti` of a
-- revoked token is recorded here and every verification path consults it.
--
-- Rows are only useful until the token would have expired anyway, so `expires_at`
-- mirrors the token's own `exp` and the housekeeping sweep deletes rows past it.
-- That keeps the table bounded without needing a fixed retention policy.
CREATE TABLE access_revocations (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NOT NULL,
    revoked_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    client_id TEXT
);

CREATE INDEX idx_access_revocations_expires ON access_revocations (expires_at);
