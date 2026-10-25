-- Published token-signing keys (ADR-0028 rotation rules, OPERATIONS.md §5.2).
--
-- Only public material is stored. A private key lives in its own 0600 PEM file
-- and never enters the database (DATA-MODEL.md §2.3), so a database dump cannot
-- be used to mint tokens.
--
-- Retired keys stay in this table on purpose: tokens signed before the rotation
-- are still valid until they expire, and verifying them needs the matching
-- public key. Deleting the row early would turn every in-flight token into a
-- verification error.
CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    public_jwk_json TEXT NOT NULL CHECK (json_valid(public_jwk_json)),
    created_at INTEGER NOT NULL,
    activated_at INTEGER NOT NULL,
    retired_at INTEGER
);

CREATE INDEX idx_signing_keys_activated ON signing_keys (activated_at);
