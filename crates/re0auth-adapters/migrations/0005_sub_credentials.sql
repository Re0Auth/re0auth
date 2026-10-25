-- Two-layer sealing (ADR-0042): the payload is encrypted under a per-record
-- DEK, and that DEK is wrapped by the master key (KEK).
--
-- `key_version` names the KEK that wrapped the DEK, not the DEK itself. Rotating
-- the master key rewrites only `dek_nonce` and `wrapped_dek`; the payload columns
-- are untouched, which is what makes rotation cheap and repeatable.
--
-- Revoking a credential drops `wrapped_dek`. Ciphertext that survives in a backup
-- is then undecryptable, because nothing left on disk can open it.
CREATE TABLE sub_credentials (
    binding_id TEXT PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE,
    key_version INTEGER NOT NULL,
    dek_nonce BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
