-- In-progress binding flows (INV-BIND-02).
--
-- Same shape and reasoning as `login_transactions`: the state is one-shot, and
-- the row records who started the flow so the callback cannot be used to bind
-- an upstream account to someone else.
CREATE TABLE pending_bindings (
    state_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upstream_id TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE INDEX pending_bindings_expiry ON pending_bindings (expires_at);
