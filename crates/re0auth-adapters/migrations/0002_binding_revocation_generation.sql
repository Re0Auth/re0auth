CREATE TABLE IF NOT EXISTS binding_revocation_epochs (
    binding_id TEXT PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK (generation >= 0)
);

INSERT OR IGNORE INTO binding_revocation_epochs (binding_id, generation)
SELECT id, 1 FROM bindings WHERE revoked_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS pending_binding_epochs (
    state_hash BLOB PRIMARY KEY REFERENCES pending_bindings(state_hash) ON DELETE CASCADE,
    revocation_generation INTEGER NOT NULL CHECK (revocation_generation >= 0)
);
