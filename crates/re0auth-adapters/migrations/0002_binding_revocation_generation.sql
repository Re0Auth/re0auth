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

INSERT OR IGNORE INTO pending_binding_epochs (state_hash, revocation_generation)
SELECT pending_bindings.state_hash,
       CASE
           WHEN bindings.revoked_at IS NOT NULL
                AND pending_bindings.created_at > bindings.revoked_at
           THEN COALESCE(binding_revocation_epochs.generation, 0)
           ELSE 0
       END
FROM pending_bindings
LEFT JOIN bindings
       ON bindings.user_id = pending_bindings.user_id
      AND bindings.upstream_id = pending_bindings.upstream_id
LEFT JOIN binding_revocation_epochs
       ON binding_revocation_epochs.binding_id = bindings.id;
