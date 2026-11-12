CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'banned'))
);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL,
    raw_access INTEGER NOT NULL CHECK (raw_access IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'suspended', 'revoked')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    secret_hash BLOB,
    secret_key_version INTEGER
);

CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    id_hash BLOB NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS login_transactions (
    state_hash BLOB PRIMARY KEY,
    nonce TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    provider TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT 'login' CHECK (purpose IN ('login', 'attach')),
    initiator TEXT REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS approval_tickets (
    jti TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_code TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE TABLE IF NOT EXISTS consents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    revoked_at INTEGER,
    version INTEGER NOT NULL DEFAULT 1,
    UNIQUE (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS pending_authorizations (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    state TEXT,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    nonce TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    auth_time INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS auth_codes (
    id TEXT PRIMARY KEY,
    code_hash BLOB NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    nonce TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    family_id TEXT,
    auth_time INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_codes (
    id TEXT PRIMARY KEY,
    device_code_hash BLOB NOT NULL UNIQUE,
    user_code_hash BLOB NOT NULL UNIQUE,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed', 'expired')),
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    interval_secs INTEGER NOT NULL,
    last_polled_at INTEGER,
    poll_count INTEGER NOT NULL,
    user_code_misses INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    family_id TEXT
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    family_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    revoked_at INTEGER,
    replaced_by TEXT,
    family_created_at INTEGER NOT NULL DEFAULT 0,
    auth_time INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bindings (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upstream_id TEXT NOT NULL,
    upstream_user_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'needs_reauth', 'revoked')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_refreshed_at INTEGER,
    last_error_code TEXT,
    revoked_at INTEGER,
    UNIQUE (user_id, upstream_id)
);

CREATE TABLE IF NOT EXISTS sub_credentials (
    binding_id TEXT PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE,
    key_version INTEGER NOT NULL,
    dek_nonce BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_attempts (
    ip TEXT NOT NULL,
    user_code_hash BLOB NOT NULL,
    misses INTEGER NOT NULL,
    last_miss_at INTEGER NOT NULL,
    PRIMARY KEY (ip, user_code_hash)
);

CREATE TABLE IF NOT EXISTS pending_bindings (
    state_hash BLOB PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upstream_id TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    return_to TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);

CREATE TABLE IF NOT EXISTS connectors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    base_url TEXT NOT NULL,
    allow_private_net INTEGER NOT NULL DEFAULT 0,
    allow_link_local_metadata INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    display_name TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS connector_resources (
    connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    path_template TEXT NOT NULL,
    required_scope TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'get',
    idempotent INTEGER NOT NULL DEFAULT 1,
    body_json TEXT NOT NULL DEFAULT '{}',
    body_typed_json TEXT,
    raw_body_json TEXT,
    PRIMARY KEY (connector_id, name)
);

CREATE TABLE IF NOT EXISTS connector_secrets (
    connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    dek_nonce BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (connector_id, kind)
);

CREATE TABLE IF NOT EXISTS access_revocations (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NOT NULL,
    revoked_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    client_id TEXT
);

CREATE TABLE IF NOT EXISTS revoked_families (
    family_id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    public_jwk_json TEXT NOT NULL CHECK (json_valid(public_jwk_json)),
    created_at INTEGER NOT NULL,
    activated_at INTEGER NOT NULL,
    retired_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    occurred_at INTEGER NOT NULL,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    client_id TEXT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    outcome TEXT NOT NULL,
    request_id TEXT,
    severity TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail_json)),
    tier TEXT NOT NULL DEFAULT 'fact' CHECK (tier IN ('fact', 'telemetry'))
);

CREATE INDEX IF NOT EXISTS idx_identities_user ON identities (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_idle ON sessions (idle_expires_at);
CREATE INDEX IF NOT EXISTS idx_login_transactions_expires ON login_transactions (expires_at);
CREATE INDEX IF NOT EXISTS idx_approval_tickets_expires ON approval_tickets (expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes (expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user ON auth_codes (user_id);
CREATE INDEX IF NOT EXISTS idx_device_codes_status_expires ON device_codes (status, expires_at);
CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON device_codes (expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_user_client ON refresh_tokens (user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_bindings_user ON bindings (user_id);
CREATE INDEX IF NOT EXISTS idx_consents_user ON consents (user_id);
CREATE INDEX IF NOT EXISTS idx_pending_authorizations_session ON pending_authorizations (session_id);
CREATE INDEX IF NOT EXISTS idx_pending_authorizations_expires ON pending_authorizations (expires_at);
CREATE INDEX IF NOT EXISTS idx_device_attempts_last_miss ON device_attempts (last_miss_at);
CREATE INDEX IF NOT EXISTS idx_audit_occurred ON audit_logs (occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs (actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_client ON audit_logs (client_id);
CREATE INDEX IF NOT EXISTS idx_access_revocations_expires ON access_revocations (expires_at);
CREATE INDEX IF NOT EXISTS idx_signing_keys_activated ON signing_keys (activated_at);
CREATE INDEX IF NOT EXISTS pending_bindings_expiry ON pending_bindings (expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_tier_time ON audit_logs (tier, occurred_at);
CREATE INDEX IF NOT EXISTS idx_login_transactions_consumed ON login_transactions (consumed_at) WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_absolute ON sessions (absolute_expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_codes_consumed ON auth_codes (consumed_at) WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_device_codes_consumed ON device_codes (consumed_at) WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_consumed ON refresh_tokens (consumed_at) WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_revoked ON refresh_tokens (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pending_authorizations_consumed ON pending_authorizations (consumed_at) WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_approval_tickets_consumed ON approval_tickets (consumed_at) WHERE consumed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bindings_revoked ON bindings (revoked_at) WHERE status = 'revoked';
CREATE INDEX IF NOT EXISTS idx_pending_bindings_consumed ON pending_bindings (consumed_at) WHERE consumed_at IS NOT NULL;

UPDATE clients
SET allowed_scopes = (
    WITH expanded AS (
        SELECT value,
            CASE value
                WHEN 'phigros.query.save.read' THEN 'phigros.xtower.read'
                WHEN 'phigros.songs.read' THEN 'phigros.xtower.read'
                WHEN 'phigros.leaderboard.read' THEN 'phigros.xtower.read'
                WHEN 'phigros.verify.read' THEN 'phigros.xtower.read'
                WHEN 'phigros.stats.read' THEN 'phigros.xtower.read'
                WHEN 'phihub.save.read' THEN 'phigros.phihub.read'
                WHEN 'phihub.catalog.read' THEN 'phigros.phihub.read'
                WHEN 'phihub.rank.read' THEN 'phigros.phihub.read'
                WHEN 'phihub.charts.read' THEN 'phigros.phihub.read'
                WHEN 'phihub.comment.read' THEN 'phigros.phihub.read'
                ELSE NULL
            END AS mapped
        FROM json_each(clients.allowed_scopes)
    ),
    retained AS (
        SELECT json_group_array(value) AS scopes FROM expanded WHERE mapped IS NULL
    ),
    with_phihub AS (
        SELECT CASE
            WHEN EXISTS (SELECT 1 FROM expanded WHERE mapped = 'phigros.phihub.read')
            THEN json_insert((SELECT scopes FROM retained), '$[#]', 'phigros.phihub.read')
            ELSE (SELECT scopes FROM retained)
        END AS scopes
    )
    SELECT CASE
        WHEN EXISTS (SELECT 1 FROM expanded WHERE mapped = 'phigros.xtower.read')
        THEN json_insert((SELECT scopes FROM with_phihub), '$[#]', 'phigros.xtower.read')
        ELSE (SELECT scopes FROM with_phihub)
    END
),
updated_at = unixepoch()
WHERE EXISTS (
    SELECT 1 FROM json_each(clients.allowed_scopes)
    WHERE value IN (
        'phigros.query.save.read',
        'phigros.songs.read',
        'phigros.leaderboard.read',
        'phigros.verify.read',
        'phigros.stats.read',
        'phihub.save.read',
        'phihub.catalog.read',
        'phihub.rank.read',
        'phihub.charts.read',
        'phihub.comment.read'
    )
);

UPDATE consents
SET revoked_at = unixepoch(), updated_at = unixepoch(), version = version + 1
WHERE revoked_at IS NULL
  AND EXISTS (
      SELECT 1 FROM json_each(consents.scopes)
      WHERE value IN (
          'phigros.query.save.read',
          'phigros.songs.read',
          'phigros.leaderboard.read',
          'phigros.verify.read',
          'phigros.stats.read',
          'phihub.save.read',
          'phihub.catalog.read',
          'phihub.rank.read',
          'phihub.charts.read',
          'phihub.comment.read'
      )
  );
