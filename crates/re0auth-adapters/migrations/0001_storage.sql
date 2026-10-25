CREATE TABLE users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL,
    raw_access INTEGER NOT NULL CHECK (raw_access IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'suspended', 'revoked')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (issuer, subject)
);

CREATE INDEX idx_identities_user ON identities (user_id);

CREATE TABLE sessions (
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

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_idle ON sessions (idle_expires_at);

CREATE TABLE auth_codes (
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
    consumed_at INTEGER
);

CREATE INDEX idx_auth_codes_expires ON auth_codes (expires_at);
CREATE INDEX idx_auth_codes_user ON auth_codes (user_id);

CREATE TABLE device_codes (
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
    consumed_at INTEGER
);

CREATE INDEX idx_device_codes_status_expires ON device_codes (status, expires_at);
CREATE INDEX idx_device_codes_expires ON device_codes (expires_at);

CREATE TABLE refresh_tokens (
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
    replaced_by TEXT
);

CREATE INDEX idx_refresh_family ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_user_client ON refresh_tokens (user_id, client_id);
CREATE INDEX idx_refresh_expires ON refresh_tokens (expires_at);

CREATE TABLE bindings (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upstream_id TEXT NOT NULL,
    upstream_user_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'needs_reauth', 'revoked', 'expired')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_refreshed_at INTEGER,
    last_error_code TEXT,
    UNIQUE (user_id, upstream_id)
);

CREATE INDEX idx_bindings_user ON bindings (user_id);
