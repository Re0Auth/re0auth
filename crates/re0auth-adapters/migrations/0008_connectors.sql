-- Connector registry mirror.
--
-- Configuration stays authoritative: AGENTS.md fixes "changing a connector means
-- editing config and restarting". These tables exist so that other rows have a
-- real foreign key to point at, and so connector-level secrets have a home that
-- is not the config file.
--
-- `id` is the UUIDv5 derived from `name` (see `connector_id_for_name`), which is
-- what the gateway and circuit breaker key on. `name` is the stable identifier
-- that appears in URLs and in `bindings.upstream_id`.
CREATE TABLE connectors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    base_url TEXT NOT NULL,
    allow_private_net INTEGER NOT NULL DEFAULT 0,
    allow_link_local_metadata INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Path templates live here and nowhere else (ADR-0032): the gateway can only
-- reach a URL this table mentions.
CREATE TABLE connector_resources (
    connector_id TEXT NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    path_template TEXT NOT NULL,
    required_scope TEXT NOT NULL,
    PRIMARY KEY (connector_id, name)
);

-- Connector-level secrets (HMAC keys, exchange secrets). Same two-layer sealing
-- as sub_credentials (ADR-0042): payload under a per-record DEK, DEK wrapped by
-- the master key. No plaintext column exists (INV-CONN-02).
CREATE TABLE connector_secrets (
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
