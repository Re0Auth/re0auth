ALTER TABLE pending_authorizations ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;
ALTER TABLE auth_codes ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;
ALTER TABLE refresh_tokens ADD COLUMN family_created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE refresh_tokens ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0;
UPDATE refresh_tokens SET family_created_at = created_at;
UPDATE refresh_tokens SET auth_time = family_created_at;
