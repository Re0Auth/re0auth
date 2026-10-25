-- Connector resource transport (ADR-0046).
--
-- The mirror used to carry only name/path/scope, which would silently drop the
-- method and body of a POST resource and leave the stored registry disagreeing
-- with the config it mirrors. `body_json` uses the same value spelling as config
-- (`{subject}` / `{credential}` / literal), so both sides parse identically.
ALTER TABLE connector_resources ADD COLUMN method TEXT NOT NULL DEFAULT 'get';
ALTER TABLE connector_resources ADD COLUMN idempotent INTEGER NOT NULL DEFAULT 1;
ALTER TABLE connector_resources ADD COLUMN body_json TEXT NOT NULL DEFAULT '{}';
