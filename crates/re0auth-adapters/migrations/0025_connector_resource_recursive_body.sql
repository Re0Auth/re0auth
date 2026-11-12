-- Recursive connector request bodies.
--
-- `body_json` remains the legacy string map so older readers can keep loading
-- every resource. New readers prefer `raw_body_json`, then `body_typed_json`,
-- and fall back to `body_json` for rows written before this migration. NULL
-- marks the absence of a new representation, including an undeclared GET body.
ALTER TABLE connector_resources ADD COLUMN body_typed_json TEXT;
ALTER TABLE connector_resources ADD COLUMN raw_body_json TEXT;
