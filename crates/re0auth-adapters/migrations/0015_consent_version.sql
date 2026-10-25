-- Consent becomes a versioned authorization fact, not a display-only row.
-- Existing grants start at version 1; every re-grant or revoke increments it.
ALTER TABLE consents ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
