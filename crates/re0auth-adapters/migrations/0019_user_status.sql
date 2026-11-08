-- B15: an account can be frozen without being deleted.
--
-- Deleting the row would destroy the audit trail and the bindings that still
-- need an upstream revocation; status keeps the account visible while every
-- admission point refuses it.
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'banned'));
