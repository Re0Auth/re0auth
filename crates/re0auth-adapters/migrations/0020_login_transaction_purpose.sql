-- Why a login transaction exists (ADR-0050).
--
-- Without this the callback cannot tell "the user asked to attach a new login
-- method" from "the user is signing in": both arrive with a state that only says
-- which provider was used. The intent has to be bound at start and read back at
-- the callback, the same way the provider already is (INV-IDP-01).

ALTER TABLE login_transactions
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login'
    CHECK (purpose IN ('login', 'attach'));

-- The account that started an attach flow. NULL for a plain login, and the
-- foreign key removes the transaction with the account, so an attach cannot
-- outlive the session that asked for it.
ALTER TABLE login_transactions
    ADD COLUMN initiator TEXT REFERENCES users(id) ON DELETE CASCADE;
