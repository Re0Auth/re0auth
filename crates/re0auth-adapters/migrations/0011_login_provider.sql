-- INV-IDP-01: a login is bound to the provider that issued the authorization
-- code. Without this column the callback would have to pick a provider from the
-- query string, which lets a caller present one IdP's code to another.
--
-- Existing rows default to '': those logins were started before multiple
-- providers existed, and a pending one cannot be completed anyway (the state is
-- short-lived), so a stale empty value never reaches the callback path.
ALTER TABLE login_transactions ADD COLUMN provider TEXT NOT NULL DEFAULT '';
