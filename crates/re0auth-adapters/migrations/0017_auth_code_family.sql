-- 记录授权码换出的令牌家族，重放时可追溯撤销
ALTER TABLE auth_codes ADD COLUMN family_id TEXT;
