-- 家族撤销后，其访问令牌立即失效
CREATE TABLE revoked_families (
    family_id TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);
