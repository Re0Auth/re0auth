-- no-transaction
-- 移除 expired：代码已删该状态而库仍允许写入
-- SQLite 无法就地改 CHECK，只能重建表
-- 关外键：sub_credentials 会级联删除
-- PRAGMA 在事务内无效，故本迁移不用事务

PRAGMA foreign_keys = OFF;

BEGIN;

DROP TABLE IF EXISTS bindings_new;

CREATE TABLE bindings_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    upstream_id TEXT NOT NULL,
    upstream_user_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'needs_reauth', 'revoked')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_refreshed_at INTEGER,
    last_error_code TEXT,
    revoked_at INTEGER,
    UNIQUE (user_id, upstream_id)
);

INSERT INTO bindings_new
    (id, user_id, upstream_id, upstream_user_id, status,
     created_at, updated_at, last_refreshed_at, last_error_code, revoked_at)
SELECT
    id, user_id, upstream_id, upstream_user_id, status,
    created_at, updated_at, last_refreshed_at, last_error_code, revoked_at
FROM bindings;

DROP TABLE bindings;

ALTER TABLE bindings_new RENAME TO bindings;

CREATE INDEX idx_bindings_user ON bindings (user_id);

COMMIT;

PRAGMA foreign_keys = ON;
