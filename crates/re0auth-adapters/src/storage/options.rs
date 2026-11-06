//! 数据库连接参数。独立成文件，避免 `storage.rs` 超过行数预算。

use serde::Deserialize;

/// SQLite 同步模式；WAL 下推荐 `Normal`。
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SqliteSynchronous {
    Full,
    #[default]
    Normal,
    Off,
}

impl SqliteSynchronous {
    pub(crate) const fn as_pragma(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Normal => "NORMAL",
            Self::Off => "OFF",
        }
    }
}

/// 连接参数。默认值面向单机部署。
#[derive(Clone, Copy, Debug)]
pub struct DatabaseOptions {
    pub synchronous: SqliteSynchronous,
    pub cache_size_mb: u32,
    pub mmap_size_mb: u32,
    pub pool_size: u32,
}

impl Default for DatabaseOptions {
    fn default() -> Self {
        Self {
            synchronous: SqliteSynchronous::Normal,
            cache_size_mb: 16,
            mmap_size_mb: 64,
            pool_size: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStore;

    #[tokio::test]
    async fn connect_applies_the_configured_pragmas() {
        let store = SqliteStore::connect_with("sqlite::memory:", DatabaseOptions::default())
            .await
            .expect("connect");
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&store.pool)
            .await
            .expect("synchronous");
        assert_eq!(synchronous, 1, "NORMAL == 1");
        let cache_size: i64 = sqlx::query_scalar("PRAGMA cache_size")
            .fetch_one(&store.pool)
            .await
            .expect("cache_size");
        assert_eq!(cache_size, -16 * 1024, "负数表示 KB，16 MB");
        // 内存库不支持 mmap，故不断言
    }
}
