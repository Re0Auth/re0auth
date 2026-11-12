//! Connector registry mirror.
//!
//! The config file stays authoritative; this table exists so that resources and
//! connector-level secrets have rows to hang off, and so the registry survives a
//! restart without re-deriving it from TOML on every read.

use async_trait::async_trait;
use re0auth_api::connector::{BodyField, BodyValue, ResourceMethod, ResourceSpec};
use re0auth_api::ports::{ConnectorRecord, ConnectorRepo, RepoError, RepoResult};
use re0auth_api::secret::SealedSecret;
use re0auth_api::{ConnectorId, Unix};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use super::{SqliteStore, db_error, parse_uuid};

/// The mirror's string spelling of a body: field name → `{subject}` / `{credential}` / literal.
fn body_json(resource: &ResourceSpec) -> RepoResult<String> {
    let map: std::collections::BTreeMap<&str, String> = resource
        .body
        .iter()
        .map(|field| (field.name.as_str(), field.value.as_token()))
        .collect();
    serde_json::to_string(&map)
        .map_err(|error| RepoError::Backend(format!("stored resource body: {error}")))
}

fn typed_body_json(resource: &ResourceSpec) -> RepoResult<Option<String>> {
    if resource.raw_body.is_some() || resource.method != ResourceMethod::Post {
        return Ok(None);
    }
    let map: std::collections::BTreeMap<&str, &BodyValue> = resource
        .body
        .iter()
        .map(|field| (field.name.as_str(), &field.value))
        .collect();
    serde_json::to_string(&map)
        .map(Some)
        .map_err(|error| RepoError::Backend(format!("stored typed resource body: {error}")))
}

fn raw_body_json(resource: &ResourceSpec) -> RepoResult<Option<String>> {
    resource
        .raw_body
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| RepoError::Backend(format!("stored raw resource body: {error}")))
}

fn parse_body(raw: &str) -> RepoResult<Vec<BodyField>> {
    let map: std::collections::BTreeMap<String, String> = serde_json::from_str(raw)
        .map_err(|error| RepoError::Backend(format!("stored resource body: {error}")))?;
    Ok(map
        .into_iter()
        .map(|(name, value)| BodyField {
            name,
            value: BodyValue::parse(&value),
        })
        .collect())
}

fn parse_typed_body(raw: &str) -> RepoResult<Vec<BodyField>> {
    let map: std::collections::BTreeMap<String, BodyValue> = serde_json::from_str(raw)
        .map_err(|error| RepoError::Backend(format!("stored typed resource body: {error}")))?;
    Ok(map
        .into_iter()
        .map(|(name, value)| BodyField { name, value })
        .collect())
}

fn parse_raw_body(raw: &str) -> RepoResult<serde_json::Value> {
    serde_json::from_str(raw)
        .map_err(|error| RepoError::Backend(format!("stored raw resource body: {error}")))
}

fn row_to_connector(row: &SqliteRow) -> RepoResult<ConnectorRecord> {
    Ok(ConnectorRecord {
        id: ConnectorId(parse_uuid(
            &row.try_get::<String, _>("id").map_err(db_error)?,
        )?),
        name: row.try_get("name").map_err(db_error)?,
        display_name: row.try_get("display_name").map_err(db_error)?,
        base_url: row.try_get("base_url").map_err(db_error)?,
        allow_private_net: row
            .try_get::<i64, _>("allow_private_net")
            .map_err(db_error)?
            != 0,
        allow_link_local_metadata: row
            .try_get::<i64, _>("allow_link_local_metadata")
            .map_err(db_error)?
            != 0,
        created_at: row.try_get("created_at").map_err(db_error)?,
        updated_at: row.try_get("updated_at").map_err(db_error)?,
    })
}

fn row_to_resource(row: &SqliteRow) -> RepoResult<ResourceSpec> {
    let name: String = row.try_get("name").map_err(db_error)?;
    let path_template: String = row.try_get("path_template").map_err(db_error)?;
    let required_scope: String = row.try_get("required_scope").map_err(db_error)?;
    let method_raw: String = row.try_get("method").map_err(db_error)?;
    let method = ResourceMethod::parse(&method_raw).ok_or_else(|| {
        RepoError::Backend(format!("stored resource: unknown method {method_raw:?}"))
    })?;
    let idempotent: i64 = row.try_get("idempotent").map_err(db_error)?;
    let body_raw: String = row.try_get("body_json").map_err(db_error)?;
    let typed_body_raw: Option<String> = row.try_get("body_typed_json").map_err(db_error)?;
    let raw_body_raw: Option<String> = row.try_get("raw_body_json").map_err(db_error)?;
    let spec = ResourceSpec::new(name, path_template)
        .map_err(|error| RepoError::Backend(format!("stored resource: {error}")))?;
    let spec = if let Some(raw) = raw_body_raw {
        let raw_body = parse_raw_body(&raw)?;
        spec.with_transport_declared(method, Vec::new(), idempotent != 0, true)
            .and_then(|spec| spec.with_raw_body(raw_body))
    } else if let Some(raw) = typed_body_raw {
        let body = parse_typed_body(&raw)?;
        spec.with_transport_declared(method, body, idempotent != 0, true)
    } else {
        let body = parse_body(&body_raw)?;
        let body_declared = method == ResourceMethod::Post || !body.is_empty();
        spec.with_transport_declared(method, body, idempotent != 0, body_declared)
    }
    .and_then(|spec| spec.with_scope(required_scope))
    .map_err(|error| RepoError::Backend(format!("stored resource: {error}")))?;
    Ok(spec)
}

#[async_trait]
impl ConnectorRepo for SqliteStore {
    async fn upsert(
        &self,
        connector: &ConnectorRecord,
        resources: &[ResourceSpec],
        now: Unix,
    ) -> RepoResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO connectors \
             (id, name, display_name, base_url, allow_private_net, allow_link_local_metadata, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
             name = excluded.name, \
             display_name = excluded.display_name, \
             base_url = excluded.base_url, \
             allow_private_net = excluded.allow_private_net, \
             allow_link_local_metadata = excluded.allow_link_local_metadata, \
             updated_at = excluded.updated_at",
        )
        .bind(connector.id.0.to_string())
        .bind(&connector.name)
        .bind(&connector.display_name)
        .bind(&connector.base_url)
        .bind(i64::from(connector.allow_private_net))
        .bind(i64::from(connector.allow_link_local_metadata))
        .bind(connector.created_at)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        // Replace wholesale: the config file is the source of truth, and leaving
        // a stale template behind would keep a URL reachable that no longer
        // exists upstream.
        sqlx::query("DELETE FROM connector_resources WHERE connector_id = ?")
            .bind(connector.id.0.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        for resource in resources {
            let body = body_json(resource)?;
            let typed_body = typed_body_json(resource)?;
            let raw_body = raw_body_json(resource)?;
            sqlx::query(
                "INSERT INTO connector_resources \
                 (connector_id, name, path_template, required_scope, method, idempotent, \
                  body_json, body_typed_json, raw_body_json) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(connector.id.0.to_string())
            .bind(&resource.name)
            .bind(&resource.path_template)
            .bind(&resource.required_scope)
            .bind(resource.method.as_str())
            .bind(i64::from(resource.idempotent))
            .bind(body)
            .bind(typed_body)
            .bind(raw_body)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        }

        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn get(&self, id: &ConnectorId) -> RepoResult<Option<ConnectorRecord>> {
        let row = sqlx::query(
            "SELECT id, name, display_name, base_url, allow_private_net, allow_link_local_metadata, \
             created_at, updated_at FROM connectors WHERE id = ?",
        )
        .bind(id.0.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_connector).transpose()
    }

    async fn find_by_name(&self, name: &str) -> RepoResult<Option<ConnectorRecord>> {
        let row = sqlx::query(
            "SELECT id, name, display_name, base_url, allow_private_net, allow_link_local_metadata, \
             created_at, updated_at FROM connectors WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        row.as_ref().map(row_to_connector).transpose()
    }

    async fn list(&self) -> RepoResult<Vec<ConnectorRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, display_name, base_url, allow_private_net, allow_link_local_metadata, \
             created_at, updated_at FROM connectors ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_connector).collect()
    }

    async fn resources(&self, id: &ConnectorId) -> RepoResult<Vec<ResourceSpec>> {
        let rows = sqlx::query(
            "SELECT name, path_template, required_scope, method, idempotent, \
             body_json, body_typed_json, raw_body_json \
             FROM connector_resources WHERE connector_id = ? ORDER BY name",
        )
        .bind(id.0.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter().map(row_to_resource).collect()
    }

    async fn resources_all(&self) -> RepoResult<Vec<(ConnectorId, ResourceSpec)>> {
        let rows = sqlx::query(
            "SELECT connector_id, name, path_template, required_scope, method, idempotent, \
             body_json, body_typed_json, raw_body_json \
             FROM connector_resources ORDER BY connector_id, name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        rows.iter()
            .map(|row| {
                let connector = ConnectorId(parse_uuid(
                    &row.try_get::<String, _>("connector_id").map_err(db_error)?,
                )?);
                Ok((connector, row_to_resource(row)?))
            })
            .collect()
    }

    async fn delete(&self, id: &ConnectorId) -> RepoResult<bool> {
        let result = sqlx::query("DELETE FROM connectors WHERE id = ?")
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn store_secret(
        &self,
        connector: &ConnectorId,
        kind: &str,
        sealed: &SealedSecret,
        now: Unix,
    ) -> RepoResult<()> {
        sqlx::query(
            "INSERT INTO connector_secrets \
             (connector_id, kind, key_version, dek_nonce, wrapped_dek, nonce, ciphertext, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(connector_id, kind) DO UPDATE SET \
             key_version = excluded.key_version, \
             dek_nonce = excluded.dek_nonce, \
             wrapped_dek = excluded.wrapped_dek, \
             nonce = excluded.nonce, \
             ciphertext = excluded.ciphertext, \
             updated_at = excluded.updated_at",
        )
        .bind(connector.0.to_string())
        .bind(kind)
        .bind(i64::from(sealed.key_version()))
        .bind(sealed.dek_nonce())
        .bind(sealed.wrapped_dek())
        .bind(sealed.nonce())
        .bind(sealed.ciphertext())
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn load_secret(
        &self,
        connector: &ConnectorId,
        kind: &str,
    ) -> RepoResult<Option<SealedSecret>> {
        let row = sqlx::query(
            "SELECT key_version, dek_nonce, wrapped_dek, nonce, ciphertext FROM connector_secrets \
             WHERE connector_id = ? AND kind = ?",
        )
        .bind(connector.0.to_string())
        .bind(kind)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let key_version: i64 = row.try_get("key_version").map_err(db_error)?;
        Ok(Some(
            SealedSecret::new(
                u32::try_from(key_version).map_err(|_| {
                    RepoError::Backend(format!("invalid key_version {key_version}"))
                })?,
                row.try_get("dek_nonce").map_err(db_error)?,
                row.try_get("wrapped_dek").map_err(db_error)?,
                row.try_get("nonce").map_err(db_error)?,
                row.try_get("ciphertext").map_err(db_error)?,
            )
            .map_err(|error| RepoError::Backend(error.to_string()))?,
        ))
    }

    async fn delete_secret(&self, connector: &ConnectorId, kind: &str) -> RepoResult<()> {
        sqlx::query("DELETE FROM connector_secrets WHERE connector_id = ? AND kind = ?")
            .bind(connector.0.to_string())
            .bind(kind)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recursive_body_rows_prefer_raw_then_typed_then_legacy() {
        let store = SqliteStore::connect("sqlite::memory:")
            .await
            .expect("SQLite store with migrations");
        let now = 1_000;
        let id = ConnectorId::new();
        let record = ConnectorRecord {
            id,
            name: "recursive-body-storage".to_string(),
            display_name: "Recursive body storage".to_string(),
            base_url: "https://upstream.example".to_string(),
            allow_private_net: false,
            allow_link_local_metadata: false,
            created_at: now,
            updated_at: now,
        };
        let raw_resource = ResourceSpec::new("choice", "/v1/choice")
            .expect("spec")
            .with_transport_declared(ResourceMethod::Post, Vec::new(), false, true)
            .expect("raw body transport")
            .with_raw_body(serde_json::json!({
                "source": "raw",
                "nested": { "history": null, "enabled": false }
            }))
            .expect("raw body");
        store
            .upsert(&record, std::slice::from_ref(&raw_resource), now)
            .await
            .expect("upsert raw resource");

        // The old column remains readable by old binaries even for a raw body.
        let row = sqlx::query(
            "SELECT body_json FROM connector_resources WHERE connector_id = ? AND name = 'choice'",
        )
        .bind(id.0.to_string())
        .fetch_one(&store.pool)
        .await
        .expect("legacy body column");
        assert_eq!(row.get::<String, _>("body_json"), "{}");

        sqlx::query(
            "UPDATE connector_resources SET body_json = ?, body_typed_json = ? \
             WHERE connector_id = ? AND name = 'choice'",
        )
        .bind(r#"{"source":"legacy"}"#)
        .bind(r#"{"source":{"json":{"enabled":false,"history":null}}}"#)
        .bind(id.0.to_string())
        .execute(&store.pool)
        .await
        .expect("install competing representations");

        let stored = store.resources(&id).await.expect("raw resource");
        assert_eq!(stored, vec![raw_resource], "raw JSON takes precedence");

        sqlx::query(
            "UPDATE connector_resources SET raw_body_json = NULL \
             WHERE connector_id = ? AND name = 'choice'",
        )
        .bind(id.0.to_string())
        .execute(&store.pool)
        .await
        .expect("remove raw representation");
        let stored = store.resources(&id).await.expect("typed resource");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].raw_body, None);
        assert_eq!(
            stored[0].body,
            vec![BodyField {
                name: "source".to_string(),
                value: BodyValue::Literal(serde_json::json!({
                    "enabled": false,
                    "history": null
                })),
            }],
            "typed JSON takes precedence over the legacy map"
        );

        sqlx::query(
            "UPDATE connector_resources SET body_typed_json = NULL \
             WHERE connector_id = ? AND name = 'choice'",
        )
        .bind(id.0.to_string())
        .execute(&store.pool)
        .await
        .expect("remove typed representation");
        let stored = store.resources(&id).await.expect("legacy resource");
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].body,
            vec![BodyField {
                name: "source".to_string(),
                value: BodyValue::Literal(serde_json::Value::String("legacy".to_string())),
            }],
            "legacy rows remain readable"
        );

        // A pre-migration empty POST body has no declaration bit; `{}` is its
        // legacy representation and must not turn into an absent declaration.
        sqlx::query(
            "UPDATE connector_resources SET body_json = '{}' \
             WHERE connector_id = ? AND name = 'choice'",
        )
        .bind(id.0.to_string())
        .execute(&store.pool)
        .await
        .expect("write legacy empty body");
        let stored = store
            .resources(&id)
            .await
            .expect("legacy explicitly empty resource");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].method, ResourceMethod::Post);
        assert!(stored[0].body.is_empty());
        assert_eq!(stored[0].raw_body, None);
    }
}
