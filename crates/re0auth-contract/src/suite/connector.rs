//! Connector registry mirror contract.

use re0auth_api::connector::{BodyField, BodyValue, ResourceMethod, ResourceSpec};
use re0auth_api::ports::{ConnectorRecord, Storage};
use re0auth_api::secret::SealedSecret;

/// Connector registry mirror and its secrets.
pub async fn connector_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let id = re0auth_api::ConnectorId::new();
    let record = ConnectorRecord {
        id,
        name: "contract-connector".to_string(),
        base_url: "https://upstream.example".to_string(),
        allow_private_net: false,
        allow_link_local_metadata: false,
        created_at: now,
        updated_at: now,
    };
    let resources = vec![
        ResourceSpec::new("scores", "/v1/scores/{subject}").expect("spec"),
        ResourceSpec::new("me", "/v1/me").expect("spec"),
        // A POST resource: the mirror must carry method, body, and idempotency,
        // or a stored registry would silently disagree with the config it mirrors.
        ResourceSpec::new("read_scores", "/v1/read")
            .expect("spec")
            .with_transport(
                ResourceMethod::Post,
                vec![
                    BodyField {
                        name: "api_user_id".to_string(),
                        value: BodyValue::Subject,
                    },
                    BodyField {
                        name: "token".to_string(),
                        value: BodyValue::Credential,
                    },
                ],
                false,
            )
            .expect("transport"),
    ];

    store
        .connectors()
        .upsert(&record, &resources, now)
        .await
        .expect("upsert connector");

    assert_eq!(
        store.connectors().get(&id).await.expect("get"),
        Some(record.clone())
    );
    assert_eq!(
        store
            .connectors()
            .find_by_name("contract-connector")
            .await
            .expect("find by name")
            .map(|found| found.id),
        Some(id)
    );
    assert_eq!(store.connectors().list().await.expect("list").len(), 1);

    let mut stored = store.connectors().resources(&id).await.expect("resources");
    stored.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(stored.len(), 3);
    assert_eq!(stored[0].name, "me");
    assert_eq!(stored[1].name, "read_scores");
    assert_eq!(stored[2].path_template, "/v1/scores/{subject}");
    // The transport must survive the mirror, not just the path and scope.
    assert_eq!(stored[1].method, ResourceMethod::Post);
    assert!(
        !stored[1].idempotent,
        "a POST is not retried unless declared"
    );
    assert_eq!(stored[1].body.len(), 2);
    assert_eq!(stored[1].body[0].value, BodyValue::Subject);
    assert_eq!(stored[1].body[1].value, BodyValue::Credential);

    // A second upsert replaces the resource set rather than merging it: a
    // template removed from the config must stop being reachable.
    store
        .connectors()
        .upsert(&record, &resources[..1], now + 10)
        .await
        .expect("re-upsert connector");
    let replaced = store.connectors().resources(&id).await.expect("resources");
    assert_eq!(replaced.len(), 1, "resources are replaced wholesale");

    // Names are unique across connectors.
    let clash = ConnectorRecord {
        id: re0auth_api::ConnectorId::new(),
        name: "contract-connector".to_string(),
        base_url: "https://other.example".to_string(),
        allow_private_net: false,
        allow_link_local_metadata: false,
        created_at: now,
        updated_at: now,
    };
    assert!(
        store.connectors().upsert(&clash, &[], now).await.is_err(),
        "two connectors must not share a name"
    );

    // Secrets round-trip as ciphertext only.
    let sealed = SealedSecret::new(1, vec![1; 12], vec![3; 44], vec![1; 12], vec![2; 32])
        .expect("sealed secret");
    assert!(
        store
            .connectors()
            .load_secret(&id, "hmac")
            .await
            .expect("load")
            .is_none()
    );
    store
        .connectors()
        .store_secret(&id, "hmac", &sealed, now)
        .await
        .expect("store secret");
    assert_eq!(
        store
            .connectors()
            .load_secret(&id, "hmac")
            .await
            .expect("load")
            .as_ref(),
        Some(&sealed)
    );
    store
        .connectors()
        .delete_secret(&id, "hmac")
        .await
        .expect("delete secret");
    assert!(
        store
            .connectors()
            .load_secret(&id, "hmac")
            .await
            .expect("load")
            .is_none()
    );

    // Deleting the connector cascades to its secrets.
    store
        .connectors()
        .store_secret(&id, "hmac", &sealed, now)
        .await
        .expect("store secret");
    assert!(store.connectors().delete(&id).await.expect("delete"));
    assert!(
        store
            .connectors()
            .load_secret(&id, "hmac")
            .await
            .expect("load")
            .is_none(),
        "secrets must not outlive their connector"
    );
    assert!(
        !store.connectors().delete(&id).await.expect("delete again"),
        "deleting a missing connector reports false"
    );
}
