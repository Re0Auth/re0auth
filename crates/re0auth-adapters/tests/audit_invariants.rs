//! INV-AUDIT-01: a security fact lands or rolls back together with the state
//! change it describes.
//!
//! The positive case is easy and uninteresting. The negative case is the whole
//! point: if the business write fails, the audit row must disappear too,
//! otherwise the log claims something happened that did not.

use re0auth_adapters::storage::SqliteStore;
use re0auth_api::audit::{AuditAction, SecurityFact};
use re0auth_api::ports::{AuthCode, Binding, BindingStatus, RepoError, Storage};
use re0auth_api::{AuthCodeId, BindingId, ClientId, UserId};

async fn seed_user_and_client(store: &SqliteStore) -> (UserId, ClientId) {
    let user = re0auth_api::ports::User {
        id: UserId::new(),
        display_name: "audit-user".to_string(),
        role: re0auth_api::ports::UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("seed user");
    let client = re0auth_api::ports::Client {
        id: ClientId::new(),
        name: "audit-client".to_string(),
        redirect_uris: vec!["https://client.example/callback".to_string()],
        allowed_scopes: vec!["phigros.stats.read".to_string()],
        raw_access: false,
        status: re0auth_api::ports::ClientStatus::Approved,
        secret_hash: None,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store
        .clients()
        .insert(
            &client,
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::ClientCreated,
                1_000,
                "client",
            ),
        )
        .await
        .expect("seed client");
    (user.id, client.id)
}

fn audit_code(hash: u8, user: UserId, client: ClientId) -> AuthCode {
    AuthCode {
        id: AuthCodeId::new(),
        code_hash: vec![hash; 32],
        client_id: client,
        user_id: user,
        redirect_uri: "https://client.example/callback".to_string(),
        scopes: vec!["phigros.stats.read".to_string()],
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        nonce: None,
        created_at: 1_000,
        expires_at: 2_000,
        consumed_at: None,
    }
}

fn fact(action: AuditAction) -> SecurityFact {
    SecurityFact::new(action, 1_000, "audit-test".to_string())
}

async fn latest_audit_count(store: &SqliteStore) -> usize {
    store
        .audits()
        .recent(1_000)
        .await
        .expect("recent audits")
        .len()
}

/// How many facts of one action exist. The seed now records its own
/// `ClientCreated` fact, so a bare total is no longer a useful assertion.
async fn count_action(store: &SqliteStore, action: AuditAction) -> usize {
    store
        .audits()
        .query(
            &re0auth_api::ports::AuditFilter {
                action: Some(action),
                ..Default::default()
            },
            None,
            1_000,
        )
        .await
        .expect("audit query")
        .len()
}

#[tokio::test]
async fn a_successful_change_and_its_fact_land_together() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let (user, client) = seed_user_and_client(&store).await;

    store
        .auth_codes()
        .insert(
            &audit_code(1, user, client),
            &fact(AuditAction::AuthCodeIssued),
        )
        .await
        .expect("insert");

    let audits = store.audits().recent(10).await.expect("audits");
    assert_eq!(
        count_action(&store, AuditAction::AuthCodeIssued).await,
        1,
        "the fact should have landed"
    );
    assert!(
        audits
            .iter()
            .any(|row| row.action == AuditAction::AuthCodeIssued)
    );
}

/// The negative case. A duplicate `code_hash` trips the unique constraint, the
/// transaction rolls back, and the audit row written for the *failing* attempt
/// must not survive.
#[tokio::test]
async fn a_failed_change_leaves_no_audit_row() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let (user, client) = seed_user_and_client(&store).await;

    let code = audit_code(7, user, client);
    store
        .auth_codes()
        .insert(&code, &fact(AuditAction::AuthCodeIssued))
        .await
        .expect("first insert");
    let after_first = count_action(&store, AuditAction::AuthCodeIssued).await;
    assert_eq!(after_first, 1);

    // Same hash again: the business INSERT itself fails before any fact is
    // written, so nothing should be logged.
    let mut duplicate = audit_code(7, user, client);
    duplicate.id = AuthCodeId::new();
    let outcome = store
        .auth_codes()
        .insert(&duplicate, &fact(AuditAction::AuthCodeIssued))
        .await;
    assert!(
        matches!(outcome, Err(RepoError::Conflict(_))),
        "expected a unique-constraint conflict, got {outcome:?}"
    );

    assert_eq!(
        count_action(&store, AuditAction::AuthCodeIssued).await,
        after_first,
        "the failed attempt must not have logged a fact (INV-AUDIT-01)"
    );
}

/// The direction that actually proves the transaction: the business INSERT
/// succeeds, then the audit INSERT fails. Both must vanish.
///
/// A duplicate audit id is the cheapest way to make the second write fail.
#[tokio::test]
async fn a_failed_audit_write_rolls_back_the_business_row() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let (user, client) = seed_user_and_client(&store).await;

    let first = fact(AuditAction::AuthCodeIssued);
    store
        .auth_codes()
        .insert(&audit_code(1, user, client), &first)
        .await
        .expect("first insert");

    // Reuse the same fact id for a different, otherwise valid auth code.
    let colliding = audit_code(2, user, client);
    let colliding_hash = colliding.code_hash.clone();
    let outcome = store.auth_codes().insert(&colliding, &first).await;
    assert!(
        outcome.is_err(),
        "the duplicate audit id should have failed the write"
    );

    // Probing with `consume`: if the row survived, this consumes it and
    // succeeds; if the transaction rolled back, the row is simply absent.
    let probe = store
        .auth_codes()
        .consume(
            re0auth_api::ports::ConsumeAuthCode {
                code_hash: &colliding_hash,
                client_id: client,
                redirect_uri: "https://client.example/callback",
                code_challenge: Some("challenge"),
                code_challenge_method: Some("S256"),
            },
            1_500,
        )
        .await;
    assert!(
        matches!(probe, Err(RepoError::NotFound)),
        "the auth code must not survive when its fact could not be written, got {probe:?}"
    );
    assert_eq!(
        count_action(&store, AuditAction::AuthCodeIssued).await,
        1,
        "only the first fact should exist"
    );
}

/// A binding write that violates a foreign key must also discard its fact.
#[tokio::test]
async fn a_failed_binding_write_leaves_no_audit_row() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");

    // `user_id` has no matching row, so the FK fails.
    let orphan = Binding {
        id: BindingId::new(),
        user_id: UserId::new(),
        upstream_id: "phigros".to_string(),
        upstream_user_id: "player".to_string(),
        status: BindingStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        last_refreshed_at: None,
        last_error_code: None,
    };

    let outcome = store
        .bindings()
        .upsert(&orphan, &fact(AuditAction::BindingCreated))
        .await;
    assert!(outcome.is_err(), "orphan binding should be rejected");
    assert_eq!(
        latest_audit_count(&store).await,
        0,
        "the failed attempt must not have logged a fact (INV-AUDIT-01)"
    );
}

/// Rotation of a consumed token is a reuse event. The row it writes must be
/// labelled with the reuse action, not the plain rotation action the caller
/// passed in.
#[tokio::test]
async fn reuse_detection_relabels_the_fact() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");

    let user = re0auth_api::ports::User {
        id: UserId::new(),
        display_name: "reuse".to_string(),
        role: re0auth_api::ports::UserRole::User,
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.users().create(&user).await.expect("user");
    let client = ClientId::new();
    store
        .clients()
        .insert(
            &re0auth_api::ports::Client {
                id: client,
                name: "reuse-client".to_string(),
                redirect_uris: vec!["https://client.example/callback".to_string()],
                allowed_scopes: vec!["phigros.stats.read".to_string()],
                raw_access: false,
                status: re0auth_api::ports::ClientStatus::Approved,
                secret_hash: None,
                created_at: 1_000,
                updated_at: 1_000,
            },
            &re0auth_api::audit::SecurityFact::new(
                re0auth_api::audit::AuditAction::ClientCreated,
                1_000,
                "client",
            ),
        )
        .await
        .expect("client");

    let family = re0auth_api::FamilyId::new();
    let token = re0auth_api::ports::RefreshToken {
        id: re0auth_api::RefreshTokenId::new(),
        token_hash: vec![9; 32],
        family_id: family,
        client_id: client,
        user_id: user.id,
        scopes: vec!["phigros.stats.read".to_string()],
        created_at: 1_000,
        expires_at: 9_000,
        consumed_at: None,
        revoked_at: None,
        replaced_by: None,
    };
    store.refresh_tokens().insert(&token).await.expect("token");

    store
        .refresh_tokens()
        .rotate(
            re0auth_api::ports::RotateRefreshToken {
                old_hash: &token.token_hash,
                new: re0auth_api::ports::RefreshToken {
                    id: re0auth_api::RefreshTokenId::new(),
                    token_hash: vec![10; 32],
                    family_id: family,
                    client_id: client,
                    user_id: user.id,
                    scopes: vec!["phigros.stats.read".to_string()],
                    created_at: 1_100,
                    expires_at: 9_000,
                    consumed_at: None,
                    revoked_at: None,
                    replaced_by: None,
                },
            },
            &fact(AuditAction::RefreshTokenRotated),
            1_100,
        )
        .await
        .expect("first rotate");

    // Second use of the same hash is reuse detection.
    let reused = store
        .refresh_tokens()
        .rotate(
            re0auth_api::ports::RotateRefreshToken {
                old_hash: &token.token_hash,
                new: re0auth_api::ports::RefreshToken {
                    id: re0auth_api::RefreshTokenId::new(),
                    token_hash: vec![11; 32],
                    family_id: family,
                    client_id: client,
                    user_id: user.id,
                    scopes: vec!["phigros.stats.read".to_string()],
                    created_at: 1_200,
                    expires_at: 9_000,
                    consumed_at: None,
                    revoked_at: None,
                    replaced_by: None,
                },
            },
            &fact(AuditAction::RefreshTokenRotated),
            1_200,
        )
        .await
        .expect("second rotate");

    assert!(
        matches!(
            reused,
            re0auth_api::ports::RotateOutcome::ReuseDetected { .. }
        ),
        "expected reuse detection, got {reused:?}"
    );

    let actions: Vec<_> = store
        .audits()
        .recent(10)
        .await
        .expect("audits")
        .into_iter()
        .map(|record| record.action)
        .collect();
    assert!(
        actions.contains(&AuditAction::RefreshTokenReuseDetected),
        "reuse must be recorded as a reuse fact, got {actions:?}"
    );
}

// ---------------------------------------------------------------------------
// One case per audited method.
//
// These exist because the per-method bodies were written independently: a
// copy-paste slip that dropped `record_fact`, or moved it outside the
// transaction, would still compile and would still pass every other test. Each
// case asserts that the *specific* action reaches the audit table.
// ---------------------------------------------------------------------------

async fn actions_after(store: &SqliteStore) -> Vec<AuditAction> {
    store
        .audits()
        .recent(100)
        .await
        .expect("audits")
        .into_iter()
        .map(|record| record.action)
        .collect()
}

#[tokio::test]
async fn every_audited_method_writes_its_action() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let (user, client) = seed_user_and_client(&store).await;

    // auth_codes::insert
    store
        .auth_codes()
        .insert(
            &audit_code(1, user, client),
            &fact(AuditAction::AuthCodeIssued),
        )
        .await
        .expect("auth code");
    assert!(
        actions_after(&store)
            .await
            .contains(&AuditAction::AuthCodeIssued),
        "auth_codes::insert did not record its fact"
    );

    // consents::grant
    store
        .consents()
        .grant(
            &re0auth_api::ports::Consent {
                id: re0auth_api::ConsentId::new(),
                user_id: user,
                client_id: client,
                scopes: vec!["openid".to_string()],
                created_at: 1_000,
                updated_at: 1_000,
                revoked_at: None,
            },
            &fact(AuditAction::ConsentGranted),
        )
        .await
        .expect("grant consent");
    assert!(
        actions_after(&store)
            .await
            .contains(&AuditAction::ConsentGranted),
        "consents::grant did not record its fact"
    );

    // consents::revoke
    store
        .consents()
        .revoke(&user, &client, &fact(AuditAction::ConsentRevoked), 1_100)
        .await
        .expect("revoke consent");
    assert!(
        actions_after(&store)
            .await
            .contains(&AuditAction::ConsentRevoked),
        "consents::revoke did not record its fact"
    );

    // bindings::upsert
    let binding = Binding {
        id: BindingId::new(),
        user_id: user,
        upstream_id: "phigros".to_string(),
        upstream_user_id: "player".to_string(),
        status: BindingStatus::Active,
        created_at: 1_000,
        updated_at: 1_000,
        last_refreshed_at: None,
        last_error_code: None,
    };
    store
        .bindings()
        .upsert(&binding, &fact(AuditAction::BindingCreated))
        .await
        .expect("upsert binding");
    assert!(
        actions_after(&store)
            .await
            .contains(&AuditAction::BindingCreated),
        "bindings::upsert did not record its fact"
    );

    // bindings::mark_needs_reauth
    store
        .bindings()
        .mark_needs_reauth(
            &binding.id,
            "upstream_401",
            &fact(AuditAction::BindingNeedsReauth),
            1_200,
        )
        .await
        .expect("mark needs reauth");
    assert!(
        actions_after(&store)
            .await
            .contains(&AuditAction::BindingNeedsReauth),
        "bindings::mark_needs_reauth did not record its fact"
    );

    // bindings::revoke
    store
        .bindings()
        .revoke(&binding.id, &fact(AuditAction::BindingRevoked), 1_300)
        .await
        .expect("revoke binding");
    assert!(
        actions_after(&store)
            .await
            .contains(&AuditAction::BindingRevoked),
        "bindings::revoke did not record its fact"
    );
}

#[tokio::test]
async fn refresh_token_methods_write_their_actions() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let (user, client) = seed_user_and_client(&store).await;

    let family = re0auth_api::FamilyId::new();
    let token = re0auth_api::ports::RefreshToken {
        id: re0auth_api::RefreshTokenId::new(),
        token_hash: vec![42; 32],
        family_id: family,
        client_id: client,
        user_id: user,
        scopes: vec!["openid".to_string()],
        created_at: 1_000,
        expires_at: 9_000,
        consumed_at: None,
        revoked_at: None,
        replaced_by: None,
    };
    store.refresh_tokens().insert(&token).await.expect("token");

    // rotate (success path)
    store
        .refresh_tokens()
        .rotate(
            re0auth_api::ports::RotateRefreshToken {
                old_hash: &token.token_hash,
                new: re0auth_api::ports::RefreshToken {
                    id: re0auth_api::RefreshTokenId::new(),
                    token_hash: vec![43; 32],
                    family_id: family,
                    client_id: client,
                    user_id: user,
                    scopes: vec!["openid".to_string()],
                    created_at: 1_100,
                    expires_at: 9_000,
                    consumed_at: None,
                    revoked_at: None,
                    replaced_by: None,
                },
            },
            &fact(AuditAction::RefreshTokenRotated),
            1_100,
        )
        .await
        .expect("rotate");
    assert!(
        actions_after(&store)
            .await
            .contains(&AuditAction::RefreshTokenRotated),
        "refresh_tokens::rotate did not record its fact"
    );

    // revoke_family
    store
        .refresh_tokens()
        .revoke_family(&family, &fact(AuditAction::RefreshTokenRevoked), 1_200)
        .await
        .expect("revoke family");
    assert!(
        actions_after(&store)
            .await
            .contains(&AuditAction::RefreshTokenRevoked),
        "refresh_tokens::revoke_family did not record its fact"
    );
}

/// `revoke` on a consent that was never granted affects zero rows. Nothing was
/// revoked, so nothing may be logged — otherwise the audit trail would claim an
/// authorization was taken away when none existed.
#[tokio::test]
async fn a_no_op_revoke_logs_nothing() {
    let store = SqliteStore::connect("sqlite::memory:")
        .await
        .expect("store");
    let (user, client) = seed_user_and_client(&store).await;

    let outcome = store
        .consents()
        .revoke(&user, &client, &fact(AuditAction::ConsentRevoked), 1_000)
        .await;
    assert!(matches!(outcome, Err(RepoError::NotFound)));
    assert_eq!(
        count_action(&store, AuditAction::ConsentRevoked).await,
        0,
        "a failed revoke must not leave a fact behind"
    );
}
