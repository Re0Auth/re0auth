//! The shared storage contract.
//!
//! Each function is a complete test paper for one port. `storage_contract_suite`
//! runs all of them; adapters may also call individual suites while migrating.

pub mod approval_ticket;
pub mod binding;
pub mod connector;
pub mod device_attempt;
pub mod device_code;
pub mod refresh_revoke;

pub use approval_ticket::approval_ticket_contract;
pub use binding::binding_contract;
pub use connector::connector_contract;
pub use device_attempt::device_attempt_contract;
pub use device_code::device_code_contract;
pub use refresh_revoke::{revoke_all_for_client_contract, revoked_family_contract};

use re0auth_api::audit::{
    AuditAction, AuditOutcome, AuditRecord, AuditTier, SecurityFact, Severity,
};
use re0auth_api::oauth::ConsentVersion;
use re0auth_api::ports::{
    AuditFilter, AuthCode, Binding, BindingQuery, BindingStatus, Client, ClientStatus, Consent,
    ConsumeAuthCode, DeviceCode, DeviceCodeState, Identity, LoginTransaction, PendingAuthorization,
    PendingBinding, RefreshToken, RepoError, RotateOutcome, RotateRefreshToken, Session, Storage,
    User, UserRole,
};
use re0auth_api::secret::ClientSecretHash;
use re0auth_api::{
    AuditId, AuthCodeId, BindingId, ClientId, ConsentId, DeviceCodeId, FamilyId, IdentityId,
    PendingAuthorizationId, RefreshTokenId, SessionId, Unix, UserId,
};

/// A fact for suites that only care that the write happens.
fn fact(action: AuditAction, now: Unix, target: &str) -> SecurityFact {
    SecurityFact::new(action, now, target)
}

/// A device-decision fact. `client_id` is intentionally left unset: the store
/// fills it from the device code, which is the whole point of the contract.
pub(super) fn device_fact(action: AuditAction, now: Unix, actor: UserId) -> SecurityFact {
    SecurityFact::new(action, now, "user_code_hash:test").actor(actor)
}

fn user(now: Unix) -> User {
    User {
        id: UserId::new(),
        display_name: "contract-user".to_string(),
        role: UserRole::User,
        created_at: now,
        updated_at: now,
    }
}

fn session(user: UserId, hash: u8, created: Unix, idle: Unix, absolute: Unix) -> Session {
    Session {
        id: SessionId::new(),
        id_hash: vec![hash; 32],
        user_id: user,
        csrf_hash: vec![hash.wrapping_add(1); 32],
        created_at: created,
        last_seen_at: created,
        idle_expires_at: idle,
        absolute_expires_at: absolute,
        revoked_at: None,
    }
}

fn auth_code(user: UserId, client: ClientId, hash: u8, expires: Unix) -> AuthCode {
    AuthCode {
        id: AuthCodeId::new(),
        code_hash: vec![hash; 32],
        client_id: client,
        user_id: user,
        redirect_uri: "https://client.example/callback".to_string(),
        scopes: vec!["phigros.stats.read".to_string()],
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        nonce: Some("nonce".to_string()),
        created_at: 1_000,
        expires_at: expires,
        consumed_at: None,
    }
}

fn refresh(
    user: UserId,
    client: ClientId,
    family: FamilyId,
    hash: u8,
    expires: Unix,
) -> RefreshToken {
    RefreshToken {
        id: RefreshTokenId::new(),
        token_hash: vec![hash; 32],
        family_id: family,
        client_id: client,
        user_id: user,
        scopes: vec!["phigros.stats.read".to_string()],
        created_at: 1_000,
        expires_at: expires,
        consumed_at: None,
        revoked_at: None,
        replaced_by: None,
    }
}

pub(super) fn device_code(user_code_hash: u8, client: ClientId, expires: Unix) -> DeviceCode {
    DeviceCode {
        id: DeviceCodeId::new(),
        device_code_hash: vec![user_code_hash.wrapping_add(1); 32],
        user_code_hash: vec![user_code_hash; 32],
        client_id: client,
        scopes: vec!["phigros.stats.read".to_string()],
        state: DeviceCodeState::Pending,
        interval_secs: 5,
        last_polled_at: None,
        poll_count: 0,
        user_code_misses: 0,
        created_at: 1_000,
        expires_at: expires,
        consumed_at: None,
    }
}

fn client(now: Unix) -> Client {
    Client {
        id: ClientId::new(),
        name: "contract-client".to_string(),
        redirect_uris: vec!["https://client.example/callback".to_string()],
        allowed_scopes: vec!["openid".to_string(), "phigros.stats.read".to_string()],
        raw_access: false,
        status: ClientStatus::Approved,
        secret_hash: None,
        created_at: now,
        updated_at: now,
    }
}

pub(super) fn binding(user: UserId, id: BindingId, status: BindingStatus, now: Unix) -> Binding {
    Binding {
        id,
        user_id: user,
        upstream_id: "phigros".to_string(),
        upstream_user_id: "upstream-user".to_string(),
        status,
        created_at: now,
        updated_at: now,
        last_refreshed_at: None,
        last_error_code: None,
    }
}

pub async fn user_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = user(now);
    store.users().create(&user).await.expect("create user");
    assert_eq!(
        store.users().get(&user.id).await.expect("get user"),
        Some(user.clone())
    );
    assert!(matches!(
        store.users().create(&user).await,
        Err(RepoError::Conflict(_))
    ));

    let identity = Identity {
        id: IdentityId::new(),
        user_id: user.id,
        issuer: "https://idp.example".to_string(),
        subject: "subject-1".to_string(),
        created_at: now,
    };
    store
        .users()
        .link_identity(&identity)
        .await
        .expect("link identity");
    assert_eq!(
        store
            .users()
            .find_by_identity("https://idp.example", "subject-1")
            .await
            .expect("find identity"),
        Some(user.clone())
    );
    assert!(matches!(
        store.users().link_identity(&identity).await,
        Err(RepoError::Conflict(_))
    ));

    let session = session(user.id, 1, now, 2_000, 5_000);
    let code = auth_code(user.id, ClientId::new(), 2, 2_000);
    let token = refresh(user.id, ClientId::new(), FamilyId::new(), 3, 5_000);
    let link = binding(user.id, BindingId::new(), BindingStatus::Active, now);
    store.sessions().create(&session).await.expect("session");
    store
        .auth_codes()
        .insert(&code, &fact(AuditAction::AuthCodeIssued, now, "code"))
        .await
        .expect("auth code");
    store
        .refresh_tokens()
        .insert(&token)
        .await
        .expect("refresh token");
    store
        .bindings()
        .upsert(&link, &fact(AuditAction::BindingCreated, now, "binding"))
        .await
        .expect("binding");

    assert!(store.users().delete(&user.id).await.expect("delete user"));
    assert_eq!(
        store.users().get(&user.id).await.expect("get deleted"),
        None
    );
    assert_eq!(
        store
            .sessions()
            .find_active(&session.id_hash, now)
            .await
            .expect("session after delete"),
        None
    );
    assert!(matches!(
        store
            .auth_codes()
            .consume(
                ConsumeAuthCode {
                    code_hash: &code.code_hash,
                    client_id: code.client_id,
                    redirect_uri: &code.redirect_uri,
                    code_challenge: code.code_challenge.as_deref(),
                    code_challenge_method: code.code_challenge_method.as_deref(),
                },
                now,
            )
            .await,
        Err(RepoError::NotFound)
    ));
    assert!(matches!(
        store
            .refresh_tokens()
            .rotate(
                RotateRefreshToken {
                    old_hash: &token.token_hash,
                    new: refresh(user.id, token.client_id, token.family_id, 4, 6_000),
                },
                &fact(AuditAction::RefreshTokenRotated, 1_000, "refresh"),
                now,
            )
            .await
            .expect("rotate after delete"),
        RotateOutcome::NotFound
    ));
    assert_eq!(
        store
            .bindings()
            .find(&user.id, "phigros")
            .await
            .expect("binding after delete"),
        None
    );
    assert!(!store.users().delete(&user.id).await.expect("delete again"));
}

pub async fn session_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = user(now);
    store.users().create(&user).await.expect("create user");

    let first = session(user.id, 10, now, 2_000, 5_000);
    store
        .sessions()
        .create(&first)
        .await
        .expect("create session");
    assert!(matches!(
        store.sessions().create(&first).await,
        Err(RepoError::Conflict(_))
    ));
    assert_eq!(
        store
            .sessions()
            .find_active(&first.id_hash, now)
            .await
            .expect("active session"),
        Some(first.clone())
    );

    store
        .sessions()
        .touch(&first.id_hash, 1_500, 2_500)
        .await
        .expect("touch session");
    let touched = store
        .sessions()
        .find_active(&first.id_hash, 2_000)
        .await
        .expect("touched session")
        .expect("session still active");
    assert_eq!(touched.last_seen_at, 1_500);
    assert_eq!(touched.idle_expires_at, 2_500);

    store
        .sessions()
        .revoke(&first.id_hash, 2_100)
        .await
        .expect("revoke session");
    assert_eq!(
        store
            .sessions()
            .find_active(&first.id_hash, 2_200)
            .await
            .expect("revoked session"),
        None
    );
    assert!(matches!(
        store.sessions().touch(&first.id_hash, 2_300, 3_000).await,
        Err(RepoError::Revoked)
    ));

    let second = session(user.id, 11, now, 2_000, 5_000);
    let third = session(user.id, 12, now, 2_000, 5_000);
    store.sessions().create(&second).await.expect("second");
    store.sessions().create(&third).await.expect("third");
    assert_eq!(
        store
            .sessions()
            .revoke_all(&user.id, 2_400)
            .await
            .expect("revoke all"),
        2
    );

    let idle_expired = session(user.id, 13, now, 1_100, 5_000);
    store
        .sessions()
        .create(&idle_expired)
        .await
        .expect("idle expired");
    assert_eq!(
        store
            .sessions()
            .find_active(&idle_expired.id_hash, 1_100)
            .await
            .expect("idle expired lookup"),
        None
    );
    assert!(matches!(
        store
            .sessions()
            .touch(&idle_expired.id_hash, 1_100, 2_000)
            .await,
        Err(RepoError::NotFound)
    ));

    let purge = session(user.id, 14, now, 1_500, 2_000);
    store
        .sessions()
        .create(&purge)
        .await
        .expect("purge session");
    let purged = store
        .sessions()
        .purge_expired(3_000)
        .await
        .expect("purge sessions");
    assert!(purged >= 1, "purge should remove expired rows");
    assert_eq!(
        store
            .sessions()
            .find_active(&purge.id_hash, 1_000)
            .await
            .expect("purged lookup"),
        None
    );
}

pub async fn auth_code_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = user(now);
    let client = ClientId::new();
    store.users().create(&user).await.expect("create user");

    let code = auth_code(user.id, client, 20, 2_000);
    store
        .auth_codes()
        .insert(&code, &fact(AuditAction::AuthCodeIssued, now, "code"))
        .await
        .expect("insert code");
    assert!(matches!(
        store
            .auth_codes()
            .insert(&code, &fact(AuditAction::AuthCodeIssued, now, "code"))
            .await,
        Err(RepoError::Conflict(_))
    ));

    let grant = store
        .auth_codes()
        .consume(
            ConsumeAuthCode {
                code_hash: &code.code_hash,
                client_id: client,
                redirect_uri: &code.redirect_uri,
                code_challenge: code.code_challenge.as_deref(),
                code_challenge_method: code.code_challenge_method.as_deref(),
            },
            now,
        )
        .await
        .expect("consume code");
    assert_eq!(grant.user_id, user.id);
    assert_eq!(grant.client_id, client);
    assert_eq!(grant.scopes, code.scopes);
    assert_eq!(grant.nonce, code.nonce);
    assert!(matches!(
        store
            .auth_codes()
            .consume(
                ConsumeAuthCode {
                    code_hash: &code.code_hash,
                    client_id: client,
                    redirect_uri: &code.redirect_uri,
                    code_challenge: code.code_challenge.as_deref(),
                    code_challenge_method: code.code_challenge_method.as_deref(),
                },
                now,
            )
            .await,
        Err(RepoError::AlreadyConsumed)
    ));

    let expired = auth_code(user.id, client, 21, 1_000);
    store
        .auth_codes()
        .insert(&expired, &fact(AuditAction::AuthCodeIssued, now, "code"))
        .await
        .expect("expired code");
    assert!(matches!(
        store
            .auth_codes()
            .consume(
                ConsumeAuthCode {
                    code_hash: &expired.code_hash,
                    client_id: client,
                    redirect_uri: &expired.redirect_uri,
                    code_challenge: expired.code_challenge.as_deref(),
                    code_challenge_method: expired.code_challenge_method.as_deref(),
                },
                1_000,
            )
            .await,
        Err(RepoError::Expired)
    ));

    let mismatch = auth_code(user.id, client, 22, 2_000);
    store
        .auth_codes()
        .insert(&mismatch, &fact(AuditAction::AuthCodeIssued, now, "code"))
        .await
        .expect("mismatch code");
    assert!(matches!(
        store
            .auth_codes()
            .consume(
                ConsumeAuthCode {
                    code_hash: &mismatch.code_hash,
                    client_id: ClientId::new(),
                    redirect_uri: &mismatch.redirect_uri,
                    code_challenge: mismatch.code_challenge.as_deref(),
                    code_challenge_method: mismatch.code_challenge_method.as_deref(),
                },
                now,
            )
            .await,
        Err(RepoError::NotFound)
    ));
    assert!(matches!(
        store
            .auth_codes()
            .consume(
                ConsumeAuthCode {
                    code_hash: &mismatch.code_hash,
                    client_id: client,
                    redirect_uri: "https://client.example/other",
                    code_challenge: mismatch.code_challenge.as_deref(),
                    code_challenge_method: mismatch.code_challenge_method.as_deref(),
                },
                now,
            )
            .await,
        Err(RepoError::NotFound)
    ));
    assert!(matches!(
        store
            .auth_codes()
            .consume(
                ConsumeAuthCode {
                    code_hash: &mismatch.code_hash,
                    client_id: client,
                    redirect_uri: &mismatch.redirect_uri,
                    code_challenge: Some("wrong-challenge"),
                    code_challenge_method: Some("S256"),
                },
                now,
            )
            .await,
        Err(RepoError::NotFound)
    ));
    store
        .auth_codes()
        .consume(
            ConsumeAuthCode {
                code_hash: &mismatch.code_hash,
                client_id: client,
                redirect_uri: &mismatch.redirect_uri,
                code_challenge: mismatch.code_challenge.as_deref(),
                code_challenge_method: mismatch.code_challenge_method.as_deref(),
            },
            now,
        )
        .await
        .expect("mismatch did not consume");

    let purged = store
        .auth_codes()
        .purge_expired(3_000)
        .await
        .expect("purge codes");
    assert!(purged >= 1, "purge should remove expired rows");
}

pub async fn refresh_token_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = user(now);
    let client = ClientId::new();
    let family = FamilyId::new();
    store.users().create(&user).await.expect("create user");

    let old = refresh(user.id, client, family, 30, 10_000);
    store
        .refresh_tokens()
        .insert(&old)
        .await
        .expect("insert old token");
    assert_eq!(
        store
            .refresh_tokens()
            .find(&old.token_hash)
            .await
            .expect("find refresh token"),
        Some(old.clone())
    );
    assert_eq!(
        store
            .refresh_tokens()
            .find(&[99; 32])
            .await
            .expect("find missing refresh token"),
        None
    );
    assert!(matches!(
        store.refresh_tokens().insert(&old).await,
        Err(RepoError::Conflict(_))
    ));

    let new = refresh(user.id, client, family, 31, 20_000);
    let outcome = store
        .refresh_tokens()
        .rotate(
            RotateRefreshToken {
                old_hash: &old.token_hash,
                new: new.clone(),
            },
            &fact(AuditAction::RefreshTokenRotated, now, "refresh"),
            now,
        )
        .await
        .expect("rotate token");
    assert!(matches!(outcome, RotateOutcome::Rotated(token) if token.id == new.id));

    let reuse = store
        .refresh_tokens()
        .rotate(
            RotateRefreshToken {
                old_hash: &old.token_hash,
                new: refresh(user.id, client, family, 32, 20_000),
            },
            &fact(AuditAction::RefreshTokenRotated, 1_100, "refresh"),
            1_100,
        )
        .await
        .expect("reuse detection");
    match reuse {
        RotateOutcome::ReuseDetected { family_revoked } => {
            assert!(family_revoked >= 1, "reuse must revoke the family");
        }
        other => panic!("expected reuse detection, got {other:?}"),
    }
    assert!(matches!(
        store
            .refresh_tokens()
            .rotate(
                RotateRefreshToken {
                    old_hash: &new.token_hash,
                    new: refresh(user.id, client, family, 33, 20_000),
                },
                &fact(AuditAction::RefreshTokenRotated, 1_200, "refresh"),
                1_200,
            )
            .await
            .expect("new token after family revoke"),
        RotateOutcome::Revoked
    ));

    let other_family = FamilyId::new();
    let other = refresh(user.id, client, other_family, 34, 10_000);
    store
        .refresh_tokens()
        .insert(&other)
        .await
        .expect("other family");
    assert_eq!(
        store
            .refresh_tokens()
            .revoke_family(
                &other_family,
                &fact(AuditAction::RefreshTokenRevoked, 1_300, "family"),
                1_300
            )
            .await
            .expect("revoke family"),
        1
    );

    let expired = refresh(user.id, client, FamilyId::new(), 35, 1_000);
    store
        .refresh_tokens()
        .insert(&expired)
        .await
        .expect("expired token");
    assert!(matches!(
        store
            .refresh_tokens()
            .rotate(
                RotateRefreshToken {
                    old_hash: &expired.token_hash,
                    new: refresh(user.id, client, expired.family_id, 36, 5_000),
                },
                &fact(AuditAction::RefreshTokenRotated, 1_000, "refresh"),
                1_000,
            )
            .await
            .expect("expired rotate"),
        RotateOutcome::Expired
    ));

    let purged = store
        .refresh_tokens()
        .purge_expired(3_000)
        .await
        .expect("purge tokens");
    assert!(purged >= 1, "purge should remove expired rows");
}

pub async fn client_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let client = client(now);
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated, now, "client"))
        .await
        .expect("insert client");
    assert_eq!(
        store.clients().get(&client.id).await.expect("get client"),
        Some(client.clone())
    );
    assert!(matches!(
        store
            .clients()
            .insert(&client, &fact(AuditAction::ClientCreated, now, "client"))
            .await,
        Err(RepoError::Conflict(_))
    ));

    store
        .clients()
        .set_status(&client.id, ClientStatus::Suspended, 1_100)
        .await
        .expect("suspend client");
    let suspended = store
        .clients()
        .get(&client.id)
        .await
        .expect("get suspended")
        .expect("client exists");
    assert_eq!(suspended.status, ClientStatus::Suspended);
    assert_eq!(suspended.updated_at, 1_100);

    assert!(matches!(
        store
            .clients()
            .set_status(&ClientId::new(), ClientStatus::Approved, 1_200)
            .await,
        Err(RepoError::NotFound)
    ));
}

pub async fn login_transaction_contract<S: Storage>(store: &S) {
    let transaction = LoginTransaction {
        state_hash: vec![0x40; 32],
        nonce: "nonce".to_string(),
        pkce_verifier: "verifier".to_string(),
        return_to: "/oauth/authorize?client_id=x".to_string(),
        provider: "test-idp".to_string(),
        created_at: 1_000,
        expires_at: 2_000,
        consumed_at: None,
    };
    store
        .login_transactions()
        .insert(&transaction)
        .await
        .expect("insert login transaction");
    let consumed = store
        .login_transactions()
        .consume(&transaction.state_hash, 1_001)
        .await
        .expect("consume login transaction");
    assert_eq!(consumed.consumed_at, Some(1_001));
    assert_eq!(consumed.nonce, "nonce");
    assert_eq!(consumed.pkce_verifier, "verifier");
    assert!(matches!(
        store
            .login_transactions()
            .consume(&transaction.state_hash, 1_002)
            .await,
        Err(RepoError::AlreadyConsumed)
    ));
    assert!(matches!(
        store.login_transactions().consume(&[0xff; 32], 1_002).await,
        Err(RepoError::NotFound)
    ));

    let expired = LoginTransaction {
        state_hash: vec![0x41; 32],
        nonce: "nonce".to_string(),
        pkce_verifier: "verifier".to_string(),
        return_to: "/".to_string(),
        provider: "test-idp".to_string(),
        created_at: 1_000,
        expires_at: 1_000,
        consumed_at: None,
    };
    store
        .login_transactions()
        .insert(&expired)
        .await
        .expect("insert expired login transaction");
    assert!(matches!(
        store
            .login_transactions()
            .consume(&expired.state_hash, 1_000)
            .await,
        Err(RepoError::Expired)
    ));

    let purged = store
        .login_transactions()
        .purge_expired(2_000)
        .await
        .expect("purge login transactions");
    assert!(purged >= 1);
}

/// The binding flow's state is one-shot and records who started it.
///
/// Both properties are load-bearing: a replayed state would let one callback
/// create two bindings, and a state that did not record its user would let
/// whoever holds it attach an upstream account to someone else's list.
pub async fn pending_binding_contract<S: Storage>(store: &S) {
    let owner = UserId::new();
    store
        .users()
        .create(&User {
            id: owner,
            display_name: "pending-binding-owner".to_string(),
            role: UserRole::User,
            created_at: 1_000,
            updated_at: 1_000,
        })
        .await
        .expect("insert user");

    let pending = PendingBinding {
        state_hash: vec![0x51; 32],
        user_id: owner,
        upstream_id: "phigros".to_string(),
        pkce_verifier: "verifier".to_string(),
        return_to: "/account".to_string(),
        created_at: 1_000,
        expires_at: 2_000,
        consumed_at: None,
    };
    store
        .pending_bindings()
        .insert(&pending)
        .await
        .expect("insert pending binding");

    let consumed = store
        .pending_bindings()
        .consume(&pending.state_hash, 1_001)
        .await
        .expect("consume pending binding");
    assert_eq!(consumed.consumed_at, Some(1_001));
    assert_eq!(
        consumed.user_id, owner,
        "the flow must report who started it, not who presented the state"
    );
    assert_eq!(consumed.upstream_id, "phigros");
    assert_eq!(consumed.pkce_verifier, "verifier");

    assert!(
        matches!(
            store
                .pending_bindings()
                .consume(&pending.state_hash, 1_002)
                .await,
            Err(RepoError::AlreadyConsumed)
        ),
        "a replayed state must not start a second binding"
    );
    assert!(matches!(
        store.pending_bindings().consume(&[0xff; 32], 1_002).await,
        Err(RepoError::NotFound)
    ));

    let expired = PendingBinding {
        state_hash: vec![0x52; 32],
        user_id: owner,
        upstream_id: "phigros".to_string(),
        pkce_verifier: String::new(),
        return_to: "/account".to_string(),
        created_at: 1_000,
        expires_at: 1_000,
        consumed_at: None,
    };
    store
        .pending_bindings()
        .insert(&expired)
        .await
        .expect("insert expired pending binding");
    assert!(matches!(
        store
            .pending_bindings()
            .consume(&expired.state_hash, 1_000)
            .await,
        Err(RepoError::Expired)
    ));

    let purged = store
        .pending_bindings()
        .purge_expired(2_000)
        .await
        .expect("purge pending bindings");
    assert!(purged >= 2, "both the consumed and the expired row go");
}

fn pending_authorization(
    user: UserId,
    session: SessionId,
    client: ClientId,
    expires: Unix,
) -> PendingAuthorization {
    PendingAuthorization {
        id: PendingAuthorizationId::new(),
        session_id: session,
        user_id: user,
        client_id: client,
        redirect_uri: "https://client.example/callback".to_string(),
        scopes: vec!["openid".to_string(), "phigros.stats.read".to_string()],
        state: Some("state-1".to_string()),
        code_challenge: "challenge".to_string(),
        code_challenge_method: "S256".to_string(),
        nonce: Some("nonce".to_string()),
        created_at: 1_000,
        expires_at: expires,
        consumed_at: None,
    }
}

pub async fn consent_contract<S: Storage>(store: &S) {
    let owner = user(1_000);
    let client = client(1_000);
    store.users().create(&owner).await.expect("owner");
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated, 1_000, "client"))
        .await
        .expect("client");
    assert!(
        store
            .consents()
            .find(&owner.id, &client.id)
            .await
            .expect("find")
            .is_none()
    );
    assert!(
        store
            .consents()
            .list_by_user(&owner.id)
            .await
            .expect("list")
            .is_empty()
    );

    let first = Consent {
        id: ConsentId::new(),
        user_id: owner.id,
        client_id: client.id,
        scopes: vec!["openid".to_string()],
        created_at: 1_000,
        updated_at: 1_000,
        revoked_at: None,
        version: ConsentVersion(0),
    };
    let granted = store
        .consents()
        .grant(&first, &fact(AuditAction::ConsentGranted, 1_000, "consent"))
        .await
        .expect("grant");
    assert_eq!(granted.version, ConsentVersion(1));
    assert_eq!(
        store
            .consents()
            .find(&owner.id, &client.id)
            .await
            .expect("find"),
        Some(granted.clone())
    );
    assert_eq!(
        store
            .consents()
            .list_by_user(&owner.id)
            .await
            .expect("list"),
        vec![granted.clone()]
    );

    let expanded = Consent {
        scopes: vec!["openid".to_string(), "phigros.stats.read".to_string()],
        updated_at: 1_100,
        ..granted.clone()
    };
    let regranted = store
        .consents()
        .grant(
            &expanded,
            &fact(AuditAction::ConsentGranted, 1_100, "consent"),
        )
        .await
        .expect("regrant");
    assert_eq!(regranted.version, ConsentVersion(2));
    assert_eq!(
        store
            .consents()
            .find(&owner.id, &client.id)
            .await
            .expect("find"),
        Some(regranted)
    );

    store
        .consents()
        .revoke(
            &owner.id,
            &client.id,
            &fact(AuditAction::ConsentRevoked, 1_200, "consent"),
            1_200,
        )
        .await
        .expect("revoke");
    assert!(
        store
            .consents()
            .find(&owner.id, &client.id)
            .await
            .expect("find")
            .is_none()
    );
    assert!(
        store
            .consents()
            .list_by_user(&owner.id)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(matches!(
        store
            .consents()
            .revoke(
                &owner.id,
                &client.id,
                &fact(AuditAction::ConsentRevoked, 1_300, "consent"),
                1_300
            )
            .await,
        Err(RepoError::NotFound)
    ));
}

pub async fn pending_authorization_contract<S: Storage>(store: &S) {
    let owner = user(1_000);
    let client = client(1_000);
    let owner_session = session(owner.id, 0x55, 1_000, 2_000, 3_000);
    store.users().create(&owner).await.expect("owner");
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated, 1_000, "client"))
        .await
        .expect("client");
    store
        .sessions()
        .create(&owner_session)
        .await
        .expect("session");

    let request = pending_authorization(owner.id, owner_session.id, client.id, 2_000);
    store
        .pending_authorizations()
        .insert(&request)
        .await
        .expect("insert");
    assert_eq!(
        store
            .pending_authorizations()
            .get(&request.id)
            .await
            .expect("get"),
        Some(request.clone())
    );
    assert!(matches!(
        store
            .pending_authorizations()
            .consume(&request.id, &SessionId::new(), 1_000)
            .await,
        Err(RepoError::NotFound)
    ));
    let consumed = store
        .pending_authorizations()
        .consume(&request.id, &owner_session.id, 1_000)
        .await
        .expect("consume");
    assert_eq!(consumed.consumed_at, Some(1_000));
    assert!(matches!(
        store
            .pending_authorizations()
            .consume(&request.id, &owner_session.id, 1_001)
            .await,
        Err(RepoError::AlreadyConsumed)
    ));

    let expired = pending_authorization(owner.id, owner_session.id, client.id, 1_000);
    store
        .pending_authorizations()
        .insert(&expired)
        .await
        .expect("expired insert");
    assert!(matches!(
        store
            .pending_authorizations()
            .consume(&expired.id, &owner_session.id, 1_000)
            .await,
        Err(RepoError::Expired)
    ));
    assert!(
        store
            .pending_authorizations()
            .purge_expired(2_000)
            .await
            .expect("purge")
            >= 1
    );

    let cascading = pending_authorization(owner.id, owner_session.id, client.id, 2_000);
    store
        .pending_authorizations()
        .insert(&cascading)
        .await
        .expect("cascading insert");
    store.users().delete(&owner.id).await.expect("delete user");
    assert!(
        store
            .pending_authorizations()
            .get(&cascading.id)
            .await
            .expect("get")
            .is_none()
    );
}

/// Revoked `jti` records (RFC 7009).
///
/// Only the time-dependent behaviour is asserted here: whether the row exists,
/// stops counting after expiry, and is purged. The atomicity of the write is
/// covered separately against SQLite, since this store has no transactions.
pub async fn access_token_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let user = user(now);
    store.users().create(&user).await.expect("create user");

    assert!(
        !store
            .access_tokens()
            .is_revoked("contract-jti", now)
            .await
            .expect("check unknown"),
        "an unrecorded jti must not be reported as revoked"
    );

    store
        .access_tokens()
        .revoke(
            "contract-jti",
            None,
            Some(user.id),
            2_000,
            &fact(AuditAction::AccessTokenRevoked, now, "jti:contract-jti"),
            now,
        )
        .await
        .expect("revoke");

    assert!(
        store
            .access_tokens()
            .is_revoked("contract-jti", 1_500)
            .await
            .expect("check live"),
        "a revoked jti must be reported while the token is still valid"
    );
    assert!(
        !store
            .access_tokens()
            .is_revoked("contract-jti", 2_001)
            .await
            .expect("check expired"),
        "after the token's own expiry the revocation is moot"
    );

    // Revoking again must not error; callers cannot tell "already revoked" from
    // "never existed" and would otherwise leak which tokens are real.
    store
        .access_tokens()
        .revoke(
            "contract-jti",
            None,
            Some(user.id),
            2_000,
            &fact(AuditAction::AccessTokenRevoked, now, "jti:contract-jti"),
            now + 10,
        )
        .await
        .expect("revoke twice");

    let purged = store
        .access_tokens()
        .purge_expired(3_000)
        .await
        .expect("purge");
    assert!(purged >= 1, "purge should remove expired revocations");
}

pub async fn audit_contract<S: Storage>(store: &S) {
    let now = 3_000;
    let user = user(now);
    store.users().create(&user).await.expect("create user");

    // A security fact, written through a repository that changes state.
    let link = binding(user.id, BindingId::new(), BindingStatus::Active, now);
    store
        .bindings()
        .upsert(&link, &fact(AuditAction::BindingCreated, now, "fact"))
        .await
        .expect("fact");

    // Telemetry, written through the lossy path.
    let telemetry = AuditRecord {
        id: AuditId::new(),
        occurred_at: now,
        actor_user_id: Some(user.id),
        client_id: None,
        action: AuditAction::AuthCodeIssued,
        target: "telemetry".to_string(),
        outcome: AuditOutcome::Success,
        severity: Severity::Info,
        request_id: None,
        detail: "{}".to_string(),
        tier: AuditTier::Telemetry,
    };
    store.audits().append(&telemetry).await.expect("append");

    // The telemetry purge must not take the security fact with it.
    let purged = store
        .audits()
        .purge_tier_before(AuditTier::Telemetry, now)
        .await
        .expect("purge telemetry");
    assert_eq!(purged, 1, "exactly the telemetry row");
    let remaining = store.audits().recent(100).await.expect("recent");
    assert!(
        remaining
            .iter()
            .all(|record| record.tier == AuditTier::Fact),
        "the security fact survives a telemetry purge"
    );

    // And the fact purge must not take telemetry with it.
    store
        .audits()
        .append(&telemetry)
        .await
        .expect("append again");
    let purged = store
        .audits()
        .purge_tier_before(AuditTier::Fact, now)
        .await
        .expect("purge facts");
    assert!(purged >= 1, "the fact is removed");
    let remaining = store.audits().recent(100).await.expect("recent");
    assert!(
        remaining
            .iter()
            .any(|record| record.tier == AuditTier::Telemetry),
        "telemetry survives a fact purge"
    );
}

/// Admin listings and filters (B1): cursor order, role change, secret rotation,
/// binding and audit filters. One paper per port would hide that they share the
/// admin surface; they are asserted together on purpose.
pub async fn admin_query_contract<S: Storage>(store: &S) {
    let now = 5_000;

    let first = user(now);
    let second = user(now + 1);
    store.users().create(&first).await.expect("create user");
    store.users().create(&second).await.expect("create user");

    // Newest first; the cursor pages strictly older.
    let page = store.users().list(None, 10).await.expect("list users");
    assert!(page.len() >= 2, "our two users are listed");
    assert_eq!(page[0].id, second.id, "newest first");
    assert_eq!(page[1].id, first.id);
    let cursor = page[0].id;
    let rest = store
        .users()
        .list(Some(&cursor), 10)
        .await
        .expect("second page");
    assert_eq!(rest[0].id, first.id, "a cursor never repeats a row");

    let admins_before = store.users().count_admins().await.expect("count");
    store
        .users()
        .set_role(
            &first.id,
            UserRole::Admin,
            &fact(AuditAction::UserRoleChanged, now + 2, "user"),
            now + 2,
        )
        .await
        .expect("set role");
    assert_eq!(
        store.users().count_admins().await.expect("count"),
        admins_before + 1
    );
    assert_eq!(
        store
            .users()
            .get(&first.id)
            .await
            .expect("get")
            .expect("user")
            .role,
        UserRole::Admin
    );
    assert!(matches!(
        store
            .users()
            .set_role(
                &UserId::new(),
                UserRole::Admin,
                &fact(AuditAction::UserRoleChanged, now, "user"),
                now
            )
            .await,
        Err(RepoError::NotFound)
    ));

    // Clients: list order, a partial edit, and secret rotation.
    let client = client(now);
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated, now, "client"))
        .await
        .expect("insert client");
    let clients = store.clients().list(None, 10).await.expect("list clients");
    assert_eq!(clients[0].id, client.id, "newest client first");
    let mut edited = client.clone();
    edited.name = "renamed".to_string();
    edited.raw_access = true;
    store
        .clients()
        .update(
            &edited,
            &fact(AuditAction::ClientUpdated, now + 3, "client"),
            now + 3,
        )
        .await
        .expect("update client");
    let fetched = store
        .clients()
        .get(&client.id)
        .await
        .expect("get")
        .expect("client");
    assert_eq!(fetched.name, "renamed");
    assert!(fetched.raw_access);
    assert_eq!(
        fetched.created_at, client.created_at,
        "an edit must not move created_at"
    );
    let hash = ClientSecretHash::new(1, vec![9; 32]).expect("hash");
    store
        .clients()
        .set_secret_hash(
            &client.id,
            Some(&hash),
            &fact(AuditAction::ClientSecretRotated, now + 4, "client"),
            now + 4,
        )
        .await
        .expect("rotate secret");
    assert!(
        store
            .clients()
            .get(&client.id)
            .await
            .expect("get")
            .expect("client")
            .secret_hash
            .is_some(),
        "a rotation installs a new hash"
    );

    // Bindings: the admin list is across users and filterable.
    let link = binding(first.id, BindingId::new(), BindingStatus::Active, now);
    store
        .bindings()
        .upsert(&link, &fact(AuditAction::BindingCreated, now, "binding"))
        .await
        .expect("binding");
    let other = binding(second.id, BindingId::new(), BindingStatus::Revoked, now + 1);
    store
        .bindings()
        .upsert(&other, &fact(AuditAction::BindingCreated, now, "binding"))
        .await
        .expect("binding");
    let all = store
        .bindings()
        .list_all(None, &BindingQuery::default(), 1000)
        .await
        .expect("list all");
    assert!(all.iter().any(|row| row.id == link.id));
    assert!(all.iter().any(|row| row.id == other.id));
    let by_user = store
        .bindings()
        .list_all(
            None,
            &BindingQuery {
                user: Some(first.id),
                ..Default::default()
            },
            10,
        )
        .await
        .expect("filter by user");
    assert_eq!(by_user.len(), 1);
    assert_eq!(by_user[0].id, link.id);
    let active = store
        .bindings()
        .list_all(
            None,
            &BindingQuery {
                status: Some(BindingStatus::Active),
                ..Default::default()
            },
            1000,
        )
        .await
        .expect("filter by status");
    assert!(active.iter().all(|row| row.status == BindingStatus::Active));
    assert!(active.iter().any(|row| row.id == link.id));

    // Audit: filters plus the descending cursor, and read-only by construction.
    let filter = AuditFilter {
        action: Some(AuditAction::BindingCreated),
        ..Default::default()
    };
    let rows = store
        .audits()
        .query(&filter, None, 10)
        .await
        .expect("audit query");
    assert!(rows.len() >= 2);
    assert!(
        rows.iter()
            .all(|row| row.action == AuditAction::BindingCreated)
    );
    let cursor = rows[0].id;
    let older = store
        .audits()
        .query(&filter, Some(&cursor), 10)
        .await
        .expect("audit page 2");
    assert!(older.iter().all(|row| row.id.0 < cursor.0));
}

pub async fn storage_contract_suite<S: Storage>(store: &S) {
    user_contract(store).await;
    session_contract(store).await;
    auth_code_contract(store).await;
    refresh_token_contract(store).await;
    revoke_all_for_client_contract(store).await;
    revoked_family_contract(store).await;
    login_transaction_contract(store).await;
    pending_binding_contract(store).await;
    approval_ticket_contract(store).await;
    consent_contract(store).await;
    pending_authorization_contract(store).await;
    device_code_contract(store).await;
    device_attempt_contract(store).await;
    binding_contract(store).await;
    client_contract(store).await;
    access_token_contract(store).await;
    connector_contract(store).await;
    audit_contract(store).await;
    admin_query_contract(store).await;
}
