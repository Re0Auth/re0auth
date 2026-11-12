//! Authorization-code contract: read-only inspection, atomic consumption, and
//! the refresh token that consumption must write in the same step.

use super::{auth_code, fact, refresh, user};
use re0auth_api::ClientId;
use re0auth_api::FamilyId;
use re0auth_api::audit::AuditAction;
use re0auth_api::ports::{ConsumeAuthCode, RepoError, Storage};

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

    let family = FamilyId::new();
    let attempt = ConsumeAuthCode {
        code_hash: &code.code_hash,
        client_id: client,
        redirect_uri: &code.redirect_uri,
        code_challenge: code.code_challenge.as_deref(),
        code_challenge_method: code.code_challenge_method.as_deref(),
        family_id: family,
    };
    let inspected = store
        .auth_codes()
        .inspect(&attempt, now)
        .await
        .expect("inspect code");
    assert_eq!(inspected.user_id, user.id);
    assert_eq!(inspected.client_id, client);
    assert_eq!(inspected.scopes, code.scopes);
    assert_eq!(inspected.nonce, code.nonce);
    assert_eq!(inspected.auth_time, code.auth_time);
    // `inspect` is read-only: repeating it returns the same grant and writes no
    // family marker.
    assert_eq!(
        store
            .auth_codes()
            .inspect(&attempt, now)
            .await
            .expect("inspect is repeatable"),
        inspected
    );
    assert_eq!(
        store
            .auth_codes()
            .family_and_client_of(&code.code_hash)
            .await
            .expect("family before consumption"),
        None
    );

    let token = refresh(user.id, client, family, 25, 10_000);
    let grant = store
        .auth_codes()
        .consume_and_insert_refresh(attempt, &token, now)
        .await
        .expect("consume code");
    assert_eq!(grant, inspected);
    assert_eq!(
        store
            .refresh_tokens()
            .find(&token.token_hash)
            .await
            .expect("find refresh token"),
        Some(token.clone())
    );
    assert_eq!(
        store
            .auth_codes()
            .family_and_client_of(&code.code_hash)
            .await
            .expect("family after consumption"),
        Some((family, client))
    );

    let replay = ConsumeAuthCode {
        code_hash: &code.code_hash,
        client_id: client,
        redirect_uri: &code.redirect_uri,
        code_challenge: code.code_challenge.as_deref(),
        code_challenge_method: code.code_challenge_method.as_deref(),
        family_id: FamilyId::new(),
    };
    assert!(matches!(
        store.auth_codes().inspect(&replay, now).await,
        Err(RepoError::AlreadyConsumed)
    ));
    let replay_token = refresh(user.id, client, FamilyId::new(), 26, 10_000);
    assert!(matches!(
        store
            .auth_codes()
            .consume_and_insert_refresh(replay, &replay_token, now)
            .await,
        Err(RepoError::AlreadyConsumed)
    ));
    assert_eq!(
        store
            .refresh_tokens()
            .find(&replay_token.token_hash)
            .await
            .expect("no refresh from a replay"),
        None
    );

    let expired = auth_code(user.id, client, 21, 1_000);
    store
        .auth_codes()
        .insert(&expired, &fact(AuditAction::AuthCodeIssued, now, "code"))
        .await
        .expect("expired code");
    let expired_attempt = ConsumeAuthCode {
        code_hash: &expired.code_hash,
        client_id: client,
        redirect_uri: &expired.redirect_uri,
        code_challenge: expired.code_challenge.as_deref(),
        code_challenge_method: expired.code_challenge_method.as_deref(),
        family_id: FamilyId::new(),
    };
    assert!(matches!(
        store.auth_codes().inspect(&expired_attempt, 1_000).await,
        Err(RepoError::Expired)
    ));
    let expired_token = refresh(user.id, client, FamilyId::new(), 27, 10_000);
    assert!(matches!(
        store
            .auth_codes()
            .consume_and_insert_refresh(expired_attempt, &expired_token, 1_000)
            .await,
        Err(RepoError::Expired)
    ));
    assert_eq!(
        store
            .refresh_tokens()
            .find(&expired_token.token_hash)
            .await
            .expect("no refresh from an expired code"),
        None
    );

    let mismatch = auth_code(user.id, client, 22, 2_000);
    store
        .auth_codes()
        .insert(&mismatch, &fact(AuditAction::AuthCodeIssued, now, "code"))
        .await
        .expect("mismatch code");
    let wrong_client = ConsumeAuthCode {
        code_hash: &mismatch.code_hash,
        client_id: ClientId::new(),
        redirect_uri: &mismatch.redirect_uri,
        code_challenge: mismatch.code_challenge.as_deref(),
        code_challenge_method: mismatch.code_challenge_method.as_deref(),
        family_id: FamilyId::new(),
    };
    assert!(matches!(
        store.auth_codes().inspect(&wrong_client, now).await,
        Err(RepoError::NotFound)
    ));
    let wrong_redirect = ConsumeAuthCode {
        code_hash: &mismatch.code_hash,
        client_id: client,
        redirect_uri: "https://client.example/other",
        code_challenge: mismatch.code_challenge.as_deref(),
        code_challenge_method: mismatch.code_challenge_method.as_deref(),
        family_id: FamilyId::new(),
    };
    assert!(matches!(
        store.auth_codes().inspect(&wrong_redirect, now).await,
        Err(RepoError::NotFound)
    ));
    let wrong_challenge = ConsumeAuthCode {
        code_hash: &mismatch.code_hash,
        client_id: client,
        redirect_uri: &mismatch.redirect_uri,
        code_challenge: Some("wrong-challenge"),
        code_challenge_method: Some("S256"),
        family_id: FamilyId::new(),
    };
    assert!(matches!(
        store.auth_codes().inspect(&wrong_challenge, now).await,
        Err(RepoError::NotFound)
    ));
    let mismatch_token = refresh(user.id, client, FamilyId::new(), 28, 10_000);
    assert!(matches!(
        store
            .auth_codes()
            .consume_and_insert_refresh(wrong_challenge, &mismatch_token, now)
            .await,
        Err(RepoError::NotFound)
    ));
    // None of those refusals consumed it: the binding-matching request still wins.
    store
        .auth_codes()
        .consume_and_insert_refresh(
            ConsumeAuthCode {
                code_hash: &mismatch.code_hash,
                client_id: client,
                redirect_uri: &mismatch.redirect_uri,
                code_challenge: mismatch.code_challenge.as_deref(),
                code_challenge_method: mismatch.code_challenge_method.as_deref(),
                family_id: FamilyId::new(),
            },
            &refresh(user.id, client, FamilyId::new(), 29, 10_000),
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
