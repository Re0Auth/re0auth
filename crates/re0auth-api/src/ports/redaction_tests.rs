//! INV-NOLOG-01, executable. Every struct that carries a hash, a nonce or a
//! one-time code must render `Debug` without those bytes. The marker is
//! asserted **and** the raw value is asserted absent: a formatter that
//! printed both would pass a marker-only check.

use super::*;

/// A value that is easy to recognise if it leaks into a `Debug` string.
const LEAK: &[u8] = b"leak-canary-do-not-print";

fn canary_bytes() -> Vec<u8> {
    LEAK.to_vec()
}

fn canary_string() -> String {
    String::from_utf8(LEAK.to_vec()).expect("ascii")
}

fn assert_redacted(rendered: &str, marker: &str) {
    assert!(
        rendered.contains("<redacted>"),
        "expected a redaction marker in {rendered}"
    );
    assert!(
        !rendered.contains(marker),
        "the secret value leaked into Debug output: {rendered}"
    );
    assert!(
        !rendered.contains("leak-canary"),
        "a canary byte sequence leaked into Debug output: {rendered}"
    );
    // `Vec<u8>` renders as `[108, 101, ...]`, so a string-only check would
    // miss the most likely leak. The first three canary bytes are enough.
    let byte_list = format!("{:?}", &LEAK[..3]);
    assert!(
        !rendered.contains(&byte_list),
        "a raw byte array leaked into Debug output: {rendered}"
    );
}

#[test]
fn session_hides_its_hashes() {
    let session = Session {
        id: SessionId::new(),
        id_hash: canary_bytes(),
        user_id: UserId::new(),
        csrf_hash: canary_bytes(),
        created_at: 1,
        last_seen_at: 2,
        idle_expires_at: 3,
        absolute_expires_at: 4,
        revoked_at: None,
    };
    let rendered = format!("{session:?}");
    assert_redacted(&rendered, &canary_string());
    assert!(rendered.contains(&session.user_id.0.to_string()));
}

#[test]
fn auth_code_hides_its_hash_and_nonce() {
    let code = AuthCode {
        id: AuthCodeId::new(),
        code_hash: canary_bytes(),
        client_id: ClientId::new(),
        user_id: UserId::new(),
        redirect_uri: "https://client.example/cb".to_string(),
        scopes: vec!["openid".to_string()],
        code_challenge: Some("challenge".to_string()),
        code_challenge_method: Some("S256".to_string()),
        nonce: Some(canary_string()),
        auth_time: 1,
        created_at: 1,
        expires_at: 2,
        consumed_at: None,
        family_id: None,
    };
    let rendered = format!("{code:?}");
    assert_redacted(&rendered, &canary_string());
    // The presence bit survives, which is what an operator needs.
    assert!(rendered.contains("Some(\"<redacted>\")"), "{rendered}");
}

#[test]
fn a_device_row_without_an_approver_is_rejected() {
    let approver = UserId::new();
    // The two statuses that require an approver refuse to be rebuilt
    // without one. This used to be a state the adapters had to defend
    // against at every poll; now it cannot be constructed at all.
    for status in [DeviceCodeStatus::Approved, DeviceCodeStatus::Consumed] {
        assert!(
            DeviceCodeState::from_columns(status, None).is_err(),
            "{status:?} without an approver must not be representable"
        );
        assert!(DeviceCodeState::from_columns(status, Some(approver)).is_ok());
    }
    // Pending, expired and denied are legitimate without an approver.
    for status in [
        DeviceCodeStatus::Pending,
        DeviceCodeStatus::Expired,
        DeviceCodeStatus::Denied,
    ] {
        assert!(
            DeviceCodeState::from_columns(status, None).is_ok(),
            "{status:?} must be reconstructible without an approver"
        );
    }
}

#[test]
fn device_code_hides_both_hashes() {
    let code = DeviceCode {
        id: DeviceCodeId::new(),
        device_code_hash: canary_bytes(),
        user_code_hash: canary_bytes(),
        client_id: ClientId::new(),
        scopes: vec!["openid".to_string()],
        state: DeviceCodeState::Pending,
        interval_secs: 5,
        last_polled_at: None,
        poll_count: 0,
        user_code_misses: 0,
        created_at: 1,
        expires_at: 2,
        consumed_at: None,
        family_id: None,
    };
    assert_redacted(&format!("{code:?}"), &canary_string());
}

#[test]
fn login_transaction_hides_nonce_and_verifier() {
    let transaction = LoginTransaction {
        state_hash: canary_bytes(),
        nonce: canary_string(),
        pkce_verifier: canary_string(),
        return_to: "/app".to_string(),
        provider: "test-idp".to_string(),
        purpose: crate::login::LoginPurpose::Login,
        initiator: None,
        created_at: 1,
        expires_at: 2,
        consumed_at: None,
    };
    assert_redacted(&format!("{transaction:?}"), &canary_string());
}

#[test]
fn refresh_token_hides_its_hash() {
    let token = RefreshToken {
        id: RefreshTokenId::new(),
        token_hash: canary_bytes(),
        family_id: FamilyId::new(),
        client_id: ClientId::new(),
        user_id: UserId::new(),
        scopes: vec!["openid".to_string()],
        created_at: 1,
        family_created_at: 1,
        auth_time: 1,
        expires_at: 2,
        consumed_at: None,
        revoked_at: None,
        replaced_by: None,
    };
    assert_redacted(&format!("{token:?}"), &canary_string());

    let rotation = RotateRefreshToken {
        old_hash: LEAK,
        new: token,
    };
    assert_redacted(&format!("{rotation:?}"), &canary_string());
}

#[test]
fn pending_authorization_hides_state_and_nonce() {
    let pending = PendingAuthorization {
        id: PendingAuthorizationId::new(),
        session_id: SessionId::new(),
        user_id: UserId::new(),
        client_id: ClientId::new(),
        redirect_uri: "https://client.example/cb".to_string(),
        scopes: vec!["openid".to_string()],
        state: Some(canary_string()),
        code_challenge: "challenge".to_string(),
        code_challenge_method: "S256".to_string(),
        nonce: Some(canary_string()),
        auth_time: 1,
        created_at: 1,
        expires_at: 2,
        consumed_at: None,
    };
    assert_redacted(&format!("{pending:?}"), &canary_string());
}

#[test]
fn approval_ticket_hides_jti_and_user_code() {
    let ticket = ApprovalTicket {
        jti: canary_string(),
        user_id: UserId::new(),
        user_code: canary_string(),
        expires_at: 2,
        consumed_at: None,
    };
    assert_redacted(&format!("{ticket:?}"), &canary_string());
}

#[test]
fn consume_auth_code_hides_its_hash() {
    let request = ConsumeAuthCode {
        code_hash: LEAK,
        client_id: ClientId::new(),
        redirect_uri: "https://client.example/cb",
        code_challenge: Some("challenge"),
        code_challenge_method: Some("S256"),
        family_id: FamilyId::new(),
    };
    assert_redacted(&format!("{request:?}"), &canary_string());
}
