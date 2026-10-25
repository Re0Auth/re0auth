//! Approval-ticket contract: single use, atomic decision, and audit attribution.

use re0auth_api::audit::AuditAction;
use re0auth_api::ports::{ApprovalDecision, ApprovalTicket, DeviceCodeState, RepoError, Storage};

use super::{client, device_code, device_fact, fact, user};
pub async fn approval_ticket_contract<S: Storage>(store: &S) {
    let now = 1_000;
    let other = user(now);
    let user = user(now);
    let client = client(now);
    store.users().create(&user).await.expect("create user");
    store
        .users()
        .create(&other)
        .await
        .expect("create other user");
    store
        .clients()
        .insert(&client, &fact(AuditAction::ClientCreated, now, "client"))
        .await
        .expect("create client");

    let approved = device_code(0x50, client.id, 2_000);
    store
        .device_codes()
        .insert(&approved)
        .await
        .expect("insert approved device");
    let ticket = ApprovalTicket {
        jti: "ticket-approve".to_string(),
        user_id: user.id,
        user_code: "ABCD-EFGH".to_string(),
        expires_at: 2_000,
        consumed_at: None,
    };
    store
        .approval_tickets()
        .insert(&ticket)
        .await
        .expect("insert approval ticket");
    assert_eq!(
        store
            .approval_tickets()
            .find(&ticket.jti)
            .await
            .expect("find ticket"),
        Some(ticket.clone())
    );
    store
        .approval_tickets()
        .consume_and_decide(
            &ticket.jti,
            user.id,
            &approved.user_code_hash,
            ApprovalDecision::Approve,
            &device_fact(AuditAction::DeviceApproved, now, user.id),
            now,
        )
        .await
        .expect("approve");
    assert!(matches!(
        store
            .device_codes()
            .find_by_user_code_hash(&approved.user_code_hash)
            .await
            .expect("find approved device")
            .expect("approved device")
            .state,
        DeviceCodeState::Approved { approver } if approver == user.id
    ));
    assert!(matches!(
        store
            .approval_tickets()
            .consume_and_decide(
                &ticket.jti,
                user.id,
                &approved.user_code_hash,
                ApprovalDecision::Approve,
                &device_fact(AuditAction::DeviceApproved, now, user.id),
                now,
            )
            .await,
        Err(RepoError::AlreadyConsumed)
    ));

    let denied = device_code(0x51, client.id, 2_000);
    store
        .device_codes()
        .insert(&denied)
        .await
        .expect("insert denied device");
    let deny_ticket = ApprovalTicket {
        jti: "ticket-deny".to_string(),
        user_id: user.id,
        user_code: "IJKL-MNOP".to_string(),
        expires_at: 2_000,
        consumed_at: None,
    };
    store
        .approval_tickets()
        .insert(&deny_ticket)
        .await
        .expect("insert deny ticket");
    store
        .approval_tickets()
        .consume_and_decide(
            &deny_ticket.jti,
            user.id,
            &denied.user_code_hash,
            ApprovalDecision::Deny,
            &device_fact(AuditAction::DeviceDenied, now, user.id),
            now,
        )
        .await
        .expect("deny");
    assert!(matches!(
        store
            .device_codes()
            .find_by_user_code_hash(&denied.user_code_hash)
            .await
            .expect("find denied device")
            .expect("denied device")
            .state,
        DeviceCodeState::Denied {
            approver: Some(approver)
        } if approver == user.id
    ));

    // INV-AUDIT-01 + INV-DEVICE-03: the decision is attributed to the client
    // named on the device code, not to whatever the caller passed in.
    let device_audit = store
        .audits()
        .recent(100)
        .await
        .expect("audit rows")
        .into_iter()
        .find(|record| record.action == AuditAction::DeviceDenied)
        .expect("the denial must be audited");
    assert_eq!(
        device_audit.client_id,
        Some(client.id),
        "the store must fill client_id from the device code"
    );
    assert_eq!(device_audit.actor_user_id, Some(user.id));

    let wrong_user_device = device_code(0x52, client.id, 2_000);
    store
        .device_codes()
        .insert(&wrong_user_device)
        .await
        .expect("insert wrong-user device");
    let wrong_user_ticket = ApprovalTicket {
        jti: "ticket-wrong-user".to_string(),
        user_id: user.id,
        user_code: "QRST-UVWX".to_string(),
        expires_at: 2_000,
        consumed_at: None,
    };
    store
        .approval_tickets()
        .insert(&wrong_user_ticket)
        .await
        .expect("insert wrong-user ticket");
    assert!(matches!(
        store
            .approval_tickets()
            .consume_and_decide(
                &wrong_user_ticket.jti,
                other.id,
                &wrong_user_device.user_code_hash,
                ApprovalDecision::Approve,
                &device_fact(AuditAction::DeviceApproved, now, user.id),
                now,
            )
            .await,
        Err(RepoError::NotFound)
    ));
    assert_eq!(
        store
            .device_codes()
            .find_by_user_code_hash(&wrong_user_device.user_code_hash)
            .await
            .expect("find wrong-user device")
            .expect("wrong-user device")
            .state,
        DeviceCodeState::Pending
    );

    let expired_ticket = ApprovalTicket {
        jti: "ticket-expired".to_string(),
        user_id: user.id,
        user_code: "YZ23-4567".to_string(),
        expires_at: now,
        consumed_at: None,
    };
    store
        .approval_tickets()
        .insert(&expired_ticket)
        .await
        .expect("insert expired ticket");
    assert!(matches!(
        store
            .approval_tickets()
            .consume_and_decide(
                &expired_ticket.jti,
                user.id,
                &wrong_user_device.user_code_hash,
                ApprovalDecision::Approve,
                &device_fact(AuditAction::DeviceApproved, now, user.id),
                now,
            )
            .await,
        Err(RepoError::Expired)
    ));

    let stale_device = device_code(0x53, client.id, now);
    store
        .device_codes()
        .insert(&stale_device)
        .await
        .expect("insert stale device");
    let stale_ticket = ApprovalTicket {
        jti: "ticket-stale-device".to_string(),
        user_id: user.id,
        user_code: "2345-6789".to_string(),
        expires_at: 2_000,
        consumed_at: None,
    };
    store
        .approval_tickets()
        .insert(&stale_ticket)
        .await
        .expect("insert stale ticket");
    assert!(matches!(
        store
            .approval_tickets()
            .consume_and_decide(
                &stale_ticket.jti,
                user.id,
                &stale_device.user_code_hash,
                ApprovalDecision::Approve,
                &device_fact(AuditAction::DeviceApproved, now + 1, user.id),
                now + 1,
            )
            .await,
        Err(RepoError::Expired)
    ));
    assert!(
        store
            .approval_tickets()
            .find(&stale_ticket.jti)
            .await
            .expect("find stale ticket")
            .expect("stale ticket")
            .consumed_at
            .is_none(),
        "a failed device decision must roll back ticket consumption"
    );

    store.users().delete(&user.id).await.expect("delete user");
    assert!(
        store
            .approval_tickets()
            .find(&ticket.jti)
            .await
            .expect("find after cascade")
            .is_none()
    );
}
