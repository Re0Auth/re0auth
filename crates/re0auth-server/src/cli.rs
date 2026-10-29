//! Admin CLI commands. They are deliberately shell-only.

use anyhow::{Context, bail};
use clap::{Args, Subcommand};
use uuid::Uuid;

use re0auth_adapters::clock::SystemClock;
use re0auth_adapters::random::OsRandom;
use re0auth_adapters::storage::SqliteStore;
use re0auth_api::ports::{ClientStatus, Storage, UserRole};
use re0auth_api::{ClientId, Clock, UserId};
use re0auth_app::admin;
use re0auth_app::admin_service::AdminService;

use crate::config::Config;

#[derive(Debug, Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Create a user and print its id.
    #[command(name = "create-user")]
    User {
        #[arg(long)]
        display_name: String,
        #[arg(long, default_value = "user")]
        role: String,
    },
    /// Create a client and print its id. With `--confidential` the secret is
    /// printed once and never stored; losing it means creating a new client.
    #[command(name = "create-client")]
    Client {
        #[arg(long)]
        name: String,
        #[arg(long = "redirect-uri", required = true)]
        redirect_uris: Vec<String>,
        #[arg(long = "scope")]
        allowed_scopes: Vec<String>,
        #[arg(long)]
        raw_access: bool,
        #[arg(long, default_value = "approved")]
        status: String,
        /// Issue a client secret (ADR-0030). Without it the client is public.
        #[arg(long)]
        confidential: bool,
    },
    /// Create a session and print the raw cookie value once.
    #[command(name = "create-session")]
    Session {
        #[arg(long)]
        user_id: Uuid,
    },
    /// Approve a pending device code.
    #[command(name = "approve-device")]
    ApproveDevice {
        #[arg(long)]
        user_code: String,
        #[arg(long)]
        user_id: Uuid,
    },
    /// Deny a pending device code.
    #[command(name = "deny-device")]
    DenyDevice {
        #[arg(long)]
        user_code: String,
    },
    /// Rotate a client's secret and print the new one exactly once.
    ///
    /// Same use case as `POST /api/admin/clients/{id}/rotate-secret`, so the
    /// audit fact and the cache invalidation are not duplicated.
    #[command(name = "rotate-client-secret")]
    RotateClientSecret {
        #[arg(long)]
        client_id: Uuid,
        /// User id recorded as the actor of the audit fact.
        #[arg(long)]
        actor: Uuid,
    },
    /// Change an existing user's role.
    ///
    /// `create-user --role` only applies at creation. The same guards as the
    /// HTTP endpoint apply: no self-demotion, never the last admin.
    #[command(name = "set-role")]
    SetRole {
        #[arg(long)]
        user_id: Uuid,
        #[arg(long)]
        role: String,
        /// User id recorded as the actor of the audit fact.
        #[arg(long)]
        actor: Uuid,
    },
    /// Revoke one access token by its `jti`, for incident response.
    ///
    /// Takes the `jti` (from the audit log or the database) rather than the
    /// bearer token, because that is what an operator has.
    #[command(name = "revoke-token")]
    RevokeToken {
        #[arg(long)]
        jti: String,
        #[arg(long)]
        client_id: Uuid,
        /// The token's `exp`, in unix seconds.
        #[arg(long)]
        expires_at: i64,
        /// User id recorded as the actor of the audit fact.
        #[arg(long)]
        actor: Uuid,
    },
    /// Mint a new token-signing key and make it active.
    ///
    /// The previous key is demoted but stays published, so tokens it already
    /// signed keep verifying until they expire (OPERATIONS.md §5.2). Restart the
    /// server to start signing with the new key.
    #[command(name = "rotate-signing-key")]
    RotateSigningKey,
    /// Re-wrap every stored credential onto the current master key.
    ///
    /// Sub-credential envelopes are re-wrapped without touching their payload
    /// ciphertext; connector-vault entries are decrypted and re-encrypted under
    /// the current key. Client-secret hashes keep the version that produced them,
    /// so keep retired keys until those secrets are rotated. Anything wrapped
    /// under an undeclared key fails rather than being skipped.
    ///
    /// Exits non-zero when anything failed or when there was nothing to rotate:
    /// an empty result looks identical to a finished one, and dropping the old
    /// key on that reading makes the next credential unreadable.
    #[command(name = "rotate-credentials")]
    RotateCredentials,
}

pub async fn run(cfg: &Config, command: AdminCommand) -> anyhow::Result<()> {
    let store = SqliteStore::connect(&cfg.database.url).await?;
    let clock = SystemClock;
    let random = OsRandom;

    match command {
        AdminCommand::User { display_name, role } => {
            let role = parse_role(&role)?;
            let id = admin::create_user(&store, &clock, &display_name, role)
                .await
                .context("create user")?;
            println!("user_id={}", id.0);
        }
        AdminCommand::Client {
            name,
            redirect_uris,
            allowed_scopes,
            raw_access,
            status,
            confidential,
        } => {
            let status = parse_client_status(&status)?;
            let scopes = if allowed_scopes.is_empty() {
                vec!["openid".to_string(), "profile".to_string()]
            } else {
                allowed_scopes
            };
            for uri in &redirect_uris {
                re0auth_api::redirect_uri::validate(uri)
                    .map_err(|error| anyhow::anyhow!("{error}"))?;
            }
            let hasher = crate::client_secret_hasher(cfg)?;
            let created = admin::create_client(
                &store,
                &clock,
                &random,
                &hasher,
                None,
                None,
                admin::NewClient {
                    name: &name,
                    redirect_uris,
                    allowed_scopes: scopes,
                    raw_access,
                    status,
                    confidential,
                },
            )
            .await
            .context("create client")?;
            println!("client_id={}", created.id.0);
            match created.secret {
                Some(secret) => {
                    println!("client_secret={secret}");
                    println!("client_secret_is_shown_once=true");
                }
                None => println!("client_type=public"),
            }
        }
        AdminCommand::Session { user_id } => {
            let created = admin::create_session(&store, &clock, &random, UserId(user_id))
                .await
                .context("create session")?;
            println!("session_cookie=re0auth_session={}", created.cookie);
            println!("csrf_token={}", created.csrf_token);
            println!("idle_expires_at={}", created.session.idle_expires_at);
            println!(
                "absolute_expires_at={}",
                created.session.absolute_expires_at
            );
        }
        AdminCommand::ApproveDevice { user_code, user_id } => {
            admin::approve_device(&store, &clock, &user_code, UserId(user_id))
                .await
                .context("approve device code")?;
            println!("device_code_approved={user_code}");
        }
        AdminCommand::DenyDevice { user_code } => {
            admin::deny_device(&store, &clock, &user_code)
                .await
                .context("deny device code")?;
            println!("device_code_denied={user_code}");
        }
        AdminCommand::RotateClientSecret { client_id, actor } => {
            let rotated = admin_service(cfg, &store)?
                .rotate_client_secret(UserId(actor), &ClientId(client_id), None)
                .await
                .context("rotate client secret")?;
            println!("client_id={}", rotated.id);
            println!("client_secret={}", rotated.secret);
            println!("client_secret_is_shown_once=true");
        }
        AdminCommand::SetRole {
            user_id,
            role,
            actor,
        } => {
            let role = parse_role(&role)?;
            let updated = admin_service(cfg, &store)?
                .set_user_role(UserId(actor), UserId(user_id), role, None)
                .await
                .context("set user role")?;
            println!("user_id={}", updated.id);
            println!("role={}", updated.role);
        }
        AdminCommand::RevokeToken {
            jti,
            client_id,
            expires_at,
            actor,
        } => {
            admin_service(cfg, &store)?
                .revoke_access_token(
                    UserId(actor),
                    &jti,
                    Some(ClientId(client_id)),
                    expires_at,
                    None,
                )
                .await
                .context("revoke access token")?;
            println!("revoked_jti={jti}");
            // ADR-0029: the running server keeps revocations in memory and only
            // reads the table at startup, so this write is not visible to it yet.
            println!("restart_required=true");
        }
        AdminCommand::RotateSigningKey => {
            let known = store.signing_keys().published().await?;
            let signer = re0auth_adapters::crypto::RsaTokenSigner::load_or_generate(
                std::path::Path::new(&cfg.crypto.signing_key_file),
                &cfg.server.issuer,
                clock.now(),
                &known,
            )?;
            let previous = signer.primary_record().map(|record| record.kid);
            let record = signer.rotate(clock.now())?;
            store.signing_keys().publish(&record).await?;
            // `publish` never writes `retired_at` (it must not resurrect a key an
            // operator retired), so the demotion needs its own idempotent call.
            // Without it the database would still call the old key active and the
            // next restart would sign with it again.
            if let Some(kid) = previous {
                store.signing_keys().retire(&kid, clock.now()).await?;
                println!("demoted_kid={kid}");
            }
            println!("active_kid={}", record.kid);
            println!("restart_required=true");
        }
        AdminCommand::RotateCredentials => {
            let sealer = crate::open_sealer(cfg)?;
            let report = re0auth_app::rotation::rotate_credentials(&store, &sealer, clock.now())
                .await
                .context("rotate credentials")?;
            println!("{}", report.summary());
            if let Some(vault) = crate::connector_vault(cfg, std::sync::Arc::new(OsRandom))? {
                let moved = vault
                    .rewrap_all()
                    .await
                    .context("rewrap connector secrets")?;
                println!("connector_secrets_rewrapped={moved}");
            }
            if !report.is_clean() {
                bail!(
                    "rotation is not clean; keep the retired key configured and re-run once the cause is fixed"
                );
            }
            let stale = stale_client_secret_hashes(&store, cfg.crypto.master_key_version).await?;
            if stale == 0 {
                println!("retired_keys_may_be_dropped=true");
            } else {
                println!("client_secret_hashes_on_retired_keys={stale}");
                println!("retired_keys_may_be_dropped=false");
            }
        }
    }

    Ok(())
}

/// Client-secret hashes cannot be re-hashed without the plaintext, so a retired
/// pepper has to stay until each confidential client rotates its secret.
async fn stale_client_secret_hashes(store: &SqliteStore, current: u32) -> anyhow::Result<u64> {
    let mut before = None;
    let mut count = 0;
    loop {
        let page = store.clients().list(before.as_ref(), 128).await?;
        if page.is_empty() {
            break;
        }
        for client in &page {
            if client
                .secret_hash
                .as_ref()
                .is_some_and(|hash| hash.key_version() != current)
            {
                count += 1;
            }
        }
        before = page.last().map(|client| client.id);
    }
    Ok(count)
}

/// The admin use cases, wired the same way the HTTP layer wires them.
///
/// No cache: the CLI is an offline tool, so there is nothing to invalidate. The
/// consequence is documented at the call site — a running server does not see
/// these writes until it restarts.
fn admin_service(cfg: &Config, store: &SqliteStore) -> anyhow::Result<AdminService> {
    Ok(AdminService::new(
        std::sync::Arc::new(store.clone()),
        std::sync::Arc::new(SystemClock),
        std::sync::Arc::new(OsRandom),
        std::sync::Arc::new(crate::client_secret_hasher(cfg)?),
    ))
}

fn parse_role(raw: &str) -> anyhow::Result<UserRole> {
    match raw {
        "user" => Ok(UserRole::User),
        "admin" => Ok(UserRole::Admin),
        other => bail!("unknown role {other:?}; expected user or admin"),
    }
}

fn parse_client_status(raw: &str) -> anyhow::Result<ClientStatus> {
    match raw {
        "pending" => Ok(ClientStatus::Pending),
        "approved" => Ok(ClientStatus::Approved),
        "suspended" => Ok(ClientStatus::Suspended),
        "revoked" => Ok(ClientStatus::Revoked),
        other => {
            bail!("unknown client status {other:?}; expected pending, approved, suspended, revoked")
        }
    }
}
