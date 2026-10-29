#![forbid(unsafe_code)]

//! Contract layer: IDs, time, error types, and ports.
//!
//! This crate must not depend on tokio, axum, sqlx, or reqwest (HR-01..HR-06).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod audit;
pub mod cache;
pub mod connector;
pub mod idp;
pub mod oauth;
pub mod ports;
pub mod rate;
pub mod redirect_uri;
pub mod schedule;
pub mod secret;

pub use secrecy::SecretString;

/// Seconds since the Unix epoch.
pub type Unix = i64;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// INV-PK-01: business primary keys are UUID v7 (time-ordered).
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

id_type!(UserId);
id_type!(ClientId);
id_type!(BindingId);
id_type!(SessionId);
id_type!(FamilyId);
id_type!(IdentityId);
id_type!(AuthCodeId);
id_type!(RefreshTokenId);
id_type!(DeviceCodeId);
id_type!(ConsentId);
id_type!(PendingAuthorizationId);
id_type!(ConnectorId);
id_type!(AuditId);

/// Signing key identifier. Kept as a string because it is published in JWKS.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(pub String);

#[derive(Debug, thiserror::Error)]
pub enum Re0Error {
    #[error("business error: {0}")]
    Business(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Re0Result<T> = Result<T, Re0Error>;

/// The only time source. Implementations live in adapters; domain takes `Unix`.
pub trait Clock: Send + Sync {
    fn now(&self) -> Unix;
}

/// The only randomness source for tokens and secrets.
pub trait Random: Send + Sync {
    fn bytes(&self, len: usize) -> Vec<u8>;
}
