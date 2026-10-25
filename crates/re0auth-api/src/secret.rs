//! Sealed sub-credentials.
//!
//! The core stores only ciphertext. Sealing is a port so the storage adapter
//! never needs a key and the gateway never sees the encryption backend.

use crate::{BindingId, Re0Error, Re0Result, SecretString};

/// AES-GCM nonce length. Every sealed value uses it, so the constructor can
/// reject a malformed one instead of letting it fail later at decrypt time.
pub const SEALED_NONCE_LEN: usize = 12;

/// AES-256 key length for both the KEK and a DEK.
pub const SEALED_KEY_LEN: usize = 32;

/// A credential sealed under a per-record data key, with that key wrapped by the
/// configured master key.
///
/// ## Why two layers
///
/// The payload is encrypted under a DEK that exists only for this record. The DEK
/// is then wrapped by the master key (the KEK) and stored beside the ciphertext.
/// Rotating the master key re-wraps the DEK and leaves the payload untouched —
/// no plaintext is produced and no ciphertext is rewritten, so rotation is cheap
/// and safe to re-run.
///
/// The second reason is destruction: revoking a credential drops its `wrapped_dek`.
/// Ciphertext that survives in a backup is then undecryptable, because the key
/// that opens it no longer exists anywhere. A delete alone cannot promise that.
///
/// INV-NOLOG-01: neither ciphertext, wrapped DEK nor nonces reach a log line.
///
/// Fields are private so the only way to obtain a value is through
/// [`SealedSecret::new`], which enforces every length. A struct literal would
/// have allowed a 3-byte nonce or an empty ciphertext to travel all the way to
/// the adapter before anything noticed.
#[derive(Clone, Eq, PartialEq)]
pub struct SealedSecret {
    /// Which KEK wrapped the DEK. This is the *master key* version, not a DEK id.
    key_version: u32,
    /// Nonce for the KEK's wrapping of the DEK.
    dek_nonce: Vec<u8>,
    /// The DEK, encrypted under the KEK.
    wrapped_dek: Vec<u8>,
    /// Nonce for the payload encryption under the DEK.
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl SealedSecret {
    /// Rejects any nonce of the wrong length and a wrapped DEK that is not a
    /// sealed 32-byte key. An empty ciphertext is allowed because sealing an
    /// empty secret is legitimate.
    ///
    /// A wrapped DEK is `SEALED_KEY_LEN` plus the GCM tag, so the exact bound is
    /// checked by the sealer rather than guessed here; this constructor only
    /// rejects obviously malformed material.
    pub fn new(
        key_version: u32,
        dek_nonce: Vec<u8>,
        wrapped_dek: Vec<u8>,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Re0Result<Self> {
        if dek_nonce.len() != SEALED_NONCE_LEN {
            return Err(Re0Error::Internal(format!(
                "wrapped-dek nonce must be {SEALED_NONCE_LEN} bytes, got {}",
                dek_nonce.len()
            )));
        }
        if nonce.len() != SEALED_NONCE_LEN {
            return Err(Re0Error::Internal(format!(
                "sealed nonce must be {SEALED_NONCE_LEN} bytes, got {}",
                nonce.len()
            )));
        }
        if wrapped_dek.is_empty() {
            return Err(Re0Error::Internal(
                "wrapped dek must not be empty".to_string(),
            ));
        }
        Ok(Self {
            key_version,
            dek_nonce,
            wrapped_dek,
            nonce,
            ciphertext,
        })
    }

    #[must_use]
    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    #[must_use]
    pub fn dek_nonce(&self) -> &[u8] {
        &self.dek_nonce
    }

    #[must_use]
    pub fn wrapped_dek(&self) -> &[u8] {
        &self.wrapped_dek
    }

    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// True when the payload is byte-identical apart from the key envelope.
    ///
    /// Used by rotation to prove it did not touch the ciphertext.
    #[must_use]
    pub fn same_payload_as(&self, other: &Self) -> bool {
        self.nonce == other.nonce && self.ciphertext == other.ciphertext
    }
}

impl std::fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedSecret")
            .field("key_version", &self.key_version)
            .field("dek_nonce", &"<redacted>")
            .field("wrapped_dek", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

/// `binding` is bound into both layers (INV-ENC-01): the DEK's wrapping and the
/// payload, so a ciphertext cannot be moved to another binding even if both
/// halves are copied together.
pub trait SecretSealer: Send + Sync {
    fn seal(&self, binding: &BindingId, plaintext: &SecretString) -> Re0Result<SealedSecret>;
    fn open(&self, binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SecretString>;

    /// Re-wraps the DEK under the current master key.
    ///
    /// The payload is not decrypted and not rewritten: only `key_version`,
    /// `dek_nonce` and `wrapped_dek` change. That is what makes rotation cheap
    /// and repeatable. Returns the value unchanged when it is already on the
    /// current key, so a caller can tell a no-op from a re-wrap by comparing
    /// [`SealedSecret::key_version`].
    fn rewrap(&self, binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SealedSecret>;
}

/// Hashes client secrets for storage and verification (ADR-0030).
///
/// Not a bare digest: a pepper derived from the master key is mixed in, so a
/// stolen database alone is not enough to test a guess offline. The output is
/// what lands in `clients.secret_hash`, and `key_version` lets a future pepper
/// rotation tell old rows apart.
pub trait ClientSecretHasher: Send + Sync {
    fn hash(&self, secret: &str) -> Re0Result<ClientSecretHash>;
    /// Constant-time comparison against a stored hash.
    fn matches(&self, secret: &str, stored: &ClientSecretHash) -> bool;
}

/// INV-NOLOG-01: the digest is a password-equivalent and is never printed.
///
/// Private for the same reason as [`SealedSecret`]: a hash is only meaningful
/// when a hasher produced it. A struct literal could carry a wrong
/// `key_version`, and `matches` would then derive the wrong pepper and reject
/// every correct password.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientSecretHash {
    key_version: u32,
    digest: Vec<u8>,
}

impl ClientSecretHash {
    pub fn new(key_version: u32, digest: Vec<u8>) -> Re0Result<Self> {
        if digest.is_empty() {
            return Err(Re0Error::Internal(
                "client secret digest must not be empty".to_string(),
            ));
        }
        Ok(Self {
            key_version,
            digest,
        })
    }

    #[must_use]
    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl std::fmt::Debug for ClientSecretHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSecretHash")
            .field("key_version", &self.key_version)
            .field("digest", &"<redacted>")
            .finish()
    }
}
