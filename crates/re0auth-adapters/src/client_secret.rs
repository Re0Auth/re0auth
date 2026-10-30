//! Client secret hashing (ADR-0030).
//!
//! A 32-byte random secret has enough entropy that a bare digest would resist
//! offline guessing. The pepper is not there to slow down guessing — it is there
//! so a stolen database alone cannot be used to verify a candidate secret,
//! because the pepper lives with the master key, not in the database.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use re0auth_api::Re0Error;
use re0auth_api::Re0Result;
use re0auth_api::secret::{ClientSecretHash, ClientSecretHasher};

use re0auth_runtime::master_key::decode_hex;

const KEY_LEN: usize = 32;
/// Distinct from `re0auth/sub-credential` so a leaked pepper cannot be used as
/// an AEAD key or vice versa.
const HKDF_INFO: &[u8] = b"re0auth/client-secret-pepper";
/// Used when no explicit current version is supplied. Runtime callers pass
/// `crypto.master_key_version` through [`HmacClientSecretHasher::with_keys`].
pub const DEFAULT_KEY_VERSION: u32 = 1;

type HmacSha256 = Hmac<Sha256>;

pub struct HmacClientSecretHasher {
    current_version: u32,
    /// One master key per version. Retired keys stay so client secrets hashed
    /// before a master-key rotation still verify.
    keys: std::collections::BTreeMap<u32, Zeroizing<[u8; KEY_LEN]>>,
}

impl HmacClientSecretHasher {
    /// The master key is the same one the sealer uses; only the HKDF `info`
    /// label differs, so one configured key covers both purposes.
    pub fn new(master_hex: &str) -> anyhow::Result<Self> {
        Self::with_keys(DEFAULT_KEY_VERSION, [(DEFAULT_KEY_VERSION, master_hex)])
    }

    /// A hasher holding the current master key plus any retired keys.
    ///
    /// A client secret hash records the version that produced it; verification
    /// must therefore use the key that version names, not the current one.
    /// Versions follow the same rules as [`super::sealer::AesGcmSealer`].
    pub fn with_keys<'a>(
        current_version: u32,
        keys: impl IntoIterator<Item = (u32, &'a str)>,
    ) -> anyhow::Result<Self> {
        if current_version == 0 {
            anyhow::bail!("the current client-secret key version must be greater than zero");
        }
        let mut parsed = std::collections::BTreeMap::new();
        for (version, master_hex) in keys {
            if version == 0 {
                anyhow::bail!("client-secret key version 0 is not allowed");
            }
            if version > current_version {
                anyhow::bail!(
                    "client-secret key version {version} is newer than the current version {current_version}"
                );
            }
            let bytes = decode_hex(master_hex.trim())?;
            if bytes.len() != KEY_LEN {
                anyhow::bail!(
                    "encryption key version {version} must be {KEY_LEN} bytes ({} hex chars), got {} bytes",
                    KEY_LEN * 2,
                    bytes.len()
                );
            }
            let mut master = Zeroizing::new([0u8; KEY_LEN]);
            master.copy_from_slice(bytes.as_slice());
            if parsed.insert(version, master).is_some() {
                anyhow::bail!("client-secret key version {version} was configured twice");
            }
        }
        if !parsed.contains_key(&current_version) {
            anyhow::bail!(
                "the current client-secret key (version {current_version}) must be configured"
            );
        }
        Ok(Self {
            current_version,
            keys: parsed,
        })
    }

    fn pepper(&self, key_version: u32) -> Re0Result<Zeroizing<[u8; KEY_LEN]>> {
        let master = self.keys.get(&key_version).ok_or_else(|| {
            internal(&format!(
                "no client-secret key is configured for version {key_version}"
            ))
        })?;
        let hkdf = Hkdf::<Sha256>::new(None, master.as_ref());
        let mut info = Vec::with_capacity(HKDF_INFO.len() + 4);
        info.extend_from_slice(HKDF_INFO);
        info.extend_from_slice(&key_version.to_be_bytes());
        let mut pepper = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(&info, pepper.as_mut())
            .map_err(|_| internal("hkdf expand failed"))?;
        Ok(pepper)
    }

    fn digest(&self, secret: &str, key_version: u32) -> Re0Result<Vec<u8>> {
        let pepper = self.pepper(key_version)?;
        let mut mac = HmacSha256::new_from_slice(pepper.as_ref())
            .map_err(|_| internal("invalid HMAC key"))?;
        mac.update(secret.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl ClientSecretHasher for HmacClientSecretHasher {
    fn hash(&self, secret: &str) -> Re0Result<ClientSecretHash> {
        ClientSecretHash::new(
            self.current_version,
            self.digest(secret, self.current_version)?,
        )
    }

    fn matches(&self, secret: &str, stored: &ClientSecretHash) -> bool {
        // HMAC's own verification is constant-time; comparing with `==` on a
        // `Vec` is not, which is why this goes back through `Mac::verify`.
        let Ok(pepper) = self.pepper(stored.key_version()) else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(pepper.as_ref()) else {
            return false;
        };
        mac.update(secret.as_bytes());
        mac.verify_slice(stored.digest()).is_ok()
    }
}

fn internal(message: &str) -> Re0Error {
    Re0Error::Internal(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_same_secret_hashes_the_same_and_matches() {
        let hasher = HmacClientSecretHasher::new(MASTER).expect("hasher");
        let hash = hasher.hash("s3cret").expect("hash");
        assert!(hasher.matches("s3cret", &hash));
        assert_eq!(hash, hasher.hash("s3cret").expect("hash again"));
    }

    #[test]
    fn a_wrong_secret_does_not_match() {
        let hasher = HmacClientSecretHasher::new(MASTER).expect("hasher");
        let hash = hasher.hash("s3cret").expect("hash");
        assert!(!hasher.matches("s3creT", &hash));
        assert!(!hasher.matches("", &hash));
    }

    #[test]
    fn different_masters_produce_different_digests() {
        let one = HmacClientSecretHasher::new(MASTER).expect("hasher");
        let other_master = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let other = HmacClientSecretHasher::new(other_master).expect("hasher");
        let hash = one.hash("s3cret").expect("hash");
        // The pepper is what makes a stolen database useless on its own.
        assert!(!other.matches("s3cret", &hash));
        assert_ne!(hash.digest(), other.hash("s3cret").expect("hash").digest());
    }

    #[test]
    fn the_pepper_label_is_distinct_from_the_sealing_label() {
        // Both derive from the same master. If the labels ever collapsed, one
        // leaked output would be usable as the other key.
        let hasher = HmacClientSecretHasher::new(MASTER).expect("hasher");
        let pepper = hasher.pepper(DEFAULT_KEY_VERSION).expect("pepper");

        let hkdf = Hkdf::<Sha256>::new(None, &decode_hex(MASTER).expect("master"));
        let mut sealing = [0u8; KEY_LEN];
        hkdf.expand(b"re0auth/sub-credential\x00\x00\x00\x01", &mut sealing)
            .expect("expand");

        assert_ne!(pepper.as_ref(), &sealing);
    }

    const ROTATED_MASTER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// A hash records the version that produced it, so a master-key rotation
    /// must keep verifying the old secret until it is re-issued.
    #[test]
    fn a_retired_key_still_verifies_the_hash_it_produced() {
        let old = HmacClientSecretHasher::new(MASTER).expect("v1");
        let hash = old.hash("s3cret").expect("hash");

        let rotated = HmacClientSecretHasher::with_keys(2, [(1, MASTER), (2, ROTATED_MASTER)])
            .expect("v2 with retired v1");
        assert!(
            rotated.matches("s3cret", &hash),
            "a secret hashed under v1 must keep working during the rotation"
        );
        let fresh = rotated.hash("s3cret").expect("hash");
        assert_eq!(fresh.key_version(), 2);
        assert!(rotated.matches("s3cret", &fresh));
        assert!(
            !old.matches("s3cret", &fresh),
            "the old hasher does not hold v2"
        );
    }

    #[test]
    fn a_hasher_must_hold_the_current_key() {
        let Err(error) = HmacClientSecretHasher::with_keys(7, [(1u32, MASTER)]) else {
            panic!("a hasher without the current key must refuse to build");
        };
        assert!(
            error.to_string().contains("current client-secret key"),
            "{error}"
        );
    }

    #[test]
    fn unknown_versions_do_not_verify_instead_of_panicking() {
        let hasher = HmacClientSecretHasher::new(MASTER).expect("hasher");
        let mut hash = hasher.hash("s3cret").expect("hash");
        // A hash claiming a version with no configured key must fail closed.
        hash = ClientSecretHash::new(9, hash.digest().to_vec()).expect("shape");
        assert!(!hasher.matches("s3cret", &hash));
    }
}
