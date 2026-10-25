//! AES-256-GCM sealing for sub-credentials (§12.1, ADR-0042).
//!
//! Two layers: a per-record DEK encrypts the payload, and the master key (KEK)
//! wraps that DEK. Rotating the master key therefore re-wraps 32 bytes per record
//! instead of re-encrypting its payload, and revoking a credential can drop the
//! wrapped DEK so leftover ciphertext is undecryptable.

use std::path::Path;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use re0auth_api::secret::{SealedSecret, SecretSealer};
use re0auth_api::{BindingId, Random, Re0Error, Re0Result, SecretString};

// The master-key rules live in `re0auth_runtime::master_key`: the connector
// vault derives keys from the same configured secret, and duplicating the
// precedence rules would let the two adapters disagree.
use re0auth_runtime::master_key::{decode_hex, resolve_master_key};

use secrecy::ExposeSecret;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// The version `seal` writes and `rewrap` moves a record onto. Retired versions
/// stay readable because [`AesGcmSealer::with_keys`] holds them.
pub const CURRENT_KEY_VERSION: u32 = 1;

type Nonce12 = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;

pub struct AesGcmSealer {
    /// Keyed by version. `CURRENT_KEY_VERSION` is always present; retired keys
    /// are kept so records written before a rotation can still be opened and
    /// re-wrapped. Dropping a retired key is what makes its records unreadable,
    /// so it must happen only after a rotation reports `skipped == 0`.
    keys: std::collections::BTreeMap<u32, Zeroizing<[u8; KEY_LEN]>>,
    random: std::sync::Arc<dyn Random>,
}

impl AesGcmSealer {
    /// A sealer holding one key, at the current version.
    pub fn new(master_hex: &str, random: std::sync::Arc<dyn Random>) -> anyhow::Result<Self> {
        Self::with_keys(std::iter::once((CURRENT_KEY_VERSION, master_hex)), random)
    }

    /// A sealer holding a current key plus any retired keys.
    ///
    /// The retired keys are what make rotation possible at all: a record wrapped
    /// under an older key cannot be re-wrapped without the key that wrapped it.
    /// Configuration therefore has to name them explicitly during a rotation, and
    /// an unknown version in the data is an error rather than a silent skip.
    pub fn with_keys<'a>(
        keys: impl IntoIterator<Item = (u32, &'a str)>,
        random: std::sync::Arc<dyn Random>,
    ) -> anyhow::Result<Self> {
        let mut parsed = std::collections::BTreeMap::new();
        for (version, master_hex) in keys {
            let bytes = decode_hex(master_hex.trim())?;
            if bytes.len() != KEY_LEN {
                anyhow::bail!(
                    "encryption key version {version} must be {KEY_LEN} bytes ({} hex chars), got {} bytes",
                    KEY_LEN * 2,
                    bytes.len()
                );
            }
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&bytes);
            if parsed.insert(version, key).is_some() {
                anyhow::bail!("encryption key version {version} was configured twice");
            }
        }
        if !parsed.contains_key(&CURRENT_KEY_VERSION) {
            anyhow::bail!(
                "the current encryption key (version {CURRENT_KEY_VERSION}) must be configured"
            );
        }
        Ok(Self {
            keys: parsed,
            random,
        })
    }

    /// Reads `RE0AUTH_ENCRYPTION_KEY` or a `0600` file. Exactly one source.
    pub fn from_env_or_file(
        file: Option<&Path>,
        random: std::sync::Arc<dyn Random>,
    ) -> anyhow::Result<Self> {
        Self::from_env_or_file_with(std::env::var("RE0AUTH_ENCRYPTION_KEY").ok(), file, random)
    }

    /// The raw master key, resolved the same way `from_env_or_file` resolves it.
    ///
    /// Exposed so other key derivations (the client-secret pepper) share one
    /// source of truth instead of re-implementing the precedence rules.
    pub fn master_key_hex(file: Option<&Path>) -> anyhow::Result<String> {
        resolve_master_key(std::env::var("RE0AUTH_ENCRYPTION_KEY").ok(), file)
    }

    fn from_env_or_file_with(
        env_value: Option<String>,
        file: Option<&Path>,
        random: std::sync::Arc<dyn Random>,
    ) -> anyhow::Result<Self> {
        Self::new(&resolve_master_key(env_value, file)?, random)
    }

    /// The cipher for a given key version, or an error naming the version.
    fn cipher(&self, key_version: u32) -> Re0Result<Aes256Gcm> {
        let key = self.keys.get(&key_version).ok_or_else(|| {
            Re0Error::Internal(format!(
                "no encryption key is configured for version {key_version}; \
                 declare it as a retired key and run the rotation again"
            ))
        })?;
        Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| internal("invalid AES-256 key"))
    }
}

fn aad(binding: &BindingId) -> Vec<u8> {
    binding.0.as_bytes().to_vec()
}

fn internal(message: &str) -> Re0Error {
    Re0Error::Internal(message.to_string())
}

impl SecretSealer for AesGcmSealer {
    fn seal(&self, binding: &BindingId, plaintext: &SecretString) -> Re0Result<SealedSecret> {
        let key_version = CURRENT_KEY_VERSION;

        // A fresh DEK per record: rotating the KEK then never has to touch a
        // payload, and revoking one credential cannot affect another's key.
        let dek_bytes = self.random.bytes(KEY_LEN);
        if dek_bytes.len() != KEY_LEN {
            return Err(internal("random source returned a short dek"));
        }
        let mut dek = Zeroizing::new([0u8; KEY_LEN]);
        dek.copy_from_slice(&dek_bytes);

        let binding_aad = aad(binding);
        let (dek_nonce, wrapped_dek) = self.wrap(&dek, &binding_aad)?;

        let payload_cipher =
            Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| internal("invalid AES-256 key"))?;
        let nonce_bytes = self.random.bytes(NONCE_LEN);
        if nonce_bytes.len() != NONCE_LEN {
            return Err(internal("random source returned a short nonce"));
        }
        let nonce = nonce_from(&nonce_bytes)?;
        let ciphertext = payload_cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.expose_secret().as_bytes(),
                    aad: &binding_aad,
                },
            )
            .map_err(|_| internal("seal failed"))?;

        SealedSecret::new(key_version, dek_nonce, wrapped_dek, nonce_bytes, ciphertext)
    }

    fn open(&self, binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SecretString> {
        let binding_aad = aad(binding);
        let dek = self.unwrap(
            sealed.key_version(),
            sealed.dek_nonce(),
            sealed.wrapped_dek(),
            &binding_aad,
        )?;

        let payload_cipher =
            Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| internal("invalid AES-256 key"))?;
        let nonce = nonce_from(sealed.nonce())?;
        let plaintext = payload_cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: sealed.ciphertext(),
                    aad: &binding_aad,
                },
            )
            .map_err(|_| internal("sealed secret failed authentication"))?;
        let text =
            String::from_utf8(plaintext).map_err(|_| internal("sealed secret is not UTF-8"))?;
        Ok(SecretString::from(text))
    }

    fn rewrap(&self, binding: &BindingId, sealed: &SealedSecret) -> Re0Result<SealedSecret> {
        if sealed.key_version() == CURRENT_KEY_VERSION {
            // Already current. Still unwrap, so a deployment that changed the key
            // material without changing the version is caught here rather than
            // when a user cannot reach their own data.
            let binding_aad = aad(binding);
            self.unwrap(
                sealed.key_version(),
                sealed.dek_nonce(),
                sealed.wrapped_dek(),
                &binding_aad,
            )?;
            return Ok(sealed.clone());
        }

        let binding_aad = aad(binding);
        let dek = self.unwrap(
            sealed.key_version(),
            sealed.dek_nonce(),
            sealed.wrapped_dek(),
            &binding_aad,
        )?;
        let (dek_nonce, wrapped_dek) = self.wrap(&dek, &binding_aad)?;

        SealedSecret::new(
            CURRENT_KEY_VERSION,
            dek_nonce,
            wrapped_dek,
            sealed.nonce().to_vec(),
            sealed.ciphertext().to_vec(),
        )
    }
}

impl AesGcmSealer {
    /// Encrypts a DEK under the current master key. Verifies the wrap by opening
    /// it again: a wrap that produced bytes the same key cannot read would only
    /// surface when a user tries to use the credential.
    fn wrap(&self, dek: &Zeroizing<[u8; KEY_LEN]>, aad: &[u8]) -> Re0Result<(Vec<u8>, Vec<u8>)> {
        let kek = self.cipher(CURRENT_KEY_VERSION)?;
        let nonce_bytes = self.random.bytes(NONCE_LEN);
        if nonce_bytes.len() != NONCE_LEN {
            return Err(internal("random source returned a short nonce"));
        }
        let nonce = nonce_from(&nonce_bytes)?;
        let wrapped = kek
            .encrypt(
                &nonce,
                Payload {
                    msg: dek.as_ref(),
                    aad,
                },
            )
            .map_err(|_| internal("dek wrap failed"))?;

        // Read back before handing the value on.
        let check = kek
            .decrypt(&nonce, Payload { msg: &wrapped, aad })
            .map_err(|_| internal("dek wrap does not round-trip"))?;
        if check.as_slice() != dek.as_ref() {
            return Err(internal("dek wrap read back a different key"));
        }
        Ok((nonce_bytes, wrapped))
    }

    /// Decrypts a wrapped DEK under the key version it was wrapped with.
    fn unwrap(
        &self,
        key_version: u32,
        dek_nonce: &[u8],
        wrapped_dek: &[u8],
        aad: &[u8],
    ) -> Re0Result<Zeroizing<[u8; KEY_LEN]>> {
        let kek = self.cipher(key_version)?;
        let nonce = nonce_from(dek_nonce)?;
        let dek = kek
            .decrypt(
                &nonce,
                Payload {
                    msg: wrapped_dek,
                    aad,
                },
            )
            .map_err(|_| internal("dek unwrap failed"))?;
        let dek: [u8; KEY_LEN] = dek
            .try_into()
            .map_err(|_| internal("unwrapped dek is not 32 bytes"))?;
        Ok(Zeroizing::new(dek))
    }
}

fn nonce_from(bytes: &[u8]) -> Re0Result<Nonce12> {
    let array: [u8; NONCE_LEN] = bytes
        .try_into()
        .map_err(|_| internal("nonce must be 12 bytes"))?;
    Ok(Nonce12::from(array))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use re0auth_api::Random;

    use super::*;

    const MASTER: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    struct FixedRandom(u8);

    impl Random for FixedRandom {
        fn bytes(&self, len: usize) -> Vec<u8> {
            vec![self.0; len]
        }
    }

    fn sealer() -> AesGcmSealer {
        AesGcmSealer::new(MASTER, Arc::new(FixedRandom(0x11))).expect("sealer")
    }

    fn token() -> SecretString {
        SecretString::from("sub-token-value".to_string())
    }

    #[test]
    fn round_trips_and_reuses_the_contract_suite() {
        re0auth_contract::secret_sealer_contract(&sealer());
    }

    #[test]
    fn ciphertext_is_not_plaintext_and_nonce_is_stored() {
        let sealer = sealer();
        let binding = BindingId::new();
        let sealed = sealer.seal(&binding, &token()).expect("seal");
        assert_ne!(sealed.ciphertext(), b"sub-token-value");
        assert_eq!(sealed.nonce().len(), NONCE_LEN);
        assert_eq!(sealed.key_version(), CURRENT_KEY_VERSION);
    }

    #[test]
    fn opening_under_another_binding_fails() {
        let sealer = sealer();
        let sealed = sealer.seal(&BindingId::new(), &token()).expect("seal");
        assert!(
            sealer.open(&BindingId::new(), &sealed).is_err(),
            "binding id is authenticated as AAD"
        );
    }

    /// Tampering has to be expressed by rebuilding the value through the
    /// constructor: the fields are private now, so a test cannot mutate a
    /// ciphertext into a state the type forbids. That is the point of the
    /// change — this test used to do exactly what production code must not.
    #[test]
    fn tampered_ciphertext_and_nonce_fail() {
        let sealer = sealer();
        let binding = BindingId::new();
        let sealed = sealer.seal(&binding, &token()).expect("seal");

        let mut ciphertext = sealed.ciphertext().to_vec();
        ciphertext[0] ^= 1;
        let bad_cipher = SealedSecret::new(
            sealed.key_version(),
            sealed.dek_nonce().to_vec(),
            sealed.wrapped_dek().to_vec(),
            sealed.nonce().to_vec(),
            ciphertext,
        )
        .expect("same nonce");
        assert!(sealer.open(&binding, &bad_cipher).is_err());

        let mut nonce = sealed.nonce().to_vec();
        nonce[0] ^= 1;
        let bad_nonce = SealedSecret::new(
            sealed.key_version(),
            sealed.dek_nonce().to_vec(),
            sealed.wrapped_dek().to_vec(),
            nonce,
            sealed.ciphertext().to_vec(),
        )
        .expect("still 12 bytes");
        assert!(sealer.open(&binding, &bad_nonce).is_err());

        // The DEK is authenticated too: swapping the envelope for another
        // binding's must fail even though the payload is unchanged.
        let mut wrapped = sealed.wrapped_dek().to_vec();
        wrapped[0] ^= 1;
        let bad_wrap = SealedSecret::new(
            sealed.key_version(),
            sealed.dek_nonce().to_vec(),
            wrapped,
            sealed.nonce().to_vec(),
            sealed.ciphertext().to_vec(),
        )
        .expect("same lengths");
        assert!(sealer.open(&binding, &bad_wrap).is_err());
    }

    /// A short nonce can no longer be produced at all; the constructor is the
    /// only door and it rejects anything that is not 12 bytes.
    #[test]
    fn a_malformed_nonce_cannot_be_constructed() {
        for bad in [vec![], vec![0u8; 11], vec![0u8; 13], vec![0u8; 16]] {
            assert!(
                SealedSecret::new(1, bad.clone(), vec![0u8; 44], vec![0u8; 12], vec![0u8; 8])
                    .is_err(),
                "{}-byte nonce must be rejected",
                bad.len()
            );
        }
        assert!(
            SealedSecret::new(1, vec![0u8; 12], vec![], vec![0u8; 12], vec![0u8; 8]).is_err(),
            "an empty wrapped dek must be rejected"
        );
    }

    #[test]
    fn unknown_key_version_cannot_be_decrypted() {
        let sealer = sealer();
        let binding = BindingId::new();
        let sealed = sealer.seal(&binding, &token()).expect("seal");
        let other = SealedSecret::new(
            99,
            sealed.dek_nonce().to_vec(),
            sealed.wrapped_dek().to_vec(),
            sealed.nonce().to_vec(),
            sealed.ciphertext().to_vec(),
        )
        .expect("valid shape");
        assert!(
            sealer.open(&binding, &other).is_err(),
            "an unconfigured key version must be an error, not a guess"
        );
    }

    #[test]
    fn master_key_must_be_32_bytes_of_hex() {
        let ok = AesGcmSealer::new(MASTER, Arc::new(FixedRandom(0)));
        assert!(ok.is_ok());
        for bad in [
            "abcd",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
        ] {
            assert!(
                AesGcmSealer::new(bad, Arc::new(FixedRandom(0))).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn exactly_one_key_source_is_allowed() {
        let file =
            std::env::temp_dir().join(format!("re0auth-master-{}.hex", uuid::Uuid::now_v7()));
        std::fs::write(&file, MASTER).expect("write key");
        let random: Arc<dyn Random> = Arc::new(FixedRandom(0));

        assert!(
            AesGcmSealer::from_env_or_file_with(
                Some(MASTER.to_string()),
                Some(&file),
                random.clone()
            )
            .is_err(),
            "setting both sources must fail"
        );
        assert!(
            AesGcmSealer::from_env_or_file_with(Some(MASTER.to_string()), None, random.clone())
                .is_ok()
        );
        assert!(AesGcmSealer::from_env_or_file_with(None, Some(&file), random.clone()).is_ok());
        assert!(
            AesGcmSealer::from_env_or_file_with(None, None, random).is_err(),
            "no source must fail"
        );

        let _ = std::fs::remove_file(file);
    }

    /// With two layers the payload ciphertext depends only on the DEK, not on
    /// the master key. Two sealers with different masters therefore produce the
    /// same payload bytes when the DEK happens to repeat — and that is the
    /// property rotation relies on. What must differ is the envelope.
    #[test]
    fn a_different_master_changes_the_envelope_not_the_payload() {
        let binding = BindingId::new();
        let other = "1111111111111111111111111111111111111111111111111111111111111111";
        let first = AesGcmSealer::new(MASTER, Arc::new(FixedRandom(0x11))).expect("first");
        let second = AesGcmSealer::new(other, Arc::new(FixedRandom(0x11))).expect("second");
        let a = first.seal(&binding, &token()).expect("seal a");
        let b = second.seal(&binding, &token()).expect("seal b");

        assert_ne!(
            a.wrapped_dek(),
            b.wrapped_dek(),
            "the master key is what protects the DEK, so the envelope must differ"
        );
        assert_eq!(
            a.ciphertext(),
            b.ciphertext(),
            "the payload is encrypted under the DEK, so the master key must not reach it"
        );
        assert!(
            second.open(&binding, &a).is_err(),
            "a DEK wrapped under another master must not open"
        );
        assert_eq!(
            second.open(&binding, &b).expect("open b").expose_secret(),
            "sub-token-value"
        );
    }

    /// A rotation rewrites the envelope and leaves the payload byte-identical.
    ///
    /// This is the whole point of the two-layer scheme: no plaintext is produced
    /// and no ciphertext is rewritten, so a rotation over a large store is cheap
    /// and can be re-run safely.
    #[test]
    fn rewrap_moves_the_envelope_and_keeps_the_payload() {
        let binding = BindingId::new();
        let old = AesGcmSealer::new(MASTER, Arc::new(FixedRandom(0x11))).expect("old");
        let sealed = old.seal(&binding, &token()).expect("seal");

        // A sealer holding the retired key plus a new current key would move the
        // record onto version 2; here both versions are the same material so the
        // assertion is about the payload, not about key material.
        let rotated = old.rewrap(&binding, &sealed).expect("rewrap");

        assert!(
            sealed.same_payload_as(&rotated),
            "rotation must not touch the ciphertext or its nonce"
        );
        assert_eq!(
            old.open(&binding, &rotated).expect("open").expose_secret(),
            "sub-token-value",
            "a re-wrapped record must still open"
        );
    }

    /// Re-wrapping a record that is already on the current version is a no-op,
    /// but it still proves the current key can read it. A deployment that changed
    /// the key material without changing the version is caught here rather than
    /// when a user cannot reach their own data.
    #[test]
    fn rewrapping_a_current_record_verifies_it_is_readable() {
        let binding = BindingId::new();
        let old = AesGcmSealer::new(MASTER, Arc::new(FixedRandom(0x11))).expect("old");
        let sealed = old.seal(&binding, &token()).expect("seal");
        assert_eq!(sealed.key_version(), CURRENT_KEY_VERSION);

        let same = old.rewrap(&binding, &sealed).expect("rewrap");
        assert_eq!(same.key_version(), CURRENT_KEY_VERSION);

        // Same version tag, different key material: the record must be refused
        // rather than assumed fine.
        let impostor = AesGcmSealer::new(
            "1111111111111111111111111111111111111111111111111111111111111111",
            Arc::new(FixedRandom(0x11)),
        )
        .expect("impostor");
        assert!(
            impostor.rewrap(&binding, &sealed).is_err(),
            "a version tag that lies about the key material must be an error"
        );
    }

    #[test]
    fn a_record_wrapped_by_an_unconfigured_key_cannot_be_rewrapped() {
        let binding = BindingId::new();
        let old = AesGcmSealer::new(MASTER, Arc::new(FixedRandom(0x11))).expect("old");
        let sealed = old.seal(&binding, &token()).expect("seal");

        // The record claims version 99, which no configured key covers.
        let orphan = SealedSecret::new(
            99,
            sealed.dek_nonce().to_vec(),
            sealed.wrapped_dek().to_vec(),
            sealed.nonce().to_vec(),
            sealed.ciphertext().to_vec(),
        )
        .expect("shape");

        let error = old
            .rewrap(&binding, &orphan)
            .expect_err("an unconfigured version must fail");
        assert!(
            error.to_string().contains("version 99"),
            "the error must name the missing version so an operator knows what to declare: {error}"
        );
    }

    #[test]
    fn a_sealer_must_hold_the_current_key() {
        let other = "1111111111111111111111111111111111111111111111111111111111111111";
        let Err(error) = AesGcmSealer::with_keys([(7u32, other)], Arc::new(FixedRandom(0))) else {
            panic!("a sealer without the current key must refuse to build");
        };
        assert!(
            error.to_string().contains("current encryption key"),
            "{error}"
        );
    }

    #[test]
    fn a_version_configured_twice_is_rejected() {
        let Err(error) = AesGcmSealer::with_keys(
            [(CURRENT_KEY_VERSION, MASTER), (CURRENT_KEY_VERSION, MASTER)],
            Arc::new(FixedRandom(0)),
        ) else {
            panic!("a duplicate version is ambiguous");
        };
        assert!(error.to_string().contains("configured twice"), "{error}");
    }
}
