//! RS256 token signing and the public JWKS document.
//!
//! A key set, not a single key. Rotation is the reason: when a new key starts
//! signing, tokens issued under the previous one are still inside their validity
//! window. They must keep verifying, which means the old public key has to stay
//! in the JWKS until the last token it signed has expired
//! (OPERATIONS.md §5.2).
//!
//! Private keys never touch the database (INV-KEY-01). Each one lives in its own
//! `0600` PEM file named after its `kid`, and the database stores only the public
//! JWK plus timestamps.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{Context, bail};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKey};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, PublicKeyUse, RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use sha2::{Digest, Sha256};

use re0auth_api::oauth::{
    ACCESS_TOKEN_USE, APPROVAL_TICKET_USE, AccessTokenClaims, ApprovalTicketClaims, IdTokenClaims,
    TokenSigner,
};
use re0auth_api::ports::SigningKeyRecord;
use re0auth_api::{Re0Error, Re0Result, Unix};

/// One usable key: the private half plus its derived public record.
pub struct SigningKey {
    pub record: SigningKeyRecord,
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // INV-NOLOG-01: the encoding key is private material.
        f.debug_struct("SigningKey")
            .field("kid", &self.record.kid)
            .field("alg", &self.record.alg)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Loads a PEM private key from disk and derives everything else from it.
    ///
    /// Only PKCS#8 (`BEGIN PRIVATE KEY`) is accepted. PKCS#1
    /// (`BEGIN RSA PRIVATE KEY`) is a RSA-only layout that would need a second
    /// parser; nothing has ever been deployed, so there is no legacy file to
    /// keep supporting. Convert one with `openssl pkcs8 -topk8 -nocrypt`.
    ///
    /// The `kid` is the first 8 bytes of the SHA-256 of the public DER. Deriving
    /// it means the same key always gets the same `kid`, and a different key
    /// always gets a different one — reusing a `kid` for a new key is the known
    /// failure mode where old tokens resolve to the wrong key.
    pub fn load(path: &Path, now: Unix) -> anyhow::Result<Self> {
        let pem = fs::read_to_string(path)
            .with_context(|| format!("read signing key {}", path.display()))?;
        let der = pem_body(&pem).with_context(|| {
            format!(
                "signing key {} must be a PKCS#8 PEM (`BEGIN PRIVATE KEY`); \
                 convert a PKCS#1 key with `openssl pkcs8 -topk8 -nocrypt -in old.pem -out new.pem`",
                path.display()
            )
        })?;
        let key_pair = KeyPair::from_pkcs8(&der).context("parse RSA signing key as PKCS#8")?;
        Self::from_key_pair(key_pair, now)
    }

    /// Generates a new key and writes it to `path` with mode `0600`.
    pub fn generate(path: &Path, now: Unix) -> anyhow::Result<Self> {
        let key_pair = KeyPair::generate(KeySize::Rsa2048).context("generate RSA signing key")?;
        let der = AsDer::<Pkcs8V1Der>::as_der(&key_pair).context("encode signing key as PKCS#8")?;
        let pem = pkcs8_pem(der.as_ref());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create key directory {}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create signing key {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .context("set signing key permissions")?;
        }
        file.write_all(pem.as_bytes())
            .context("write signing key")?;
        Self::from_key_pair(key_pair, now)
    }

    fn from_key_pair(key_pair: KeyPair, now: Unix) -> anyhow::Result<Self> {
        // `public_key()` is the DER SubjectPublicKeyInfo, not a PKCS#1 RSAPublicKey.
        // The kid therefore commits to this encoding: re-encoding the same key a
        // different way would mint a new kid and orphan every token it signed.
        let public_der = key_pair.public_key();
        let digest = Sha256::digest(public_der.as_ref());
        let kid = digest
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let public = PublicKey::from_der(public_der.as_ref()).context("parse RSA public key")?;
        let modulus = public.modulus();
        let exponent = public.exponent();
        // Built from the JWK types rather than a hand-written JSON literal: a
        // misspelled member name would serialise happily and produce a key set
        // no client could use. The struct makes the shape a compile-time fact.
        let public_jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(Algorithm::RS256.into()),
                key_id: Some(kid.clone()),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: URL_SAFE_NO_PAD.encode(modulus.big_endian_without_leading_zero()),
                e: URL_SAFE_NO_PAD.encode(exponent.big_endian_without_leading_zero()),
            }),
        };
        let public_jwk_json = serde_json::to_string(&public_jwk).context("serialize public JWK")?;

        // `EncodingKey::from_rsa_der` only accepts a PKCS#1 RSAPrivateKey, not the
        // PKCS#8 document aws-lc-rs produces, so the private half goes back
        // through PEM. `from_rsa_pem` does accept PKCS#8.
        let private_der =
            AsDer::<Pkcs8V1Der>::as_der(&key_pair).context("encode RSA private key as PKCS#8")?;
        let encoding = EncodingKey::from_rsa_pem(pkcs8_pem(private_der.as_ref()).as_bytes())
            .context("load RSA signing key")?;

        Ok(Self {
            record: SigningKeyRecord {
                kid,
                alg: "RS256".to_string(),
                public_jwk_json,
                created_at: now,
                activated_at: now,
                retired_at: None,
            },
            encoding,
            decoding: DecodingKey::from_rsa_der(public_der.as_ref()),
        })
    }

    fn header(&self) -> Header {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.record.kid.clone());
        header
    }
}

/// A key set that can sign with the newest key and verify with any of them.
pub struct RsaTokenSigner {
    issuer: String,
    access_aud: String,
    /// Keyed by `kid`. `BTreeMap` so the JWKS output is stable across restarts,
    /// which keeps response caching and diffing sane.
    keys: RwLock<BTreeMap<String, SigningKey>>,
    /// Which key new tokens are signed with.
    active: RwLock<Option<String>>,
    /// Where newly generated private keys are written.
    key_dir: PathBuf,
}

impl std::fmt::Debug for RsaTokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaTokenSigner")
            .field("issuer", &self.issuer)
            .field("keys", &self.keys.read().map(|k| k.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl RsaTokenSigner {
    /// Loads the key file at `path`, generating it on first start, and publishes
    /// it. Existing keys in `known` are loaded too so their tokens keep
    /// verifying after a rotation.
    ///
    /// `known` is what the database remembers; a row whose PEM file is missing is
    /// a hard error rather than a silent drop, because dropping it turns every
    /// token signed by that key into a verification failure.
    pub fn load_or_generate(
        path: &Path,
        issuer: &str,
        now: Unix,
        known: &[SigningKeyRecord],
    ) -> anyhow::Result<Self> {
        let primary = if path.exists() {
            SigningKey::load(path, now)?
        } else {
            SigningKey::generate(path, now)?
        };
        let key_dir = path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let issuer = issuer.trim_end_matches('/').to_string();
        let access_aud = format!("{issuer}/api/v1");

        let mut keys = BTreeMap::new();
        let mut primary = primary;
        // The configured file has no lifecycle metadata of its own, so consult
        // the database for it too. Otherwise a key retired in the previous run
        // would come back active just because it sits at `signing_key_file`.
        if let Some(known) = known.iter().find(|row| row.kid == primary.record.kid) {
            primary.record.created_at = known.created_at;
            primary.record.activated_at = known.activated_at;
            primary.record.retired_at = known.retired_at;
        }
        keys.insert(primary.record.kid.clone(), primary);

        for record in known {
            if keys.contains_key(&record.kid) {
                continue;
            }
            let retired_path = key_dir.join(format!("{}.pem", record.kid));
            let mut key =
                SigningKey::load(&retired_path, record.created_at).with_context(|| {
                    format!(
                        "signing key {} is published but its private key is missing at {}",
                        record.kid,
                        retired_path.display()
                    )
                })?;
            if key.record.kid != record.kid {
                bail!(
                    "signing key file {} does not match its recorded kid {}",
                    retired_path.display(),
                    record.kid
                );
            }
            // The file holds key material only, so `load` stamps everything with
            // "now". The database is the authority on lifecycle: without this the
            // reload would resurrect retired keys and flatten `activated_at`,
            // making the active-key choice depend on iteration order.
            key.record.created_at = record.created_at;
            key.record.activated_at = record.activated_at;
            key.record.retired_at = record.retired_at;
            keys.insert(record.kid.clone(), key);
        }

        // Active is the newest key by `activated_at`, not necessarily the one at
        // `signing_key_file`. After a rotation the new key lives in its own
        // `{kid}.pem` and the configured path still holds the original, so
        // pinning active to the file would silently undo every rotation on the
        // next restart.
        //
        // A retired key is never active even if it is newest, which is what makes
        // `--retire-current` able to force a rollback.
        let active = keys
            .values()
            .filter(|key| key.record.retired_at.is_none())
            .max_by_key(|key| (key.record.activated_at, key.record.kid.clone()))
            .map(|key| key.record.kid.clone());

        Ok(Self {
            issuer,
            access_aud,
            keys: RwLock::new(keys),
            active: RwLock::new(active),
            key_dir,
        })
    }

    /// The record of the key currently used for signing, for publishing to the
    /// database.
    pub fn primary_record(&self) -> Option<SigningKeyRecord> {
        let active = self.active.read().ok()?.clone()?;
        let keys = self.keys.read().ok()?;
        keys.get(&active).map(|key| key.record.clone())
    }

    /// Every record that must appear in the JWKS, including retired ones.
    pub fn records(&self) -> Vec<SigningKeyRecord> {
        self.keys
            .read()
            .map(|keys| keys.values().map(|key| key.record.clone()).collect())
            .unwrap_or_default()
    }

    /// Publishes a new key and makes it the signing key, demoting the current one
    /// to verification-only.
    ///
    /// The old key is *not* removed: tokens it signed are still valid until they
    /// expire, and dropping it would break them mid-flight.
    pub fn rotate(&self, now: Unix) -> anyhow::Result<SigningKeyRecord> {
        // A fresh path per key; generating over the active file would destroy the
        // very key we are trying to keep verifying.
        let key = SigningKey::generate(&self.key_dir.join(format!("pending-{now}.pem")), now)?;
        let record = key.record.clone();
        // Rename to the kid-based path the loader expects on restart.
        let wanted = self.key_dir.join(format!("{}.pem", record.kid));
        let pending = self.key_dir.join(format!("pending-{now}.pem"));
        if wanted.exists() {
            bail!("refusing to reuse an existing signing key file");
        }
        fs::rename(&pending, &wanted)
            .with_context(|| format!("move new key into {}", wanted.display()))?;

        {
            let mut keys = self
                .keys
                .write()
                .map_err(|_| anyhow::anyhow!("signing key lock poisoned"))?;
            keys.insert(record.kid.clone(), key);
        }
        let previous = self
            .active
            .write()
            .map_err(|_| anyhow::anyhow!("active key lock poisoned"))?
            .replace(record.kid.clone());
        if let Some(kid) = previous
            && let Ok(mut keys) = self.keys.write()
            && let Some(key) = keys.get_mut(&kid)
        {
            key.record.retired_at = Some(now);
        }
        Ok(record)
    }

    fn active_key(&self) -> Re0Result<(String, Header, EncodingKey)> {
        let active = self
            .active
            .read()
            .map_err(|_| internal("active key lock poisoned"))?
            .clone()
            .ok_or_else(|| internal("no active signing key"))?;
        let keys = self
            .keys
            .read()
            .map_err(|_| internal("signing key lock poisoned"))?;
        let key = keys
            .get(&active)
            .ok_or_else(|| internal("active key is missing from the key set"))?;
        Ok((active, key.header(), key.encoding.clone()))
    }

    /// Picks the decoding key named by the token's `kid`.
    ///
    /// A token whose `kid` is unknown is rejected rather than tried against every
    /// key: signature verification is not a search problem.
    fn decoding_for(&self, token: &str) -> Re0Result<DecodingKey> {
        let kid = jsonwebtoken::decode_header(token)
            .map_err(internal)?
            .kid
            .ok_or_else(|| internal("token has no kid"))?;
        let keys = self
            .keys
            .read()
            .map_err(|_| internal("signing key lock poisoned"))?;
        keys.get(&kid)
            .map(|key| key.decoding.clone())
            .ok_or_else(|| internal(format!("unknown kid {kid}")))
    }
}

fn internal(error: impl std::fmt::Display) -> Re0Error {
    Re0Error::Internal(error.to_string())
}

const PKCS8_LABEL: &str = "PRIVATE KEY";

fn pkcs8_pem(der: &[u8]) -> String {
    // `EncodeConfig::new()` defaults to CRLF; these files are read on the same
    // host that wrote them, so LF keeps the bytes stable across platforms.
    pem::encode_config(
        &pem::Pem::new(PKCS8_LABEL, der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

/// Extracts the DER body of a PKCS#8 PEM document.
///
/// Deliberately narrow: a wrong label is rejected rather than decoded, because
/// feeding a PKCS#1 body to the PKCS#8 parser produces an error that names no
/// cause.
fn pem_body(pem: &str) -> anyhow::Result<Vec<u8>> {
    let document = pem::parse(pem).context("not a PEM document")?;
    if document.tag() != PKCS8_LABEL {
        anyhow::bail!(
            "found a {:?} PEM block, expected {PKCS8_LABEL:?}",
            document.tag()
        );
    }
    Ok(document.contents().to_vec())
}

impl TokenSigner for RsaTokenSigner {
    fn sign_access(&self, claims: &AccessTokenClaims) -> Re0Result<String> {
        let (_, header, encoding) = self.active_key()?;
        encode(&header, claims, &encoding).map_err(internal)
    }

    fn sign_id(&self, claims: &IdTokenClaims) -> Re0Result<String> {
        let (_, header, encoding) = self.active_key()?;
        encode(&header, claims, &encoding).map_err(internal)
    }

    fn sign_approval_ticket(&self, claims: &ApprovalTicketClaims) -> Re0Result<String> {
        let (_, header, encoding) = self.active_key()?;
        encode(&header, claims, &encoding).map_err(internal)
    }

    fn verify_access(&self, token: &str) -> Re0Result<AccessTokenClaims> {
        let decoding = self.decoding_for(token)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.access_aud.as_str()]);
        validation.validate_exp = true;
        let decoded =
            decode::<AccessTokenClaims>(token, &decoding, &validation).map_err(internal)?;
        // INV-TOKEN-01: access tokens and id_tokens are not interchangeable.
        if decoded.claims.token_use != ACCESS_TOKEN_USE {
            return Err(internal("wrong token use"));
        }
        if decoded.claims.sub.is_empty() {
            return Err(internal("missing subject"));
        }
        Ok(decoded.claims)
    }

    fn verify_approval_ticket(&self, token: &str) -> Re0Result<ApprovalTicketClaims> {
        let decoding = self.decoding_for(token)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.issuer.as_str()]);
        validation.validate_exp = true;
        let decoded =
            decode::<ApprovalTicketClaims>(token, &decoding, &validation).map_err(internal)?;
        if decoded.claims.token_use != APPROVAL_TICKET_USE {
            return Err(internal("wrong token use"));
        }
        if decoded.claims.sub.is_empty() || decoded.claims.user_code.is_empty() {
            return Err(internal("missing approval ticket claims"));
        }
        Ok(decoded.claims)
    }

    fn jwks(&self) -> String {
        // `JwkSet` is what verifiers parse into, so building it directly keeps
        // the served document in the same shape they expect. A record whose
        // stored JSON cannot be read is skipped rather than aborting the whole
        // set: one corrupt row must not take every key offline.
        let keys: Vec<Jwk> = self
            .records()
            .iter()
            .filter_map(|record| serde_json::from_str(&record.public_jwk_json).ok())
            .collect();
        let set = jsonwebtoken::jwk::JwkSet { keys };
        serde_json::to_string(&set).unwrap_or_else(|_| "{\"keys\":[]}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("re0auth-keys-{}", uuid::Uuid::now_v7()));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn key(&self) -> PathBuf {
            self.0.join("signing.pem")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn signer(dir: &TempDir) -> RsaTokenSigner {
        RsaTokenSigner::load_or_generate(&dir.key(), "https://auth.example.com", 1_000, &[])
            .expect("signer")
    }

    fn access_claims() -> AccessTokenClaims {
        AccessTokenClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user".to_string(),
            aud: "https://auth.example.com/api/v1".to_string(),
            client_id: "client".to_string(),
            scope: "openid".to_string(),
            exp: 4_000_000_000,
            iat: 1_000,
            jti: "jti".to_string(),
            token_use: ACCESS_TOKEN_USE.to_string(),
        }
    }

    #[test]
    fn access_tokens_verify_and_id_tokens_do_not() {
        let dir = TempDir::new();
        let signer = signer(&dir);
        let claims = access_claims();
        let token = signer.sign_access(&claims).expect("sign access");
        assert_eq!(signer.verify_access(&token).expect("verify access"), claims);

        let id = signer
            .sign_id(&IdTokenClaims {
                iss: "https://auth.example.com".to_string(),
                sub: "user".to_string(),
                aud: "client".to_string(),
                exp: 4_000_000_000,
                iat: 1_000,
                nonce: Some("nonce".to_string()),
            })
            .expect("sign id");
        assert!(signer.verify_access(&id).is_err());
        assert!(signer.jwks().contains("\"kid\""));
    }

    /// The served key set is parsed by clients, so every member they need has to
    /// be present and correctly named. This is the assertion the old hand-built
    /// JSON literal could not make: a typo there still produced valid JSON.
    #[test]
    fn the_published_jwk_carries_every_member_a_verifier_needs() {
        let dir = TempDir::new();
        let signer = signer(&dir);
        let jwks: jsonwebtoken::jwk::JwkSet =
            serde_json::from_str(&signer.jwks()).expect("jwks parses");
        let key = jwks.keys.first().expect("one key");

        assert_eq!(
            key.common.key_id.as_deref(),
            Some(signer.records()[0].kid.as_str())
        );
        assert_eq!(key.common.public_key_use, Some(PublicKeyUse::Signature));
        assert_eq!(
            key.common.key_algorithm,
            Some(Algorithm::RS256.into()),
            "alg must be present or clients cannot pick an algorithm"
        );
        match &key.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                assert_eq!(rsa.key_type, RSAKeyType::RSA);
                assert!(!rsa.n.is_empty(), "modulus is required");
                assert_eq!(rsa.e, "AQAB", "65537 is the exponent every RSA key uses");
            }
            other => panic!("expected RSA parameters, got {other:?}"),
        }
    }

    #[test]
    fn approval_tickets_do_not_verify_as_access_tokens() {
        let dir = TempDir::new();
        let signer = signer(&dir);
        let claims = ApprovalTicketClaims {
            iss: "https://auth.example.com".to_string(),
            sub: "user".to_string(),
            aud: "https://auth.example.com".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            exp: 4_000_000_000,
            iat: 1_000,
            jti: "ticket-jti".to_string(),
            token_use: APPROVAL_TICKET_USE.to_string(),
        };
        let token = signer
            .sign_approval_ticket(&claims)
            .expect("sign approval ticket");
        assert_eq!(
            signer
                .verify_approval_ticket(&token)
                .expect("verify approval ticket"),
            claims
        );
        assert!(signer.verify_access(&token).is_err());
    }

    #[test]
    fn a_rotated_key_still_verifies_tokens_from_the_old_one() {
        // This is the entire reason the key set exists. If rotation dropped the
        // old key, every token issued before it would fail mid-flight.
        let dir = TempDir::new();
        let signer = signer(&dir);
        let old_kid = signer.primary_record().expect("primary").kid;
        let old_token = signer.sign_access(&access_claims()).expect("sign");

        let new_record = signer.rotate(2_000).expect("rotate");
        assert_ne!(new_record.kid, old_kid, "a rotation must mint a new kid");

        let new_token = signer.sign_access(&access_claims()).expect("sign");
        assert_eq!(
            signer
                .verify_access(&old_token)
                .expect("old token must survive"),
            access_claims()
        );
        assert!(signer.verify_access(&new_token).is_ok());

        // Both public keys must be published, or a client checking the JWKS
        // cannot verify the old token either.
        let jwks = signer.jwks();
        assert!(jwks.contains(&new_record.kid), "new kid missing from JWKS");
        assert!(jwks.contains(&old_kid), "old kid missing from JWKS");
    }

    #[test]
    fn a_reloaded_signer_verifies_tokens_signed_before_the_restart() {
        let dir = TempDir::new();
        let first = signer(&dir);
        let token = first.sign_access(&access_claims()).expect("sign");
        let known = first.records();

        let reloaded =
            RsaTokenSigner::load_or_generate(&dir.key(), "https://auth.example.com", 2_000, &known)
                .expect("reload");
        assert!(reloaded.verify_access(&token).is_ok());
        assert_eq!(reloaded.records().len(), known.len());
    }

    #[test]
    fn a_rotation_survives_a_restart() {
        // The configured path still holds the original key after rotating, so a
        // signer that simply made the file's key active would undo the rotation
        // on every restart. The database decides which key is active.
        let dir = TempDir::new();
        let first = signer(&dir);
        let original = first.primary_record().expect("primary").kid;

        let rotated = first.rotate(2_000).expect("rotate");
        assert_ne!(rotated.kid, original);

        let known = first.records();
        let reloaded =
            RsaTokenSigner::load_or_generate(&dir.key(), "https://auth.example.com", 3_000, &known)
                .expect("reload");

        assert_eq!(
            reloaded.primary_record().expect("active").kid,
            rotated.kid,
            "the restart reverted the rotation"
        );
    }

    #[test]
    fn a_retired_key_is_never_chosen_as_active_after_a_restart() {
        // `retired_at` means "stopped being the signing key", not "gone": the key
        // stays in the JWKS so the tokens it signed keep verifying.
        let dir = TempDir::new();
        let first = signer(&dir);
        let rotated = first.rotate(2_000).expect("rotate");

        // Simulate a restart where the older key was explicitly retired too.
        let mut known = first.records();
        for row in &mut known {
            row.retired_at = Some(2_500);
        }
        let reloaded =
            RsaTokenSigner::load_or_generate(&dir.key(), "https://auth.example.com", 3_000, &known)
                .expect("reload");
        assert!(
            reloaded.primary_record().is_none(),
            "a retired key must not be chosen for signing"
        );
        // Retired keys remain published, so old tokens still verify.
        assert_eq!(reloaded.records().len(), 2);
        assert!(
            reloaded
                .records()
                .iter()
                .any(|record| record.kid == rotated.kid)
        );
    }

    #[test]
    fn rotation_demotes_the_previous_key_without_unpublishing_it() {
        let dir = TempDir::new();
        let first = signer(&dir);
        let original = first.primary_record().expect("primary").kid;
        let rotated = first.rotate(2_000).expect("rotate");

        let records = first.records();
        let old = records
            .iter()
            .find(|record| record.kid == original)
            .expect("old key still present");
        assert_eq!(old.retired_at, Some(2_000), "old key must be demoted");
        // Both are still in the JWKS; only one is used for signing.
        assert!(first.jwks().contains(&original));
        assert!(first.jwks().contains(&rotated.kid));
        assert_eq!(first.primary_record().expect("active").kid, rotated.kid);
    }

    #[test]
    fn a_published_key_without_its_private_file_is_a_hard_error() {
        // Silently continuing would make every token it signed unverifiable,
        // which looks like a wave of random authentication failures.
        let dir = TempDir::new();
        let first = signer(&dir);
        let mut known = first.records();
        known.push(SigningKeyRecord {
            kid: "deadbeefdeadbeef".to_string(),
            alg: "RS256".to_string(),
            public_jwk_json: "{}".to_string(),
            created_at: 1,
            activated_at: 1,
            retired_at: None,
        });
        let error =
            RsaTokenSigner::load_or_generate(&dir.key(), "https://auth.example.com", 2_000, &known)
                .expect_err("missing key file must fail");
        assert!(
            format!("{error:#}").contains("deadbeefdeadbeef"),
            "error must name the missing key: {error:#}"
        );
    }

    #[test]
    fn a_generated_key_file_is_pkcs8() {
        // The loader only accepts PKCS#8, so the writer must emit exactly that.
        // A mismatch here would generate a key the next start could not read.
        let dir = TempDir::new();
        signer(&dir);
        let pem = fs::read_to_string(dir.key()).expect("read key");
        assert!(
            pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "expected a PKCS#8 label, got: {}",
            pem.lines().next().unwrap_or_default()
        );
        assert!(pem.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn a_pkcs1_key_is_rejected_with_a_conversion_hint() {
        // PKCS#1 is the older RSA-only layout. Rejecting it is deliberate; the
        // point of this test is that the message says what to do about it,
        // because aws-lc-rs's own error names no cause.
        let dir = TempDir::new();
        let path = dir.key();
        fs::write(
            &path,
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n",
        )
        .expect("write pkcs1 key");
        let error = SigningKey::load(&path, 1_000).expect_err("pkcs1 must be rejected");
        let message = format!("{error:#}");
        assert!(
            message.contains("PKCS#8"),
            "error must name the required format: {message}"
        );
        assert!(
            message.contains("openssl pkcs8 -topk8"),
            "error must say how to convert: {message}"
        );
    }

    #[test]
    fn the_pem_label_is_matched_exactly() {
        // The load path wraps every failure from `pem_body` in the same
        // conversion hint, so a test through `load` cannot tell a rejected label
        // apart from rejected base64. This one targets the label check itself: a
        // `RSA PRIVATE KEY` body is well-formed base64 and would otherwise decode.
        let pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(
            pem_body(pkcs1).is_err(),
            "a PKCS#1 document must not pass the PKCS#8 label check"
        );

        let pkcs8 = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            pem_body(pkcs8).expect("separator matches the label"),
            vec![0u8; 3],
            "base64 must decode once the label matches"
        );
    }

    #[test]
    fn the_kid_is_derived_from_the_public_key_not_the_file_bytes() {
        // Same key written twice must yield the same kid; a kid that depended on
        // incidental PEM formatting would change on every regeneration.
        let dir = TempDir::new();
        let pem = fs::read_to_string({
            signer(&dir);
            dir.key()
        })
        .expect("read key");

        let second = TempDir::new();
        fs::write(second.key(), &pem).expect("copy key");
        let first_signer = SigningKey::load(&dir.key(), 1_000).expect("load first");
        let second_signer = SigningKey::load(&second.key(), 2_000).expect("load second");
        assert_eq!(first_signer.record.kid, second_signer.record.kid);
        // Lifecycle metadata is per-load, but the kid is not.
        assert_eq!(first_signer.record.created_at, 1_000);
        assert_eq!(second_signer.record.created_at, 2_000);
    }
}
