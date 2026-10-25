//! Connector-owned vault for upstream root credentials (INV-CONN-02).
//!
//! Default backend per ADR-0039: a standalone file encrypted with AES-256-GCM,
//! keyed by HKDF from `RE0AUTH_ENCRYPTION_KEY` under its own info string. The
//! file is deliberately separate from the core SQLite database; callers pass
//! the path and `validate` refuses a path that collides with the database.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use re0auth_api::connector::ConnectorSecretStore;
use re0auth_api::{Random, Re0Error, Re0Result, SecretString};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// Distinct from `re0auth/sub-credential` and `re0auth/client-secret-pepper`:
/// a key leaked from one derivation must not open another's ciphertext.
const HKDF_INFO: &[u8] = b"re0auth/connector-root";
/// Written by `put`; `get` accepts any version it can derive a key for, so a
/// rotation only needs the old key kept alongside the new one.
pub const CURRENT_KEY_VERSION: u32 = 1;
const FILE_VERSION: u32 = 1;

type Nonce12 = Nonce<<Aes256Gcm as AeadCore>::NonceSize>;

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    version: u32,
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    key_version: u32,
    nonce: String,
    ciphertext: String,
}

pub struct EncryptedFileSecretStore {
    path: PathBuf,
    master: Zeroizing<[u8; KEY_LEN]>,
    random: Arc<dyn Random>,
    /// Serializes read-modify-write cycles: two concurrent `put` calls would
    /// otherwise both read the old map and one entry would be lost.
    gate: tokio::sync::Mutex<()>,
}

impl EncryptedFileSecretStore {
    /// `master_hex` is the raw key resolved once at startup. The file is
    /// created lazily on the first `put`, so an instance that stores nothing
    /// does not need a writable path.
    pub fn new(
        path: impl Into<PathBuf>,
        master_hex: &str,
        random: Arc<dyn Random>,
    ) -> anyhow::Result<Self> {
        let bytes = re0auth_runtime::master_key::decode_hex(master_hex.trim())?;
        if bytes.len() != KEY_LEN {
            anyhow::bail!(
                "connector secret encryption key must be {KEY_LEN} bytes ({} hex chars), got {}",
                KEY_LEN * 2,
                bytes.len()
            );
        }
        let mut master = Zeroizing::new([0u8; KEY_LEN]);
        master.copy_from_slice(&bytes);
        Ok(Self {
            path: path.into(),
            master,
            random,
            gate: tokio::sync::Mutex::new(()),
        })
    }

    /// Same key resolution as the sub-credential sealer: env or file, exactly one.
    pub fn from_env_or_file(
        path: impl Into<PathBuf>,
        master_key_file: Option<&Path>,
        random: Arc<dyn Random>,
    ) -> anyhow::Result<Self> {
        let master = re0auth_runtime::master_key::resolve_master_key(
            std::env::var("RE0AUTH_ENCRYPTION_KEY").ok(),
            master_key_file,
        )?;
        Self::new(path, &master, random)
    }

    /// Refuses a vault path that resolves to the same file as the core database
    /// (ADR-0039). Sharing a file would put root credentials inside the database
    /// file that operators back up and copy around.
    ///
    /// The core database is passed as a path rather than as a URL: resolving a
    /// `sqlite:` URL is `re0auth_adapters::sqlite_path`'s job, and this crate may
    /// not depend on that adapter (ADR-0021).
    pub fn reject_core_database_path(&self, core_database: Option<&Path>) -> anyhow::Result<()> {
        let Some(database_path) = core_database else {
            return Ok(());
        };
        let vault = normalize(&self.path)?;
        let database = normalize(database_path)?;
        if vault == database {
            anyhow::bail!(
                "connector secret file {} must not be the core database; use a separate path",
                self.path.display()
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn derive(&self, key_version: u32) -> Re0Result<Zeroizing<[u8; KEY_LEN]>> {
        let hkdf = Hkdf::<Sha256>::new(None, self.master.as_ref());
        let mut info = Vec::with_capacity(HKDF_INFO.len() + 4);
        info.extend_from_slice(HKDF_INFO);
        info.extend_from_slice(&key_version.to_be_bytes());
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hkdf.expand(&info, key.as_mut())
            .map_err(|_| internal("hkdf expand failed"))?;
        Ok(key)
    }

    fn cipher(&self, key_version: u32) -> Re0Result<Aes256Gcm> {
        let key = self.derive(key_version)?;
        Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| internal("invalid AES-256 key"))
    }

    /// A missing file is an empty vault, not an error: nothing has been stored
    /// yet. A present but unreadable file is an error — silently treating a
    /// corrupt vault as empty would make the next write destroy its contents.
    fn load(&self) -> Re0Result<Envelope> {
        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Envelope {
                    version: FILE_VERSION,
                    entries: BTreeMap::new(),
                });
            }
            Err(error) => {
                return Err(internal(&format!(
                    "read connector secret file {}: {error}",
                    self.path.display()
                )));
            }
        };
        if raw.is_empty() {
            return Ok(Envelope {
                version: FILE_VERSION,
                entries: BTreeMap::new(),
            });
        }
        let envelope: Envelope = serde_json::from_slice(&raw).map_err(|error| {
            internal(&format!(
                "connector secret file {} is not valid JSON: {error}",
                self.path.display()
            ))
        })?;
        if envelope.version != FILE_VERSION {
            return Err(internal(&format!(
                "connector secret file version {} is not supported",
                envelope.version
            )));
        }
        Ok(envelope)
    }

    /// Writes to a sibling temp file and renames, so a crash mid-write cannot
    /// leave a half-written vault. The temp file is created `0600` on unix.
    fn store(&self, envelope: &Envelope) -> Re0Result<()> {
        let bytes = serde_json::to_vec_pretty(envelope)
            .map_err(|_| internal("serialize connector secret file"))?;
        let temp = self.path.with_extension("tmp");
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| internal(&format!("create {}: {error}", parent.display())))?;
        }
        write_private(&temp, &bytes)?;
        fs::rename(&temp, &self.path).map_err(|error| {
            let _ = fs::remove_file(&temp);
            internal(&format!(
                "replace connector secret file {}: {error}",
                self.path.display()
            ))
        })?;
        Ok(())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Re0Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| internal(&format!("open {}: {error}", path.display())))?;
    file.write_all(bytes)
        .map_err(|error| internal(&format!("write {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| internal(&format!("sync {}: {error}", path.display())))
}

fn aad(key: &str) -> &[u8] {
    key.as_bytes()
}

/// Compares canonicalized paths where possible; falls back to the absolute form
/// because the vault may not exist yet.
fn normalize(path: &Path) -> anyhow::Result<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    Ok(base.join(path.file_name().unwrap_or_default()))
}

fn internal(message: &str) -> Re0Error {
    Re0Error::Internal(message.to_string())
}

#[async_trait::async_trait]
impl ConnectorSecretStore for EncryptedFileSecretStore {
    async fn put(&self, key: &str, secret: &SecretString) -> Re0Result<()> {
        let _guard = self.gate.lock().await;
        let cipher = self.cipher(CURRENT_KEY_VERSION)?;
        let nonce_bytes = self.random.bytes(NONCE_LEN);
        if nonce_bytes.len() != NONCE_LEN {
            return Err(internal("random source returned a short nonce"));
        }
        let nonce: [u8; NONCE_LEN] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| internal("nonce must be 12 bytes"))?;
        let ciphertext = cipher
            .encrypt(
                &Nonce12::from(nonce),
                Payload {
                    msg: secret.expose_secret().as_bytes(),
                    aad: aad(key),
                },
            )
            .map_err(|_| internal("seal connector secret failed"))?;

        let mut envelope = self.load()?;
        envelope.entries.insert(
            key.to_string(),
            Entry {
                key_version: CURRENT_KEY_VERSION,
                nonce: BASE64.encode(nonce),
                ciphertext: BASE64.encode(ciphertext),
            },
        );
        self.store(&envelope)
    }

    async fn get(&self, key: &str) -> Re0Result<Option<SecretString>> {
        let _guard = self.gate.lock().await;
        let envelope = self.load()?;
        let Some(entry) = envelope.entries.get(key) else {
            return Ok(None);
        };
        let cipher = self.cipher(entry.key_version)?;
        let nonce_bytes = BASE64
            .decode(&entry.nonce)
            .map_err(|_| internal("connector secret nonce is not base64"))?;
        let nonce: [u8; NONCE_LEN] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| internal("connector secret nonce must be 12 bytes"))?;
        let ciphertext = BASE64
            .decode(&entry.ciphertext)
            .map_err(|_| internal("connector secret ciphertext is not base64"))?;
        let plaintext = cipher
            .decrypt(
                &Nonce12::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: aad(key),
                },
            )
            .map_err(|_| internal("connector secret failed authentication"))?;
        let text =
            String::from_utf8(plaintext).map_err(|_| internal("connector secret is not UTF-8"))?;
        Ok(Some(SecretString::from(text)))
    }

    async fn delete(&self, key: &str) -> Re0Result<()> {
        let _guard = self.gate.lock().await;
        let mut envelope = self.load()?;
        if envelope.entries.remove(key).is_none() {
            return Ok(());
        }
        self.store(&envelope)
    }
}
