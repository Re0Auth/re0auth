//! Master-key loading shared by every encrypting adapter.
//!
//! Two adapters derive keys from the same configured secret: the sub-credential
//! sealer (in `re0auth-adapters`) and the connector root-credential vault (in
//! `re0auth-connectors`). They must agree on the precedence rules — env over
//! file, exactly one source, never neither — or an operator who configures both
//! gets a different answer depending on which adapter starts first.
//!
//! The rules therefore live here, in infrastructure, rather than being copied
//! into both adapters. Neither side may depend on the other (ADR-0021), and a
//! duplicated rule is exactly the kind of thing that drifts silently.

use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

/// Resolves the master key from exactly one source.
///
/// `env_value` is the raw environment value (already read by the caller, so this
/// function stays testable without mutating process state). Blank is treated as
/// absent: an empty variable in a compose file means "not configured", not
/// "configure an empty key".
pub fn resolve_master_key(
    env_value: Option<String>,
    file: Option<&Path>,
) -> anyhow::Result<Zeroizing<String>> {
    let env_value = env_value.filter(|value| !value.trim().is_empty());
    match (env_value, file) {
        (Some(_), Some(_)) => anyhow::bail!(
            "both RE0AUTH_ENCRYPTION_KEY and crypto.master_key_file are set; configure exactly one"
        ),
        (Some(value), None) => Ok(Zeroizing::new(value)),
        (None, Some(path)) => read_key_file(path),
        (None, None) => anyhow::bail!(
            "no encryption key configured: set RE0AUTH_ENCRYPTION_KEY or crypto.master_key_file"
        ),
    }
}

/// Decodes a hex string into bytes, rejecting odd length and non-hex digits.
///
/// Returns `Zeroizing` because every caller decodes key material.
pub fn decode_hex(raw: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let bytes = hex::decode(raw.trim()).map_err(|error| match error {
        hex::FromHexError::OddLength => anyhow::anyhow!("encryption key hex has an odd length"),
        hex::FromHexError::InvalidHexCharacter { c, index } => {
            anyhow::anyhow!("encryption key hex has an invalid character {c:?} at position {index}")
        }
        _ => anyhow::anyhow!("encryption key is not valid hex"),
    })?;
    Ok(Zeroizing::new(bytes))
}

#[cfg_attr(not(unix), allow(dead_code))]
fn mode_is_private(mode: u32) -> bool {
    mode & 0o077 == 0
}

fn read_key_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;

        // Check the opened descriptor, not the path: a replacement between
        // metadata and read must not change which file we adopt.
        let mut file = fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|error| {
                anyhow::anyhow!("read encryption key file {}: {error}", path.display())
            })?;
        let metadata = file.metadata().map_err(|error| {
            anyhow::anyhow!("read encryption key file {}: {error}", path.display())
        })?;
        let mode = metadata.mode() & 0o777;
        if !mode_is_private(mode) {
            anyhow::bail!(
                "encryption key file {} must not be group/world accessible (mode {mode:o})",
                path.display()
            );
        }
        #[cfg(target_os = "linux")]
        {
            // /proc/self is owned by the effective UID on Linux. A key owned by
            // another user is not ours even when the mode happens to be 0600.
            if let Ok(proc) = fs::metadata("/proc/self")
                && metadata.uid() != proc.uid()
            {
                anyhow::bail!(
                    "encryption key file {} must be owned by the current user (uid {}, expected {})",
                    path.display(),
                    metadata.uid(),
                    proc.uid()
                );
            }
        }
        let mut content = Zeroizing::new(String::new());
        file.read_to_string(&mut content).map_err(|error| {
            anyhow::anyhow!("read encryption key file {}: {error}", path.display())
        })?;
        Ok(Zeroizing::new(content.trim().to_string()))
    }
    #[cfg(not(unix))]
    {
        // No stable ACL API: say so rather than implying the file is private.
        tracing::warn!(
            path = %path.display(),
            "file permissions are not verified on this platform; restrict the key file to the service account"
        );
        let content = fs::read_to_string(path).map_err(|error| {
            anyhow::anyhow!("read encryption key file {}: {error}", path.display())
        })?;
        Ok(Zeroizing::new(content.trim().to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn key_file() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("re0auth-key-{}.hex", uuid::Uuid::now_v7()));
        std::fs::write(&path, MASTER).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set key permissions");
        }
        path
    }

    #[test]
    fn exactly_one_source_is_allowed() {
        let file = key_file();
        assert!(resolve_master_key(Some(MASTER.to_string()), Some(&file)).is_err());
        assert!(resolve_master_key(Some(MASTER.to_string()), None).is_ok());
        assert!(resolve_master_key(None, Some(&file)).is_ok());
        assert!(resolve_master_key(None, None).is_err());
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn a_blank_env_value_counts_as_absent() {
        let file = key_file();
        assert_eq!(
            resolve_master_key(Some("   ".to_string()), Some(&file))
                .expect("file wins")
                .as_str(),
            MASTER
        );
        assert!(resolve_master_key(Some("".to_string()), None).is_err());
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn decode_hex_rejects_odd_and_non_hex() {
        assert_eq!(
            decode_hex("0f1e").expect("valid hex").as_slice(),
            &[0x0f, 0x1e]
        );
        assert!(decode_hex("abc").is_err(), "odd length");
        assert!(decode_hex("zz").is_err(), "non-hex digit");
    }

    #[test]
    fn key_modes_must_be_private() {
        assert!(mode_is_private(0o600));
        assert!(mode_is_private(0o400));
        assert!(!mode_is_private(0o640));
        assert!(!mode_is_private(0o604));
        assert!(!mode_is_private(0o777));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_key_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let file = key_file();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640))
            .expect("set permissive mode");
        let error = resolve_master_key(None, Some(&file)).expect_err("mode must be rejected");
        assert!(error.to_string().contains("group/world accessible"));
        let _ = std::fs::remove_file(file);
    }
}

#[cfg(all(test, not(unix)))]
mod s18_tests {
    use super::*;

    const MASTER: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    #[test]
    fn s18_non_unix_reads_the_key_despite_missing_acl_checks() {
        let path = std::env::temp_dir().join(format!("re0auth-key-{}.hex", uuid::Uuid::now_v7()));
        std::fs::write(&path, MASTER).expect("write key");
        let key = resolve_master_key(None, Some(&path)).expect("key file");
        assert_eq!(key.as_str(), MASTER);
        let _ = std::fs::remove_file(path);
    }
}
