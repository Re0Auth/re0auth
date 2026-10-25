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

/// Resolves the master key from exactly one source.
///
/// `env_value` is the raw environment value (already read by the caller, so this
/// function stays testable without mutating process state). Blank is treated as
/// absent: an empty variable in a compose file means "not configured", not
/// "configure an empty key".
pub fn resolve_master_key(
    env_value: Option<String>,
    file: Option<&Path>,
) -> anyhow::Result<String> {
    let env_value = env_value.filter(|value| !value.trim().is_empty());
    match (env_value, file) {
        (Some(_), Some(_)) => anyhow::bail!(
            "both RE0AUTH_ENCRYPTION_KEY and crypto.master_key_file are set; configure exactly one"
        ),
        (Some(value), None) => Ok(value),
        (None, Some(path)) => read_key_file(path),
        (None, None) => anyhow::bail!(
            "no encryption key configured: set RE0AUTH_ENCRYPTION_KEY or crypto.master_key_file"
        ),
    }
}

/// Decodes a hex string into bytes, rejecting odd length and non-hex digits.
pub fn decode_hex(raw: &str) -> anyhow::Result<Vec<u8>> {
    hex::decode(raw.trim()).map_err(|error| match error {
        hex::FromHexError::OddLength => anyhow::anyhow!("encryption key hex has an odd length"),
        hex::FromHexError::InvalidHexCharacter { c, index } => {
            anyhow::anyhow!("encryption key hex has an invalid character {c:?} at position {index}")
        }
        _ => anyhow::anyhow!("encryption key is not valid hex"),
    })
}

fn read_key_file(path: &Path) -> anyhow::Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path).map_err(|error| {
            anyhow::anyhow!("read encryption key file {}: {error}", path.display())
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "encryption key file {} must not be group/world accessible (mode {mode:o})",
                path.display()
            );
        }
    }
    let content = fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("read encryption key file {}: {error}", path.display()))?;
    Ok(content.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn key_file() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("re0auth-key-{}.hex", uuid::Uuid::now_v7()));
        std::fs::write(&path, MASTER).expect("write key");
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
            resolve_master_key(Some("   ".to_string()), Some(&file)).expect("file wins"),
            MASTER
        );
        assert!(resolve_master_key(Some("".to_string()), None).is_err());
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn decode_hex_rejects_odd_and_non_hex() {
        assert_eq!(decode_hex("0f1e").expect("valid hex"), vec![0x0f, 0x1e]);
        assert!(decode_hex("abc").is_err(), "odd length");
        assert!(decode_hex("zz").is_err(), "non-hex digit");
    }
}
