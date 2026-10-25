//! Where an SQLite URL points on disk.
//!
//! The `sqlite:` URL has its own grammar — `sqlite::memory:`,
//! `sqlite://?mode=memory`, query parameters, percent-encoded file names — and
//! `sqlx` is the crate that decides what it means. A hand-written
//! `strip_prefix("sqlite://") + split('?')` read the simple case correctly and
//! misread a percent-encoded name, which is how two strings naming one file
//! stopped being equal (ADR-0039's check is a comparison, so a missed decode is
//! a missed collision).

use std::path::{Path, PathBuf};
use std::str::FromStr;

/// The file an SQLite URL names, or `None` when it names a memory database or is
/// not an SQLite URL at all.
///
/// `None` is not an error: there is no file for a memory database to collide
/// with.
#[must_use]
pub fn database_file_path(url: &str) -> Option<PathBuf> {
    // `sqlx` only strips the `sqlite:` prefixes and would otherwise take the whole
    // string as a file name, so the scheme has to be checked here.
    if !url.starts_with("sqlite:") {
        return None;
    }
    let options = sqlx::sqlite::SqliteConnectOptions::from_str(url).ok()?;
    let filename = options.get_filename();
    if is_in_memory(filename) {
        return None;
    }
    Some(filename.to_path_buf())
}

/// `sqlx` reports a memory database as either an empty name or a `file:` pseudo
/// name that no filesystem has. `pins_the_memory_spellings` checks the shapes
/// `sqlx` produces, so an upgrade that renames them fails there rather than
/// silently turning a memory database into a file.
fn is_in_memory(filename: &Path) -> bool {
    filename.as_os_str().is_empty() || filename.to_string_lossy().starts_with("file:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_url_yields_the_file() {
        assert_eq!(
            database_file_path("sqlite://data/re0auth.db"),
            Some(PathBuf::from("data/re0auth.db"))
        );
        assert_eq!(
            database_file_path("sqlite:///var/lib/re0auth.db"),
            Some(PathBuf::from("/var/lib/re0auth.db"))
        );
    }

    /// Query parameters select a mode, not a different file.
    #[test]
    fn query_parameters_do_not_change_the_file() {
        assert_eq!(
            database_file_path("sqlite://data/re0auth.db?mode=ro&cache=shared"),
            Some(PathBuf::from("data/re0auth.db"))
        );
    }

    /// `sqlx` percent-decodes the name, so `%20` and a space are one file.
    #[test]
    fn a_percent_encoded_name_is_decoded() {
        assert_eq!(
            database_file_path("sqlite://data/re0auth%20copy.db"),
            Some(PathBuf::from("data/re0auth copy.db"))
        );
    }

    /// Every spelling of "no file" has to be recognised, or the vault guard would
    /// compare against a name that only exists in `sqlx`'s head.
    #[test]
    fn pins_the_memory_spellings() {
        for url in [
            "sqlite::memory:",
            "sqlite://:memory:",
            "sqlite://?mode=memory",
            "sqlite://?mode=memory&cache=private",
        ] {
            assert_eq!(database_file_path(url), None, "{url}");
        }
    }

    #[test]
    fn a_url_that_does_not_parse_has_no_file() {
        assert_eq!(database_file_path("postgres://localhost/re0auth"), None);
        assert_eq!(database_file_path(""), None);
        assert_eq!(database_file_path("not a url"), None);
    }
}
