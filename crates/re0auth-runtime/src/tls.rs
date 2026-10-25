//! TLS trust configuration for outbound traffic (§6.9, ADR-0036).
//!
//! The trust store is Mozilla's static bundle; host system trust is never read.
//! An operator may *append* a private CA (for an internal IdP), never replace
//! the bundle. A bad path or unparsable PEM fails at startup — silently falling
//! back to "Mozilla only" would hide a misconfiguration that looks like an
//! outage.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use rustls::RootCertStore;
use rustls::client::ClientConfig;
use rustls_pki_types::pem::PemObject;

/// Marker shown in startup logs: how many roots came from where.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustSummary {
    pub mozilla_roots: usize,
    pub extra_roots: usize,
}

impl TrustSummary {
    #[must_use]
    pub fn total(self) -> usize {
        self.mozilla_roots + self.extra_roots
    }
}

#[derive(Clone, Debug)]
pub struct TlsConfig {
    extra_ca_pem: Option<Vec<u8>>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::mozilla_only()
    }
}

impl TlsConfig {
    #[must_use]
    pub fn mozilla_only() -> Self {
        Self { extra_ca_pem: None }
    }

    /// Appends PEM-encoded CA certificates on top of the Mozilla bundle.
    pub fn with_extra_ca_pem(mut self, pem: Vec<u8>) -> Self {
        self.extra_ca_pem = Some(pem);
        self
    }

    /// `SSL_CERT_FILE`-compatible: read the file, never silently ignore it.
    pub fn with_extra_ca_file(self, path: &Path) -> anyhow::Result<Self> {
        let pem = std::fs::read(path)
            .with_context(|| format!("read extra CA bundle {}", path.display()))?;
        Ok(self.with_extra_ca_pem(pem))
    }

    /// Builds the rustls config used by `GuardedClient`.
    pub fn build(&self) -> anyhow::Result<(ClientConfig, TrustSummary)> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mozilla_roots = roots.len();

        let extra_roots = match &self.extra_ca_pem {
            None => 0,
            Some(pem) => append_pem(&mut roots, pem)?,
        };

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .context("select rustls protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok((
            config,
            TrustSummary {
                mozilla_roots,
                extra_roots,
            },
        ))
    }
}

/// Returns how many certificates were added. Zero certificates in a non-empty
/// file is an error: the operator asked for a CA and got nothing.
fn append_pem(roots: &mut RootCertStore, pem: &[u8]) -> anyhow::Result<usize> {
    // CA certificates are public material; no zeroization needed.
    // `rustls-pki-types` owns the PEM parser; `rustls-pemfile` is unmaintained
    // (RUSTSEC-2025-0134).
    let mut added = 0;
    for item in rustls_pki_types::CertificateDer::pem_slice_iter(pem) {
        let cert = item.context("parse extra CA certificate")?;
        roots
            .add(cert)
            .context("extra CA certificate is not a valid root")?;
        added += 1;
    }
    if added == 0 {
        bail!("extra CA bundle contained no certificates");
    }
    Ok(added)
}

/// One-line description for startup logs (§6.9 requires an audit trail).
pub struct TrustSummaryDisplay<'a>(pub &'a TrustSummary);

impl std::fmt::Display for TrustSummaryDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tls trust: {} Mozilla roots, {} extra CA roots",
            self.0.mozilla_roots, self.0.extra_roots
        )
    }
}

impl TrustSummary {
    #[must_use]
    pub fn describe(&self) -> TrustSummaryDisplay<'_> {
        TrustSummaryDisplay(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mozilla_bundle_is_loaded() {
        let (config, summary) = TlsConfig::mozilla_only().build().expect("tls config");
        assert!(
            summary.mozilla_roots > 100,
            "expected the full Mozilla bundle, got {}",
            summary.mozilla_roots
        );
        assert_eq!(summary.extra_roots, 0);
        assert_eq!(summary.total(), summary.mozilla_roots);
        assert!(Arc::strong_count(&Arc::new(config)) > 0);
    }

    #[test]
    fn missing_extra_ca_file_is_an_error() {
        let missing = std::env::temp_dir().join("re0auth-missing-ca-does-not-exist.pem");
        let _ = std::fs::remove_file(&missing);
        let error = TlsConfig::mozilla_only()
            .with_extra_ca_file(&missing)
            .expect_err("a missing CA path must fail, not fall back");
        assert!(error.to_string().contains("read extra CA bundle"));
    }

    #[test]
    fn empty_pem_file_is_an_error() {
        let path =
            std::env::temp_dir().join(format!("re0auth-empty-ca-{}.pem", uuid::Uuid::now_v7()));
        std::fs::write(&path, b"").expect("write");
        let config = TlsConfig::mozilla_only()
            .with_extra_ca_file(&path)
            .expect("file reads");
        let error = config.build().expect_err("no certificates must fail");
        assert!(
            error.to_string().contains("no certificates"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn garbage_pem_is_an_error() {
        let config = TlsConfig::mozilla_only().with_extra_ca_pem(
            b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n".to_vec(),
        );
        assert!(config.build().is_err());
    }

    #[test]
    fn trust_summary_reports_both_sources() {
        let summary = TrustSummary {
            mozilla_roots: 121,
            extra_roots: 2,
        };
        assert_eq!(summary.total(), 123);
        assert_eq!(
            summary.describe().to_string(),
            "tls trust: 121 Mozilla roots, 2 extra CA roots"
        );
    }
}
