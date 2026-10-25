//! Re-wrapping stored credentials onto the current master key (ADR-0042).
//!
//! The work is small because the payload is not touched: each record's DEK is
//! unwrapped under the retired key and wrapped again under the current one. The
//! interesting parts are the edges — an empty store, a record that moved on
//! mid-scan, and a key the operator forgot to declare — because each of them
//! silently reads as success if it is not handled.

use re0auth_api::ports::Storage;
use re0auth_api::secret::SecretSealer;
use re0auth_api::{BindingId, Re0Error, Re0Result, Unix};

/// How many records to read per page. Small enough that a rotation over a large
/// store does not hold a whole table in memory, large enough that the per-page
/// query is not the cost.
const PAGE: u32 = 128;

/// What a rotation did, in terms an operator can act on.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RotationReport {
    /// Records that were on an older key and are now on the current one.
    pub rewrapped: u64,
    /// Records already on the current key. They still had to be read.
    pub already_current: u64,
    /// Records that changed between being read and being swapped. Not an error:
    /// another rotation, or a fresh enrolment, got there first.
    pub moved_on: u64,
    /// Records that could not be rewrapped, with the reason. Any non-zero value
    /// means the retired key must stay configured.
    pub failed: Vec<(BindingId, String)>,
    /// Whether the store held no credentials at all.
    pub empty: bool,
}

impl RotationReport {
    /// Whether an operator may drop the retired key from the configuration.
    ///
    /// An empty store is deliberately *not* a clean result. Read from outside an
    /// empty rotation is indistinguishable from a finished one (`rewrapped = 0`,
    /// `failed = 0`), and an operator who deletes the old key on that reading
    /// loses the ability to open every record the moment one appears.
    pub fn is_clean(&self) -> bool {
        !self.empty && self.failed.is_empty()
    }

    /// The line an operator sees. Never claims success on its own.
    pub fn summary(&self) -> String {
        if self.empty {
            return "no sub-credentials exist: nothing was rotated, so the retired key \
                    cannot be dropped on this result"
                .to_string();
        }
        format!(
            "rewrapped={} already_current={} moved_on={} failed={}",
            self.rewrapped,
            self.already_current,
            self.moved_on,
            self.failed.len()
        )
    }
}

/// Re-wraps every stored credential onto the sealer's current key.
///
/// `sealer` must hold both the current key and every retired key the store
/// actually uses; an unknown version surfaces as a failed record rather than
/// being skipped, because a skipped record is one the operator will believe is
/// migrated.
pub async fn rotate_credentials(
    storage: &dyn Storage,
    sealer: &dyn SecretSealer,
    now: Unix,
) -> Re0Result<RotationReport> {
    let repo = storage.bindings();
    let mut report = RotationReport::default();
    let mut cursor: Option<BindingId> = None;
    let mut seen_any = false;

    loop {
        let page = repo
            .scan_sub_credentials(cursor.as_ref(), PAGE)
            .await
            .map_err(|error| Re0Error::Internal(format!("scan sub-credentials: {error}")))?;
        if page.is_empty() {
            break;
        }
        seen_any = true;
        let last = page.last().map(|(id, _)| *id);
        for (binding, sealed) in page {
            match sealer.rewrap(&binding, &sealed) {
                Ok(rewrapped) => {
                    if rewrapped.key_version() == sealed.key_version() {
                        report.already_current += 1;
                        continue;
                    }
                    // A miss here means someone else wrote the row between the
                    // scan and this swap. The new value is authoritative, so this
                    // is not a failure — the next rotation will pick it up.
                    let swapped = repo
                        .rewrap_sub_credential(&binding, &sealed, &rewrapped, now)
                        .await
                        .map_err(|error| {
                            Re0Error::Internal(format!("rewrap sub-credential: {error}"))
                        })?;
                    if swapped {
                        report.rewrapped += 1;
                    } else {
                        report.moved_on += 1;
                    }
                }
                Err(error) => {
                    // Keep going: one unreadable record must not strand the rest.
                    // The version is the operator's to declare, and the count is
                    // what tells them to do it. `re0auth-app` carries no `tracing`
                    // dependency, so the reason is returned rather than logged.
                    report.failed.push((binding, error.to_string()));
                }
            }
        }
        match last {
            Some(id) => cursor = Some(id),
            None => break,
        }
    }

    report.empty = !seen_any;
    Ok(report)
}
