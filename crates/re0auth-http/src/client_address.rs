//! Derives the client address used for rate limiting and audit keys.
//!
//! INV-RATE-01: the peer address is the default key. `X-Forwarded-For` is only
//! consulted when the peer itself is a configured trusted proxy, and then only
//! its right-most hop is taken. Both halves matter:
//!
//! - Trusting XFF unconditionally lets any caller pick its own rate-limit bucket,
//!   which turns per-client limits into no limit at all.
//! - Taking the left-most hop would let a caller append a forged entry, because
//!   proxies prepend rather than rewrite.

use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

/// A parsed `trusted_proxies` entry: either a single address or a CIDR block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyRange {
    net: IpNet,
}

impl ProxyRange {
    /// Parses `10.0.0.5` or `10.0.0.0/8`. Returns `None` for anything else, so a
    /// typo cannot silently widen the trust set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        if value.contains('/') {
            return Some(Self {
                net: value.parse().ok()?,
            });
        }
        // A bare address is the one-entry range, which `IpNet` spells with a
        // full-length prefix.
        let address: IpAddr = value.parse().ok()?;
        let prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some(Self {
            net: IpNet::new(address, prefix).ok()?,
        })
    }

    /// Whether `address` falls inside the range.
    ///
    /// `ipnet` deliberately does not match across families, so the two mapped
    /// directions are handled here: a v4-mapped v6 peer is folded to its v4 form
    /// (otherwise `::ffff:10.0.0.1` would escape a `10.0.0.0/8` entry, which is
    /// the same range spelled differently), and a v4 peer is widened when the
    /// range is v6, so the configured prefix keeps its meaning.
    ///
    /// The same folding exists in `re0auth-runtime::outbound`, which this crate
    /// may not depend on (ADR-0026).
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.net, normalize(address)) {
            (IpNet::V4(net), IpAddr::V4(peer)) => net.contains(&peer),
            (IpNet::V6(net), IpAddr::V6(peer)) => net.contains(&peer),
            (IpNet::V6(net), IpAddr::V4(peer)) => net.contains(&peer.to_ipv6_mapped()),
            (IpNet::V4(_), IpAddr::V6(_)) => false,
        }
    }
}

fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => address,
    }
}

/// The address a request should be attributed to.
///
/// A malformed `X-Forwarded-For` from a trusted proxy falls back to the peer
/// address rather than erroring: a proxy bug should not fail user requests, and
/// falling back cannot be exploited because the peer is already trusted.
#[must_use]
pub fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &[ProxyRange]) -> String {
    if !trusted.iter().any(|range| range.contains(peer)) {
        return peer.to_string();
    }
    right_most_forwarded_for(headers)
        .filter(|candidate| !candidate.is_unspecified())
        .unwrap_or(peer)
        .to_string()
}

fn right_most_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let mut last = None;
    for value in headers.get_all("x-forwarded-for") {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for hop in text.split(',') {
            let hop = hop.trim();
            if hop.is_empty() {
                continue;
            }
            // Entries may carry a port, a quoted form, or an obfuscated token;
            // only well-formed addresses are considered.
            if let Some(address) = hop_address(hop) {
                last = Some(address);
            }
        }
    }
    last
}

/// The address a single forwarded hop names.
///
/// A v6 literal may arrive bracketed (`[::1]`) with or without a port; trimming
/// the brackets before the bare-address parse is what used to be missed — `[::1]`
/// has no colon to split on after the bracket, so the hop was silently dropped.
/// Dropping a hop falls back to the peer address, which is why this was wrong
/// rather than dangerous.
fn hop_address(hop: &str) -> Option<IpAddr> {
    let bare = hop.trim_matches('"');
    if let Ok(address) = bare.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Some(address);
    }
    // `host:port`, where the host may itself be a bracketed v6 literal.
    let (host, _port) = bare.rsplit_once(':')?;
    host.trim_matches(['[', ']']).parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().expect("value"));
        headers
    }

    #[test]
    fn parses_addresses_and_blocks() {
        assert!(ProxyRange::parse("10.0.0.1").is_some());
        assert!(ProxyRange::parse("10.0.0.0/8").is_some());
        assert!(ProxyRange::parse("2001:db8::/32").is_some());
        assert!(ProxyRange::parse("10.0.0.0/33").is_none());
        assert!(ProxyRange::parse("not-an-address").is_none());
        assert!(ProxyRange::parse("").is_none());
    }

    #[test]
    fn matches_inside_and_outside_the_block() {
        let range = ProxyRange::parse("10.0.0.0/8").expect("range");
        assert!(range.contains("10.1.2.3".parse().expect("ip")));
        assert!(!range.contains("11.0.0.1".parse().expect("ip")));
    }

    #[test]
    fn non_prefix_bits_do_not_match() {
        let range = ProxyRange::parse("10.0.0.0/24").expect("range");
        assert!(range.contains("10.0.0.200".parse().expect("ip")));
        assert!(!range.contains("10.0.1.1".parse().expect("ip")));
    }

    #[test]
    fn an_untrusted_peer_cannot_spoof_its_address() {
        // The whole point: a caller outside the trust set names itself, and the
        // forged header is ignored.
        let resolved = resolve(
            "203.0.113.9".parse().expect("ip"),
            &headers("1.2.3.4"),
            &[ProxyRange::parse("10.0.0.0/8").expect("range")],
        );
        assert_eq!(resolved, "203.0.113.9");
    }

    #[test]
    fn a_trusted_peer_uses_the_right_most_hop() {
        // A caller appends a forged hop on the left; proxies append on the right.
        let resolved = resolve(
            "10.0.0.5".parse().expect("ip"),
            &headers("1.2.3.4, 198.51.100.7"),
            &[ProxyRange::parse("10.0.0.0/8").expect("range")],
        );
        assert_eq!(resolved, "198.51.100.7");
    }

    #[test]
    fn a_malformed_forwarded_header_falls_back_to_the_peer() {
        let resolved = resolve(
            "10.0.0.5".parse().expect("ip"),
            &headers("unknown, also-unknown"),
            &[ProxyRange::parse("10.0.0.0/8").expect("range")],
        );
        assert_eq!(resolved, "10.0.0.5");
    }

    #[test]
    fn an_unspecified_forwarded_address_is_ignored() {
        // `0.0.0.0` would collapse every client into one bucket.
        let resolved = resolve(
            "10.0.0.5".parse().expect("ip"),
            &headers("0.0.0.0"),
            &[ProxyRange::parse("10.0.0.0/8").expect("range")],
        );
        assert_eq!(resolved, "10.0.0.5");
    }

    #[test]
    fn a_port_suffix_is_tolerated() {
        let resolved = resolve(
            "10.0.0.5".parse().expect("ip"),
            &headers("198.51.100.7:443"),
            &[ProxyRange::parse("10.0.0.0/8").expect("range")],
        );
        assert_eq!(resolved, "198.51.100.7");
    }

    #[test]
    fn multiple_headers_are_read_in_order() {
        let mut map = HeaderMap::new();
        map.append("x-forwarded-for", "1.2.3.4".parse().expect("v"));
        map.append("x-forwarded-for", "198.51.100.9".parse().expect("v"));
        let resolved = resolve(
            "10.0.0.5".parse().expect("ip"),
            &map,
            &[ProxyRange::parse("10.0.0.0/8").expect("range")],
        );
        assert_eq!(resolved, "198.51.100.9");
    }

    /// A v6 range compared against a real v4 peer used to slice 16 bytes out of
    /// a 4-byte array and panic. The two sides are now widened to v6 before the
    /// prefix comparison, so the configured prefix keeps its meaning: /120 is
    /// the v4 /24, and /128 is one host.
    #[test]
    fn a_v6_range_does_not_panic_on_a_v4_peer() {
        let block = ProxyRange::parse("::ffff:10.0.0.0/120").expect("range");
        assert!(block.contains("10.0.0.5".parse().expect("ip")));
        assert!(!block.contains("10.0.1.5".parse().expect("ip")));

        let host = ProxyRange::parse("::ffff:10.0.0.5/128").expect("range");
        assert!(host.contains("10.0.0.5".parse().expect("ip")));
        assert!(!host.contains("10.0.0.6".parse().expect("ip")));
    }

    /// The other direction: a v4 range against a mapped v6 peer.
    #[test]
    fn a_v4_range_matches_a_mapped_v6_peer() {
        let block = ProxyRange::parse("10.0.0.0/24").expect("range");
        assert!(block.contains("::ffff:10.0.0.5".parse().expect("ip")));
        assert!(!block.contains("::ffff:10.0.1.5".parse().expect("ip")));
    }

    /// A bracketed v6 hop needs no port to be readable. It used to be dropped,
    /// because `[::1]` neither parses as an address nor splits into host:port.
    #[test]
    fn a_bracketed_v6_hop_needs_no_port() {
        let trusted = [ProxyRange::parse("::1/128").expect("range")];
        assert_eq!(
            resolve("::1".parse().expect("ip"), &headers("[::1]"), &trusted),
            "::1"
        );
        assert_eq!(
            resolve(
                "2001:db8::9".parse().expect("peer inside the block"),
                &headers("[2001:db8::1]"),
                &[ProxyRange::parse("2001:db8::/32").expect("range")]
            ),
            "2001:db8::1"
        );
        // Port forms keep working, and a bare v6 without brackets is unchanged.
        assert_eq!(
            resolve("::1".parse().expect("ip"), &headers("[::1]:443"), &trusted),
            "::1"
        );
        assert_eq!(
            resolve("::1".parse().expect("ip"), &headers("::1"), &trusted),
            "::1"
        );
    }

    /// Families that are not mapped views of each other stay apart: an operator
    /// trusting `10.0.0.0/8` does not thereby trust every v6 peer.
    #[test]
    fn families_that_are_not_views_of_each_other_do_not_match() {
        let v4 = ProxyRange::parse("10.0.0.0/8").expect("range");
        assert!(!v4.contains("2001:db8::1".parse().expect("ip")));
        assert!(!v4.contains("::1".parse().expect("ip")));

        let v6 = ProxyRange::parse("2001:db8::/32").expect("range");
        assert!(!v6.contains("10.0.0.5".parse().expect("ip")));
    }

    /// Host bits in the configured entry are ignored rather than rejected: an
    /// operator writing `10.0.0.5/8` means the `10.0.0.0/8` block.
    #[test]
    fn host_bits_in_the_entry_do_not_change_the_block() {
        let range = ProxyRange::parse("10.1.2.3/8").expect("range");
        assert!(range.contains("10.9.9.9".parse().expect("ip")));
        assert!(!range.contains("11.0.0.1".parse().expect("ip")));
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        let host = ProxyRange::parse("192.0.2.7").expect("range");
        assert!(host.contains("192.0.2.7".parse().expect("ip")));
        assert!(!host.contains("192.0.2.8".parse().expect("ip")));
    }
}
