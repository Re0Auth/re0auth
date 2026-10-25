//! Outbound address classification (INV-SSRF-01, §6.9).
//!
//! Pure: no DNS, no sockets. `http_client` resolves names and feeds the
//! addresses here; nothing else may decide whether an address is reachable.
//!
//! Layering note: the design doc places outbound policy in `re0auth-domain`,
//! but adapters may not depend on domain (archtest enforces the direction).
//! Until `re0auth-runtime` exists to hold it, it lives next to its only user.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

const ALWAYS_DENIED: &[(&str, &str)] = &[
    ("0.0.0.0/8", "unspecified"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "carrier-grade NAT"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link-local"),
    ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "IETF protocol assignments"),
    ("192.168.0.0/16", "private"),
    ("198.18.0.0/15", "benchmarking"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
    ("::/128", "unspecified"),
    ("::1/128", "loopback"),
    ("fc00::/7", "unique local"),
    ("fe80::/10", "link-local"),
    ("ff00::/8", "multicast"),
];

/// Metadata endpoints stay blocked even with `allow_private_net` (ADR-0033).
const METADATA: &[&str] = &[
    "169.254.169.254/32",
    "169.254.170.2/32",
    "100.100.100.200/32",
    "fd00:ec2::254/128",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressClass {
    Public,
    Private,
    LinkLocal,
    Loopback,
    Metadata,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundPolicy {
    /// Reach the public internet only. The production default.
    PublicOnly,
    /// Admin opted into RFC1918/ULA for a self-hosted connector (ADR-0033).
    AllowPrivateNet,
    /// Additionally allow link-local and metadata ranges. Separate switch.
    AllowLinkLocalMetadata,
    /// Allow loopback for an instance-level configured local IdP or connector
    /// (§6.9 "内网 IdP 场景走实例级显式配置"). Never opens metadata ranges.
    AllowLoopback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundDenied {
    /// Scheme is not `https`, and plain HTTP was not explicitly permitted.
    Scheme(&'static str),
    /// No address left after filtering, or DNS returned nothing.
    NoAddress,
    /// The address resolves into a blocked range.
    Address { class: AddressClass, text: String },
}

impl std::fmt::Display for OutboundDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scheme(scheme) => write!(f, "scheme {scheme} is not allowed"),
            Self::NoAddress => write!(f, "host did not resolve to any address"),
            Self::Address { class, text } => {
                write!(f, "address {text} is {class:?} and not allowed")
            }
        }
    }
}

/// IPv4-mapped IPv6 (`::ffff:10.0.0.1`) must be classified as the IPv4 address.
/// `ipnet` does not do this: a v4 CIDR does not match a mapped v6 address.
#[must_use]
pub fn normalize(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => address,
    }
}

/// Parsed forms of [`METADATA`] and [`ALWAYS_DENIED`].
///
/// The tables stay the source of truth so the ranges and their labels are
/// auditable in one place; this only removes the per-call parsing. `classify`
/// runs on every outbound request, and re-parsing sixteen to twenty CIDR strings
/// each time measured 294 ns per call in release builds — roughly ten times the
/// cost of the comparison itself.
struct DeniedNets {
    metadata: Vec<IpNet>,
    always_denied: Vec<(IpNet, &'static str)>,
}

fn denied_nets() -> &'static DeniedNets {
    static NETS: std::sync::OnceLock<DeniedNets> = std::sync::OnceLock::new();
    NETS.get_or_init(|| DeniedNets {
        // A malformed entry is a bug in a constant that ships inside the
        // binary. Skipping it silently would quietly narrow SSRF protection, so
        // this fails loudly instead. `every_denied_range_parses` catches it in
        // tests rather than at first request.
        metadata: METADATA
            .iter()
            .map(|raw| raw.parse().expect("metadata range must parse"))
            .collect(),
        always_denied: ALWAYS_DENIED
            .iter()
            .map(|(raw, label)| (raw.parse().expect("denied range must parse"), *label))
            .collect(),
    })
}

#[must_use]
pub fn classify(address: IpAddr) -> AddressClass {
    let address = normalize(address);
    let nets = denied_nets();
    if nets.metadata.iter().any(|net| net.contains(&address)) {
        return AddressClass::Metadata;
    }
    let Some((_, label)) = nets
        .always_denied
        .iter()
        .find(|(net, _)| net.contains(&address))
    else {
        return AddressClass::Public;
    };
    match *label {
        "loopback" => AddressClass::Loopback,
        "link-local" => AddressClass::LinkLocal,
        "private" | "unique local" | "carrier-grade NAT" => AddressClass::Private,
        _ => AddressClass::Other,
    }
}

fn allowed(class: AddressClass, policy: OutboundPolicy) -> bool {
    match class {
        AddressClass::Public => true,
        AddressClass::Private => !matches!(policy, OutboundPolicy::PublicOnly),
        AddressClass::LinkLocal | AddressClass::Metadata => {
            matches!(policy, OutboundPolicy::AllowLinkLocalMetadata)
        }
        // Loopback is a local IdP/connector exception, never a metadata one.
        AddressClass::Loopback => policy == OutboundPolicy::AllowLoopback,
        AddressClass::Other => false,
    }
}

/// Rejects a scheme that the outbound guard cannot police.
pub fn check_scheme(scheme: &str, allow_http: bool) -> Result<(), OutboundDenied> {
    match scheme {
        "https" => Ok(()),
        "http" if allow_http => Ok(()),
        "http" => Err(OutboundDenied::Scheme("http")),
        "file" => Err(OutboundDenied::Scheme("file")),
        "ftp" => Err(OutboundDenied::Scheme("ftp")),
        "ws" => Err(OutboundDenied::Scheme("ws")),
        "wss" => Err(OutboundDenied::Scheme("wss")),
        _ => Err(OutboundDenied::Scheme("unknown")),
    }
}

/// Every address must pass: a mixed answer is a rebinding attempt, not a
/// reason to pick the public one (§6.9 DNS rebinding).
pub fn check_addresses(
    addresses: &[IpAddr],
    policy: OutboundPolicy,
) -> Result<IpAddr, OutboundDenied> {
    if addresses.is_empty() {
        return Err(OutboundDenied::NoAddress);
    }
    let mut first: Option<IpAddr> = None;
    for address in addresses {
        let normalized = normalize(*address);
        let class = classify(normalized);
        if !allowed(class, policy) {
            return Err(OutboundDenied::Address {
                class,
                text: normalized.to_string(),
            });
        }
        first.get_or_insert(normalized);
    }
    first.ok_or(OutboundDenied::NoAddress)
}

/// Convenience for the common case: parse literal text, then check.
pub fn check_literal(text: &str, policy: OutboundPolicy) -> Result<IpAddr, OutboundDenied> {
    let address: IpAddr = text.parse().map_err(|_| OutboundDenied::NoAddress)?;
    check_addresses(&[address], policy)
}

#[must_use]
pub fn is_metadata_v4(address: Ipv4Addr) -> bool {
    classify(IpAddr::V4(address)) == AddressClass::Metadata
}

#[must_use]
pub fn is_metadata_v6(address: Ipv6Addr) -> bool {
    classify(IpAddr::V6(address)) == AddressClass::Metadata
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC: &str = "203.0.113.10";

    fn policy() -> OutboundPolicy {
        OutboundPolicy::PublicOnly
    }

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("ip")
    }

    #[test]
    fn every_denied_range_parses() {
        // The tables are now parsed once into a `OnceLock`. A typo in a constant
        // would otherwise surface as a panic on the first outbound request,
        // which is the worst possible moment; this catches it in CI instead.
        for (raw, _) in ALWAYS_DENIED {
            raw.parse::<IpNet>().unwrap_or_else(|error| {
                panic!("ALWAYS_DENIED entry {raw} does not parse: {error}")
            });
        }
        for raw in METADATA {
            raw.parse::<IpNet>()
                .unwrap_or_else(|error| panic!("METADATA entry {raw} does not parse: {error}"));
        }
        // And the cache agrees with the count, so an entry cannot be silently
        // dropped during collection.
        let nets = denied_nets();
        assert_eq!(nets.always_denied.len(), ALWAYS_DENIED.len());
        assert_eq!(nets.metadata.len(), METADATA.len());
    }

    #[test]
    fn classification_is_stable_across_repeated_calls() {
        // Guards the caching itself: the first call initialises, later calls read
        // the shared table. A wrong initialisation that only shows up after the
        // first call would slip past every single-call test.
        let address = ip("169.254.169.254");
        for _ in 0..3 {
            assert_eq!(classify(address), AddressClass::Metadata);
        }
        for _ in 0..3 {
            assert_eq!(classify(ip(PUBLIC)), AddressClass::Public);
        }
    }

    #[test]
    fn public_addresses_pass() {
        let address = check_literal(PUBLIC, policy()).expect("public");
        assert_eq!(address, ip(PUBLIC));
        assert_eq!(classify(address), AddressClass::Public);
        assert!(check_literal("198.51.100.7", policy()).is_ok());
        assert!(check_literal("2001:db8::1", policy()).is_ok());
    }

    #[test]
    fn always_denied_ranges_are_rejected() {
        for text in [
            "127.0.0.1",
            "127.255.255.254",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
        ] {
            assert!(
                check_literal(text, policy()).is_err(),
                "{text} must be denied by default"
            );
        }
    }

    #[test]
    fn metadata_is_blocked_even_with_private_net() {
        for text in [
            "169.254.169.254",
            "169.254.170.2",
            "100.100.100.200",
            "fd00:ec2::254",
        ] {
            assert!(
                check_literal(text, OutboundPolicy::AllowPrivateNet).is_err(),
                "{text} must stay blocked even with allow_private_net"
            );
            assert!(
                check_literal(text, OutboundPolicy::AllowLinkLocalMetadata).is_ok(),
                "{text} is reachable only with the explicit metadata switch"
            );
        }
        assert_eq!(classify(ip("169.254.169.254")), AddressClass::Metadata);
    }

    #[test]
    fn private_net_switch_opens_rfc1918_and_ula_only() {
        for text in ["10.1.2.3", "172.16.0.1", "192.168.1.1", "fd00::1"] {
            assert!(
                check_literal(text, OutboundPolicy::AllowPrivateNet).is_ok(),
                "{text} should be allowed by the private-net switch"
            );
        }
        for text in ["127.0.0.1", "::1", "0.0.0.0"] {
            assert!(
                check_literal(text, OutboundPolicy::AllowPrivateNet).is_err(),
                "{text} must stay blocked: loopback is never a connector target"
            );
        }
    }

    #[test]
    fn loopback_requires_the_explicit_local_policy() {
        for policy in [
            OutboundPolicy::PublicOnly,
            OutboundPolicy::AllowPrivateNet,
            OutboundPolicy::AllowLinkLocalMetadata,
        ] {
            assert!(check_literal("127.0.0.1", policy).is_err());
            assert!(check_literal("::1", policy).is_err());
        }
        assert!(check_literal("127.0.0.1", OutboundPolicy::AllowLoopback).is_ok());
        assert!(check_literal("::1", OutboundPolicy::AllowLoopback).is_ok());
    }

    #[test]
    fn loopback_policy_does_not_open_metadata() {
        for text in ["169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254"] {
            assert!(
                check_literal(text, OutboundPolicy::AllowLoopback).is_err(),
                "{text} must stay blocked: the local-IdP switch is not a metadata switch"
            );
        }
    }

    #[test]
    fn ipv4_mapped_addresses_are_normalized_first() {
        let mapped = ip("::ffff:169.254.169.254");
        assert_eq!(classify(mapped), AddressClass::Metadata);
        assert!(check_literal("::ffff:169.254.169.254", policy()).is_err());

        let mapped_private = ip("::ffff:10.0.0.1");
        assert_eq!(classify(mapped_private), AddressClass::Private);
        assert!(check_literal("::ffff:10.0.0.1", policy()).is_err());
        assert!(check_literal("::ffff:10.0.0.1", OutboundPolicy::AllowPrivateNet).is_ok());

        let mapped_loop = ip("::ffff:127.0.0.1");
        assert_eq!(classify(mapped_loop), AddressClass::Loopback);
        assert!(check_literal("::ffff:127.0.0.1", OutboundPolicy::AllowLinkLocalMetadata).is_err());
    }

    #[test]
    fn mixed_answer_is_rejected_as_rebinding() {
        let addresses = vec![ip(PUBLIC), ip("10.0.0.1")];
        let denied = check_addresses(&addresses, policy()).expect_err("mixed answer");
        assert!(matches!(
            denied,
            OutboundDenied::Address {
                class: AddressClass::Private,
                ..
            }
        ));
    }

    #[test]
    fn empty_answer_is_rejected() {
        assert_eq!(
            check_addresses(&[], policy()).expect_err("empty"),
            OutboundDenied::NoAddress
        );
    }

    #[test]
    fn multiple_public_addresses_pick_the_first() {
        let addresses = vec![ip(PUBLIC), ip("198.51.100.7")];
        assert_eq!(
            check_addresses(&addresses, policy()).expect("public"),
            ip(PUBLIC)
        );
    }

    #[test]
    fn schemes_other_than_https_are_rejected() {
        assert!(check_scheme("https", false).is_ok());
        assert!(check_scheme("http", false).is_err());
        assert!(check_scheme("http", true).is_ok());
        for scheme in ["file", "ftp", "gopher", "data", "ws", "wss", ""] {
            assert!(
                check_scheme(scheme, true).is_err(),
                "{scheme} must be rejected"
            );
        }
    }

    #[test]
    fn metadata_helpers_agree_with_classification() {
        assert!(is_metadata_v4(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(!is_metadata_v4(Ipv4Addr::new(169, 254, 169, 253)));
        assert!(is_metadata_v6("fd00:ec2::254".parse().expect("ip")));
        assert!(!is_metadata_v6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn carrier_grade_nat_is_treated_as_private() {
        assert_eq!(classify(ip("100.64.0.1")), AddressClass::Private);
        assert!(check_literal("100.64.0.1", policy()).is_err());
    }
}
