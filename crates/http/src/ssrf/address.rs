//! The public-address policy: the one place that decides whether a guarded
//! fetch may connect to an IP address.
//!
//! Hand-written because `IpAddr::is_global` is still unstable, and written
//! from the registries rather than from Python's `ipaddress` flags, which
//! disagree with them in both directions (see [`is_public_address`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The GCP metadata server. Inside `169.254.0.0/16` already; named on its own
/// so that no edit to the link-local row can ever reopen it.
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// IPv4 blocks a fetch may never reach, from the IANA IPv4 Special-Purpose
/// Address Registry (rows whose "Globally Reachable" is False or blank) plus
/// the multicast block, which lives in a registry of its own. More-specific
/// registry rows inside a block listed here are covered by it and not
/// repeated.
const DENIED_V4: &[(Ipv4Addr, u8)] = &[
    // "This network" (RFC 791); includes 0.0.0.0/32 "This host on this network".
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    // Private-Use (RFC 1918).
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    // Shared Address Space, i.e. carrier-grade NAT (RFC 6598).
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    // Loopback (RFC 1122).
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    // Link Local (RFC 3927), where cloud metadata servers live.
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    // Private-Use (RFC 1918).
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    // IETF Protocol Assignments (RFC 6890), the WHOLE /24: its globally
    // reachable more-specifics (192.0.0.9 PCP anycast, 192.0.0.10 TURN
    // anycast) are protocol anycast addresses, never a fetch target.
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    // Documentation TEST-NET-1 (RFC 5737).
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    // Deprecated 6to4 Relay Anycast (RFC 7526; terminated, no reachability
    // given), including the 6a44 relay 192.88.99.2/32 (not reachable).
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    // Private-Use (RFC 1918).
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    // Benchmarking (RFC 2544).
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    // Documentation TEST-NET-2 (RFC 5737).
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    // Documentation TEST-NET-3 (RFC 5737).
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    // Multicast (RFC 5771; the IANA IPv4 Multicast Address Space Registry).
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    // Reserved for future use (RFC 1112), including Limited Broadcast
    // 255.255.255.255/32 (RFC 919).
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// Global Unicast (the IANA IPv6 Address Space registry): the only IPv6
/// space IANA allocates public unicast from. Everything outside it is
/// reserved, unique-local, link-local, site-local, multicast or a special
/// purpose that is not globally reachable, and is denied by this one rule.
const GLOBAL_UNICAST_V6: (Ipv6Addr, u8) = (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);

/// IPv6 blocks inside [`GLOBAL_UNICAST_V6`] a fetch may never reach, from the
/// IANA IPv6 Special-Purpose Address Registry.
const DENIED_V6: &[(Ipv6Addr, u8)] = &[
    // IETF Protocol Assignments (RFC 2928), the WHOLE /23: Teredo
    // 2001::/32 (reachability N/A: it tunnels to an obfuscated IPv4),
    // Benchmarking 2001:2::/48, the deprecated ORCHID 2001:10::/28, and the
    // globally reachable more-specifics too — PCP/TURN/DNS-SD anycast
    // (2001:1::1-3), AMT (2001:3::/32), AS112 (2001:4:112::/48), ORCHIDv2
    // (2001:20::/28) and drone IDs (2001:30::/28) — none of which serves a
    // resource a fetch has any business with.
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    // Documentation (RFC 3849).
    (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
    // 6to4 (RFC 3056). Reachability N/A; denied outright rather than
    // unwrapped: the embedded IPv4 names a relay router, not the host the
    // packet is for, and the mechanism is long deprecated.
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    // Documentation (RFC 9637).
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
];

/// Whether a guarded fetch may connect to `ip` — the policy
/// [`fetch_public`](super::fetch_public) applies to IP-literal hosts and to
/// every resolved address.
///
/// # Source
///
/// The IANA **IPv4** and **IPv6 Special-Purpose Address Registries**
/// (<https://www.iana.org/assignments/iana-ipv4-special-registry/> and
/// <https://www.iana.org/assignments/iana-ipv6-special-registry/>), both
/// "Last Updated 2025-10-09", **retrieved 2026-10-17**. Every row whose
/// "Globally Reachable" is `False` is denied; the rows where it is `N/A` or
/// blank, and the globally reachable rows nested inside a non-reachable
/// block, are decided below, always toward denial.
///
/// # IPv4 — denied
///
/// | Block | Registry name |
/// |---|---|
/// | `0.0.0.0/8` (and `0.0.0.0/32`) | "This network" / "This host on this network" |
/// | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Private-Use |
/// | `100.64.0.0/10` | Shared Address Space (carrier-grade NAT) |
/// | `127.0.0.0/8` | Loopback |
/// | `169.254.0.0/16`, and `169.254.169.254` by name | Link Local; the metadata server |
/// | `192.0.0.0/24`, whole | IETF Protocol Assignments (the reachable `.9` and `.10` anycast addresses too) |
/// | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Documentation (TEST-NET-1/2/3) |
/// | `192.88.99.0/24`, whole | Deprecated 6to4 Relay Anycast (no reachability given) and the 6a44 relay |
/// | `198.18.0.0/15` | Benchmarking |
/// | `224.0.0.0/4` | Multicast (IANA's multicast registry) |
/// | `240.0.0.0/4` | Reserved, including Limited Broadcast `255.255.255.255` |
///
/// Everything else is public, including the three globally reachable rows
/// outside those blocks (`192.31.196.0/24` and `192.175.48.0/24`, AS112;
/// `192.52.193.0/24`, AMT).
///
/// # IPv6
///
/// - **IPv4-mapped** `::ffff:0:0/96` is unwrapped and the embedded IPv4 is
///   judged by the IPv4 policy: a socket connect to `::ffff:a.b.c.d` *is* a
///   connect to `a.b.c.d`.
/// - **NAT64 well-known prefix** `64:ff9b::/96` (globally reachable) is
///   unwrapped the same way: a translator delivers `64:ff9b::a.b.c.d` to
///   `a.b.c.d`, so the IPv4 is what has to be public. This keeps a DNS64
///   network's synthesized answers for public hosts working, and refuses
///   `64:ff9b::169.254.169.254`. (Python's `ipaddress` denies the whole
///   prefix as reserved; this is the one place the policy is looser than
///   Python's, deliberately.)
/// - **Outside `2000::/3` (Global Unicast) everything is denied**: that is
///   `::/128` unspecified, `::1/128` loopback, the deprecated IPv4-compatible
///   `::/96`, the local-use NAT64 prefix `64:ff9b:1::/48`, discard-only
///   `100::/64`, the dummy prefix `100:0:0:1::/64`, SRv6 SIDs `5f00::/16`,
///   unique-local `fc00::/7`, link-local `fe80::/10`, site-local
///   `fec0::/10`, multicast `ff00::/8`, and every reserved block.
/// - **Inside `2000::/3`**: `2001::/23` whole (IETF Protocol Assignments —
///   Teredo, Benchmarking, ORCHID and the reachable anycast/AMT/AS112/
///   ORCHIDv2/drone-ID more-specifics alike), `2001:db8::/32` and
///   `3fff::/20` (Documentation), and 6to4 `2002::/16` (reachability N/A;
///   denied rather than unwrapped, since its IPv4 names a relay, not the
///   host).
///
/// # Compared with Python
///
/// Python's `stridelabs.mcp.ssrf.is_public_address` combines `ipaddress`'s
/// flags. This policy denies everything those flags deny except
/// `64:ff9b::/96` wrapping a public IPv4 (above), and also denies what they
/// let through: `192.0.0.9`, `192.0.0.10`, `192.88.99.0/24`, the reachable
/// `2001::/23` more-specifics, and site-local `fec0::/10`, which no
/// `ipaddress` flag covers.
pub fn is_public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    ip != METADATA_V4
        && !DENIED_V4
            .iter()
            .any(|&(network, prefix)| in_v4_block(ip, network, prefix))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped().or_else(|| nat64_well_known(ip)) {
        return is_public_v4(v4);
    }
    let (network, prefix) = GLOBAL_UNICAST_V6;
    in_v6_block(ip, network, prefix)
        && !DENIED_V6
            .iter()
            .any(|&(network, prefix)| in_v6_block(ip, network, prefix))
}

/// The IPv4 address embedded in a `64:ff9b::/96` address (RFC 6052 §2.1: a
/// /96 prefix carries the IPv4 in the last 32 bits).
fn nat64_well_known(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let bits = u128::from(ip);
    let prefix = u128::from(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0));
    // The cast keeps exactly the low 32 bits, which is the embedded address.
    (bits >> 32 == prefix >> 32).then(|| Ipv4Addr::from(bits as u32))
}

fn in_v4_block(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(network) & mask
}

fn in_v6_block(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    u128::from(ip) & mask == u128::from(network) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(addr: &str) -> bool {
        is_public_address(addr.parse().unwrap_or_else(|_| panic!("{addr} parses")))
    }

    /// Python's `TestLiteralIpPolicy` set, minus the URL brackets (the URL
    /// form, with its message, is `target`'s test of the same list).
    #[test]
    fn pythons_nineteen_rejected_literals_are_denied() {
        for addr in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.0.10",
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
        ] {
            assert!(!public(addr), "{addr} must be denied");
        }
    }

    /// One denied registry row and what sits on either side of it.
    struct Row {
        cidr: &'static str,
        /// Whether the address just below the block is public; `None` when
        /// the block starts the address space.
        below: Option<bool>,
        /// Whether the address just above the block is public; `None` when
        /// the block ends the address space.
        above: Option<bool>,
    }

    const fn row(cidr: &'static str, below: Option<bool>, above: Option<bool>) -> Row {
        Row { cidr, below, above }
    }

    const PUBLIC: Option<bool> = Some(true);
    const DENIED: Option<bool> = Some(false);
    const EDGE: Option<bool> = None;

    /// Written from the IANA CSVs (retrieved 2026-10-17), independently of
    /// the implementation's tables: every row that is not globally
    /// reachable, nested rows included, plus the blocks the policy adds.
    /// A neighbour that is `DENIED` sits in another denied block (a parent,
    /// or the next row); the comment says which.
    const DENIED_ROWS: &[Row] = &[
        // --- IPv4 special-purpose registry ---
        row("0.0.0.0/8", EDGE, PUBLIC),
        row("0.0.0.0/32", EDGE, DENIED), // inside 0.0.0.0/8
        row("10.0.0.0/8", PUBLIC, PUBLIC),
        row("100.64.0.0/10", PUBLIC, PUBLIC),
        row("127.0.0.0/8", PUBLIC, PUBLIC),
        row("169.254.0.0/16", PUBLIC, PUBLIC),
        row("169.254.169.254/32", DENIED, DENIED), // inside link-local
        row("172.16.0.0/12", PUBLIC, PUBLIC),
        row("192.0.0.0/24", PUBLIC, PUBLIC),
        row("192.0.0.0/29", PUBLIC, DENIED), // above: 192.0.0.8, its own row
        row("192.0.0.8/32", DENIED, DENIED), // inside 192.0.0.0/24
        row("192.0.0.170/32", DENIED, DENIED),
        row("192.0.0.171/32", DENIED, DENIED),
        row("192.0.2.0/24", PUBLIC, PUBLIC),
        row("192.88.99.0/24", PUBLIC, PUBLIC),
        row("192.88.99.2/32", DENIED, DENIED), // inside 192.88.99.0/24
        row("192.168.0.0/16", PUBLIC, PUBLIC),
        row("198.18.0.0/15", PUBLIC, PUBLIC),
        row("198.51.100.0/24", PUBLIC, PUBLIC),
        row("203.0.113.0/24", PUBLIC, PUBLIC),
        row("240.0.0.0/4", DENIED, EDGE), // below: multicast
        row("255.255.255.255/32", DENIED, EDGE),
        // --- IPv4 multicast registry ---
        row("224.0.0.0/4", PUBLIC, DENIED), // above: 240.0.0.0/4
        // --- IPv6 special-purpose registry, outside 2000::/3 ---
        // Every neighbour here is outside 2000::/3 as well.
        row("::/128", EDGE, DENIED),
        row("::1/128", DENIED, DENIED),
        row("64:ff9b:1::/48", DENIED, DENIED),
        row("100::/64", DENIED, DENIED),
        row("100:0:0:1::/64", DENIED, DENIED),
        row("5f00::/16", DENIED, DENIED),
        row("fc00::/7", DENIED, DENIED),
        row("fe80::/10", DENIED, DENIED),
        // --- IPv6, not in the special-purpose registry ---
        row("fec0::/10", DENIED, DENIED), // site-local (RFC 3879, deprecated)
        row("ff00::/8", DENIED, EDGE),    // multicast
        // --- IPv6 special-purpose registry, inside 2000::/3 ---
        row("2001::/23", PUBLIC, PUBLIC),
        row("2001::/32", PUBLIC, DENIED), // Teredo; above: 2001:1::, in 2001::/23
        row("2001:2::/48", DENIED, DENIED), // Benchmarking, inside 2001::/23
        row("2001:10::/28", DENIED, DENIED), // deprecated ORCHID, inside 2001::/23
        row("2001:db8::/32", PUBLIC, PUBLIC),
        row("2002::/16", PUBLIC, PUBLIC),
        row("3fff::/20", PUBLIC, PUBLIC),
    ];

    /// `(first, last)` of a CIDR block, as integers, plus the parse.
    fn bounds(cidr: &str) -> (IpAddr, IpAddr) {
        let (network, prefix) = cidr.split_once('/').expect("CIDR has a prefix");
        let prefix: u32 = prefix.parse().expect("numeric prefix");
        match network.parse::<IpAddr>().expect("CIDR network parses") {
            IpAddr::V4(network) => {
                let host_bits = u32::MAX.checked_shr(prefix).unwrap_or(0);
                let first = u32::from(network) & !host_bits;
                (
                    Ipv4Addr::from(first).into(),
                    Ipv4Addr::from(first | host_bits).into(),
                )
            }
            IpAddr::V6(network) => {
                let host_bits = u128::MAX.checked_shr(prefix).unwrap_or(0);
                let first = u128::from(network) & !host_bits;
                (
                    Ipv6Addr::from(first).into(),
                    Ipv6Addr::from(first | host_bits).into(),
                )
            }
        }
    }

    fn step(ip: IpAddr, up: bool) -> Option<IpAddr> {
        match ip {
            IpAddr::V4(v4) => {
                let n = u32::from(v4);
                let n = if up {
                    n.checked_add(1)
                } else {
                    n.checked_sub(1)
                }?;
                Some(Ipv4Addr::from(n).into())
            }
            IpAddr::V6(v6) => {
                let n = u128::from(v6);
                let n = if up {
                    n.checked_add(1)
                } else {
                    n.checked_sub(1)
                }?;
                Some(Ipv6Addr::from(n).into())
            }
        }
    }

    #[test]
    fn every_denied_range_is_denied_at_both_ends_and_its_neighbours_are_as_expected() {
        for Row { cidr, below, above } in DENIED_ROWS {
            let (first, last) = bounds(cidr);
            assert!(!is_public_address(first), "{cidr}: first {first} denied");
            assert!(!is_public_address(last), "{cidr}: last {last} denied");
            for (neighbour, expected, side) in [
                (step(first, false), below, "below"),
                (step(last, true), above, "above"),
            ] {
                match (neighbour, expected) {
                    (Some(addr), Some(expected)) => assert_eq!(
                        is_public_address(addr),
                        *expected,
                        "{cidr}: the neighbour {side}, {addr}"
                    ),
                    (None, None) => {}
                    (neighbour, expected) => panic!(
                        "{cidr}: table says {side} is {expected:?}, address space says {neighbour:?}"
                    ),
                }
            }
        }
    }

    /// The structural IPv6 rule, at its edges: Global Unicast is public right
    /// up to both ends, and nothing outside it is.
    #[test]
    fn global_unicast_is_the_only_public_ipv6_space() {
        let (first, last) = bounds("2000::/3");
        assert!(is_public_address(first), "{first}");
        assert!(is_public_address(last), "{last}");
        assert!(!public("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(!public("4000::"));
    }

    #[test]
    fn globally_reachable_rows_outside_denied_blocks_are_public() {
        for cidr in [
            "192.31.196.0/24",   // AS112-v4
            "192.52.193.0/24",   // AMT
            "192.175.48.0/24",   // Direct Delegation AS112 Service
            "2620:4f:8000::/48", // Direct Delegation AS112 Service (v6)
        ] {
            let (first, last) = bounds(cidr);
            assert!(is_public_address(first), "{cidr}: {first}");
            assert!(is_public_address(last), "{cidr}: {last}");
        }
        for addr in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
            "2606:4700:4700::1111",
        ] {
            assert!(public(addr), "{addr}");
        }
    }

    /// Registry rows that ARE globally reachable but sit inside a block that
    /// is not: denied on purpose (the module docs say why).
    #[test]
    fn reachable_more_specifics_inside_denied_blocks_stay_denied() {
        for addr in [
            "192.0.0.9",
            "192.0.0.10",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
        ] {
            assert!(!public(addr), "{addr} must be denied");
        }
    }

    #[test]
    fn ipv4_mapped_addresses_are_judged_by_the_embedded_ipv4() {
        assert!(public("::ffff:8.8.8.8"));
        assert!(public("::ffff:93.184.216.34"));
        for addr in [
            "::ffff:0.0.0.0",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:192.168.0.9",
            "::ffff:255.255.255.255",
        ] {
            assert!(!public(addr), "{addr} must be denied");
        }
        // Just outside ::ffff:0:0/96 on both sides: outside 2000::/3.
        assert!(!public("::fffe:ffff:ffff"));
        assert!(!public("::1:0:0:0"));
    }

    #[test]
    fn nat64_well_known_prefix_is_judged_by_the_embedded_ipv4() {
        assert!(public("64:ff9b::8.8.8.8"));
        assert!(public("64:ff9b::93.184.216.34"));
        for addr in [
            "64:ff9b::",                // 0.0.0.0
            "64:ff9b::10.0.0.1",        // private
            "64:ff9b::127.0.0.1",       // loopback
            "64:ff9b::169.254.169.254", // metadata
            "64:ff9b::ffff:ffff",       // 255.255.255.255
        ] {
            assert!(!public(addr), "{addr} must be denied");
        }
        // Just outside 64:ff9b::/96 on both sides: outside 2000::/3.
        assert!(!public("64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(!public("64:ff9b::1:0:0"));
        // Not unwrapped either: outside the /96, low bits that spell a public
        // IPv4 are not an embedded address.
        assert!(!public("64:ff9b::1:808:808"));
    }

    #[test]
    fn other_ipv4_embedding_forms_are_denied_even_around_a_public_ipv4() {
        for addr in [
            "2002:808:808::1",                      // 6to4 wrapping 8.8.8.8
            "2001:0:4136:e378:8000:63bf:f7f7:f7f7", // Teredo, client 8.8.8.8 (obfuscated)
            "::8.8.8.8",                            // deprecated IPv4-compatible
            "::127.0.0.1",
            "::ffff:0:8.8.8.8",   // IPv4-translated (SIIT)
            "64:ff9b:1::808:808", // local-use NAT64
        ] {
            assert!(!public(addr), "{addr} must be denied");
        }
    }

    #[test]
    fn the_metadata_address_is_denied_by_name() {
        assert!(!is_public_v4(METADATA_V4));
        assert!(!public("169.254.169.254"));
        assert!(!public("::ffff:169.254.169.254"));
    }
}
