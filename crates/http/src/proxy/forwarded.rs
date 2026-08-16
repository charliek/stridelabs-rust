//! `X-Forwarded-*` synthesis on the request leg — who the client was, and what
//! scheme it used.
//!
//! Both headers are conventions rather than contracts, and both are *client
//! input* until some hop decides otherwise. That decision is the whole of this
//! module: [`ForwardedPolicy`] makes a proxy say out loud, per leg, whether it
//! trusts what arrived or replaces it. There is deliberately **no `Default`**
//! on any type here — a forwarding policy is a security decision, and the one
//! a service inherits by accident is the one nobody reviews.
//!
//! # The trust question, in one paragraph
//!
//! An upstream that reads `X-Forwarded-Proto` to decide "this request was
//! secure" (Ory Hydra does exactly that) is trusting whichever hop wrote the
//! header. If a proxy in front of it forwards a client-supplied value, then
//! *the client* is that hop and can claim `https` over plain HTTP.
//! [`XfpPolicy::Override`] is the answer that cannot be talked out of:
//! applied unconditionally, collapsing every inbound line to exactly one
//! authoritative value. [`XfpPolicy::PreserveTrustedOrSet`] is the weaker,
//! more common posture — keep what arrived, set the scheme only when absent —
//! and it is safe **only** if the ingress in front strips a client-sent
//! `X-Forwarded-Proto` or always overwrites it with an authoritative value.
//!
//! ## The set-if-absent coincidence (the canonical warning)
//!
//! slauth's Hydra leg copies request headers through a static allow-list and
//! then applies its overrides. `x-forwarded-proto` is not in that allow-list,
//! so a client-sent value never survives the copy, so set-if-absent and
//! override produce byte-identical requests today. That equivalence is a
//! **coincidence of one allow-list**, not a property of the design: the day
//! someone adds `x-forwarded-proto` to the allow-list for an unrelated reason,
//! set-if-absent starts trusting the client and the change looks like a
//! one-line header addition in review. Nothing fails, nothing logs, and Hydra
//! believes whatever the caller claimed. That is why slauth uses
//! [`XfpPolicy::Override`] even where set-if-absent would be observationally
//! identical — and why `PreserveTrustedOrSet` carries "trusted" in its name
//! rather than being spelled `SetIfAbsent`, which reads like a mere absence
//! check instead of the trust delegation it is.
//!
//! # Ported from
//!
//! limen's `http::forwarded::apply` (the XFF append semantics, exactly —
//! including the parts one would not choose fresh; they are called out at
//! [`XffPolicy::Append`]) and slauth's `ProxyPolicy` override list. Neither
//! service's own header names, allow-lists or scheme constants come with it.

use std::fmt::Write as _;
use std::net::IpAddr;

use http::{HeaderMap, HeaderName, HeaderValue};

/// The chain of client addresses a request has passed through.
const X_FORWARDED_FOR: &str = "x-forwarded-for";
/// The scheme the client used to reach the front of the proxy chain.
const X_FORWARDED_PROTO: &str = "x-forwarded-proto";

/// What [`apply_forwarded`] does with `X-Forwarded-For`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XffPolicy {
    /// Append this hop's view of the peer to whatever chain arrived — standard
    /// reverse-proxy semantics, carried from limen unchanged. Four details are
    /// load-bearing and all four are pinned by tests:
    ///
    /// - **Multi-line aware.** A `HeaderMap` can hold one name as several
    ///   field lines; reading only the first and inserting would silently drop
    ///   every earlier hop. All lines are read, and the result is written as
    ///   **one combined line** — normal XFF practice, and simple to append to
    ///   again downstream.
    /// - **Omits only when there is no peer *and* no existing value.** An
    ///   existing chain with no peer is preserved verbatim, never removed:
    ///   a hop that cannot see its own peer (a test harness driving the router
    ///   directly, a listener without connect-info) still must not erase what
    ///   a fronting load balancer recorded. With no peer the header is left
    ///   exactly as it arrived, lines and all — nothing is re-rendered.
    /// - **Empty and non-UTF-8 existing lines are dropped**, silently. This is
    ///   limen's behavior carried knowingly rather than a decision defended on
    ///   the merits: such a line cannot name a real hop, and no rendering of
    ///   it would be read the same way by a downstream parser. It is worth
    ///   knowing when reading a chain that is shorter than expected.
    /// - **The peer renders bare**: no port (which is why the argument is an
    ///   [`IpAddr`] and not a `SocketAddr`) and, for IPv6, no brackets — an
    ///   XFF element is an address, not a URI authority.
    Append,
    /// Set the peer only when the header is **absent**, and never otherwise —
    /// slauth's semantics, where the caller's headers have already passed a
    /// static allow-list before this runs, so a surviving value is one the
    /// deployment chose to trust.
    ///
    /// Presence is [`HeaderMap::contains_key`], not "has a usable value": a
    /// present-but-empty line counts as present and suppresses synthesis. That
    /// is parity with the Python original (`header not in headers`), not an
    /// endorsement — under this policy the deployment's ingress owns and
    /// sanitizes `X-Forwarded-For`.
    FillIfAbsent,
    /// Leave `X-Forwarded-For` exactly as it arrived. For a leg whose upstream
    /// must not see a chain at all, or one where a layer above already wrote
    /// it.
    Untouched,
}

/// What [`apply_forwarded`] does with `X-Forwarded-Proto`.
///
/// The scheme is a `&'static str` rather than a parsed [`HeaderValue`] for the
/// same reason [`ForwardedPolicy::overrides`] is: `HeaderValue` is interior-
/// mutable, so a `const` policy cannot hold a reference to one (E0492).
/// Validity is therefore a runtime property, and the bar is the **URI scheme
/// grammar** (RFC 3986 §3.1: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`),
/// not merely "is a legal header value". `"https, http"` passes the latter and
/// would hand the upstream two values in one line — exactly the ambiguity this
/// type exists to remove — so it is rejected. A rejected scheme trips a
/// `debug_assert`; what happens in release is per-variant, below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfpPolicy {
    /// Write `scheme` unconditionally, replacing **every** inbound line with
    /// exactly one value. The security control: after this, the upstream has
    /// no choice of which line to believe and no client-supplied value
    /// survives. Use it whenever the upstream draws a security conclusion from
    /// the header — and, per the module docs, even when the current header
    /// allow-list makes [`XfpPolicy::PreserveTrustedOrSet`] look equivalent.
    ///
    /// **Fail-closed.** The inbound header is removed *first, unconditionally*,
    /// and the scheme is written only if it passes the grammar above. So in a
    /// release build with a malformed scheme constant the upstream sees **no**
    /// `X-Forwarded-Proto` at all — never the caller's. An upstream that
    /// defaults to "not secure" on an absent header then degrades safely; one
    /// that inherited the client's claim would not degrade at all.
    Override(&'static str),
    /// Keep an existing value; write `scheme` only when the header is absent
    /// ([`HeaderMap::contains_key`] — a present-but-empty line counts as
    /// present and suppresses the write).
    ///
    /// The name is the warning: keeping an existing value **is** trusting
    /// whichever hop wrote it, and this hop cannot tell a load balancer's
    /// value from a client's. It is correct only under a deployment that
    /// guarantees one of the two — the ingress strips a client-sent
    /// `X-Forwarded-Proto`, or the ingress always sets an authoritative one.
    /// If neither is guaranteed, this policy lets a caller declare its own
    /// scheme; see the module docs for what that costs and for the
    /// coincidence that hides it.
    ///
    /// A rejected scheme means no write, in release: whatever arrived is left
    /// exactly as it arrived. There is nothing to fail closed *to* here — this
    /// variant's whole premise is that an inbound value may be trusted.
    PreserveTrustedOrSet(&'static str),
    /// Leave `X-Forwarded-Proto` exactly as it arrived — including absent.
    Untouched,
}

/// One leg's forwarding policy: what to do with each `X-Forwarded-*` header,
/// plus any other headers this server sets itself.
///
/// Every field is `&'static`-friendly so a whole policy can be a `const` beside
/// the route that uses it, which is how both reference consumers hold theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardedPolicy {
    /// `X-Forwarded-For` handling.
    pub xff: XffPolicy,
    /// `X-Forwarded-Proto` handling. The **only** place this header's
    /// authority lives — see [`ForwardedPolicy::overrides`].
    pub xfp: XfpPolicy,
    /// Headers this server sets on the way out, applied after the chain above
    /// so they beat anything the client sent (and, being `insert`s, collapse a
    /// repeated inbound header to one value) — but before [`xfp`], which is
    /// the one header they may not contest.
    ///
    /// `&str` pairs rather than parsed `(HeaderName, HeaderValue)` because
    /// `HeaderValue` is interior-mutable and a `const` cannot hold a reference
    /// to one (E0492) — the parsed form would force every consumer into a
    /// separate `static` beside its policy. The cost is that validity is a
    /// runtime property: an invalid name or value is **skipped** rather than
    /// written, and trips a `debug_assert` (see [`apply_forwarded`]).
    ///
    /// **This list may never name `x-forwarded-proto` — under *any* [`xfp`],
    /// [`XfpPolicy::Untouched`] included.** It is debug-asserted, and the pair
    /// is skipped in release. That header's authority belongs to [`xfp`]
    /// alone: a reader auditing a leg's scheme handling must be able to read
    /// one field and be done, and "the `XfpPolicy` is `Untouched`, so the
    /// generic list may set it" is a rule that holds only until someone
    /// changes the `XfpPolicy` — at which point two writers exist and the
    /// diff that created the conflict touched neither of them. A leg that
    /// wants to set the header uses [`XfpPolicy::Override`], which is also the
    /// only form that strips a repeated inbound value.
    ///
    /// [`xfp`]: ForwardedPolicy::xfp
    pub overrides: &'static [(&'static str, &'static str)],
}

/// Apply `policy` to outbound request headers: `X-Forwarded-For`, then the
/// server's own overrides, then `X-Forwarded-Proto` — in that order, because
/// each step is allowed to beat the one before it.
///
/// The scheme going **last** is deliberate and structural. It is the one
/// header here an upstream may draw a security conclusion from, so
/// [`XfpPolicy`] wins by construction rather than by everyone remembering that
/// the generic override list must not contest it. The `debug_assert` on that
/// collision (below) is then a design guard rather than the only thing
/// standing between a stray override pair and a forged scheme.
///
/// `client_ip` is this hop's view of the peer, or `None` when it is unavailable
/// (a test harness driving the router directly, a listener without connect-info
/// extraction). An [`IpAddr`] rather than a `SocketAddr` so the ephemeral client
/// port cannot leak into the chain — an XFF element is an address.
///
/// # Debug assertions
///
/// Four programmer errors are caught in debug builds, on the principle that a
/// malformed constant should stop a developer rather than a production
/// request. Each has a defined release behavior, and none of them is "write it
/// anyway":
///
/// - an override name that is not a valid header name — pair skipped;
/// - an override value that is not a valid header value (a `\r\n` in one would
///   be request-header injection if it were written verbatim) — pair skipped;
/// - an override that names `x-forwarded-proto` under any [`XfpPolicy`] — pair
///   skipped, so the policy's own answer stands (see
///   [`ForwardedPolicy::overrides`]);
/// - a [`XfpPolicy`] scheme that is not a URI scheme per RFC 3986 §3.1 — not
///   written, and for [`XfpPolicy::Override`] the inbound header is removed
///   regardless, so the failure is closed rather than a silent fallback to the
///   caller's claim.
///
/// # Example
///
/// ```
/// use std::net::IpAddr;
/// use stridelabs_http::proxy::{apply_forwarded, ForwardedPolicy, XffPolicy, XfpPolicy};
///
/// // The upstream trusts `X-Forwarded-Proto` as proof the outside hop was
/// // TLS, so this leg states it rather than relaying what the caller claimed.
/// const HYDRA_LEG: ForwardedPolicy = ForwardedPolicy {
///     xff: XffPolicy::Append,
///     xfp: XfpPolicy::Override("https"),
///     overrides: &[],
/// };
///
/// let mut headers = http::HeaderMap::new();
/// headers.insert("x-forwarded-proto", http::HeaderValue::from_static("http"));
///
/// let peer: IpAddr = "203.0.113.9".parse()?;
/// apply_forwarded(&mut headers, Some(peer), &HYDRA_LEG);
///
/// assert_eq!(headers["x-forwarded-for"], "203.0.113.9");
/// assert_eq!(headers["x-forwarded-proto"], "https");
/// # Ok::<(), std::net::AddrParseError>(())
/// ```
pub fn apply_forwarded(
    headers: &mut HeaderMap,
    client_ip: Option<IpAddr>,
    policy: &ForwardedPolicy,
) {
    debug_assert!(
        !policy
            .overrides
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(X_FORWARDED_PROTO)),
        "x-forwarded-proto is named in the overrides list: that header's authority belongs to \
         XfpPolicy alone, whatever the current XfpPolicy is — use XfpPolicy::Override"
    );

    match policy.xff {
        XffPolicy::Append => append_forwarded_for(headers, client_ip),
        XffPolicy::FillIfAbsent => {
            // `contains_key`, so a present-but-empty value suppresses the fill.
            if let Some(peer) = client_ip {
                if !headers.contains_key(X_FORWARDED_FOR) {
                    set(headers, X_FORWARDED_FOR, &peer.to_string(), "peer address");
                }
            }
        }
        XffPolicy::Untouched => {}
    }

    // Then the server's own headers, so they beat anything the client sent.
    for (name, value) in policy.overrides {
        // Asserted above; in release the pair is dropped rather than allowed
        // to contest `XfpPolicy` for the scheme.
        if name.eq_ignore_ascii_case(X_FORWARDED_PROTO) {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            debug_assert!(false, "invalid override header name: {name:?}");
            continue;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            debug_assert!(false, "invalid override header value for {name:?}");
            continue;
        };
        headers.insert(name, value);
    }

    // The scheme LAST — see this function's docs. Nothing above can reach it.
    match policy.xfp {
        XfpPolicy::Override(scheme) => {
            // Fail closed: every inbound line goes first and unconditionally,
            // *before* the policy constant is judged. A malformed constant
            // therefore leaves the header absent in a release build rather
            // than leaving the caller's claim standing.
            headers.remove(X_FORWARDED_PROTO);
            if let Some(value) = scheme_value(scheme) {
                headers.insert(X_FORWARDED_PROTO, value);
            }
        }
        XfpPolicy::PreserveTrustedOrSet(scheme) => {
            // Judged before the presence check, so a malformed constant is
            // caught on every request rather than only on the ones that happen
            // to arrive without the header.
            let value = scheme_value(scheme);
            if !headers.contains_key(X_FORWARDED_PROTO) {
                if let Some(value) = value {
                    headers.insert(X_FORWARDED_PROTO, value);
                }
            }
        }
        XfpPolicy::Untouched => {}
    }
}

/// A [`XfpPolicy`] scheme as a header value, or `None` (with a debug assert) if
/// it is not a URI scheme.
///
/// The check is the RFC 3986 §3.1 grammar — `ALPHA *( ALPHA / DIGIT / "+" /
/// "-" / "." )` — rather than [`HeaderValue`]'s, which is far more permissive:
/// `"https, http"` is a perfectly legal header value and a perfectly illegal
/// answer to "which scheme did the client use", since a downstream comma-split
/// finds two. Anything that passes this grammar is visible ASCII and so always
/// a valid header value.
fn scheme_value(scheme: &str) -> Option<HeaderValue> {
    if !is_uri_scheme(scheme) {
        debug_assert!(false, "invalid forwarded-proto scheme: {scheme:?}");
        return None;
    }
    HeaderValue::from_str(scheme).ok()
}

/// RFC 3986 §3.1: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn is_uri_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

/// limen's append: every existing line, then this hop's peer, written back as
/// one line — and nothing at all when there is no peer, which is what leaves an
/// existing chain untouched instead of re-rendered.
fn append_forwarded_for(headers: &mut HeaderMap, client_ip: Option<IpAddr>) {
    let Some(peer) = client_ip else {
        // No peer: an existing chain stays exactly as it arrived (including as
        // several field lines), and an absent one stays absent. Fabricating a
        // value would be worse than omitting one.
        return;
    };
    // Built as one growing `String` rather than `Vec<String>` + `join`: this
    // runs once per proxied request, and a chain of length N would otherwise
    // cost N+ owned-string allocations before the join even starts.
    let mut chain = String::new();
    for line in headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        // Empty and non-visible-ASCII lines are dropped here — see
        // `XffPolicy::Append`.
        .filter_map(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        if !chain.is_empty() {
            chain.push_str(", ");
        }
        chain.push_str(line);
    }
    if !chain.is_empty() {
        chain.push_str(", ");
    }
    write!(chain, "{peer}").expect("writing to a String is infallible");
    // `insert`, not `append`: every line read above is replaced by this single
    // combined one, so no hop is duplicated and none is lost.
    set(headers, X_FORWARDED_FOR, &chain, "forwarded-for chain");
}

/// `insert` a validated `X-Forwarded-For` value, skipping (and, in debug,
/// asserting) rather than writing anything a peer could read as a second
/// header.
///
/// Neither caller can actually fail this check — every part of a chain came
/// back out of [`HeaderValue::to_str`], and an [`IpAddr`] renders as visible
/// ASCII. The guard stays because "unreachable by construction" is a property
/// of today's two callers, not of the function.
fn set(headers: &mut HeaderMap, name: &'static str, value: &str, what: &str) {
    match HeaderValue::from_str(value) {
        Ok(value) => {
            headers.insert(name, value);
        }
        Err(_) => debug_assert!(false, "invalid {what}: {value:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy every test starts from: nothing happens unless the test asks
    /// for it. There is deliberately no `Default` impl on any of these types
    /// (a forwarding policy is a security decision and must be spelled out at
    /// the call site), so the test fixture spells it instead.
    const INERT: ForwardedPolicy = ForwardedPolicy {
        xff: XffPolicy::Untouched,
        xfp: XfpPolicy::Untouched,
        overrides: &[],
    };

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().expect("test address parses"))
    }

    fn lines(headers: &HeaderMap, name: &str) -> Vec<String> {
        headers
            .get_all(name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect()
    }

    // --- X-Forwarded-For: Append -------------------------------------------

    #[test]
    fn an_ipv4_peer_renders_bare_with_no_port() {
        // The parameter is an `IpAddr`, not a `SocketAddr`, precisely so a
        // port cannot reach the chain: an XFF element is an address, and a
        // downstream that parses one gets a different answer if a `:port` is
        // glued on.
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            ip("203.0.113.9"),
            &ForwardedPolicy {
                xff: XffPolicy::Append,
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_FOR), vec!["203.0.113.9"]);
    }

    #[test]
    fn an_ipv6_peer_renders_without_brackets() {
        // XFF carries a bare IP, unlike a `Host`/URI authority which needs
        // `[…]` around an IPv6 literal. `IpAddr::to_string` already omits
        // them; this pins that rendering against regression.
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            ip("2001:db8::1"),
            &ForwardedPolicy {
                xff: XffPolicy::Append,
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_FOR), vec!["2001:db8::1"]);
    }

    #[test]
    fn an_existing_chain_with_no_peer_is_preserved_not_removed() {
        // The omission rule is "no peer AND no existing value", not "no peer".
        // A chain a fronting load balancer set must survive a hop that cannot
        // see its own peer — dropping it would erase every earlier hop.
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.1"));
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xff: XffPolicy::Append,
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_FOR), vec!["198.51.100.1"]);
    }

    #[test]
    fn no_peer_and_no_existing_chain_writes_nothing() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xff: XffPolicy::Append,
                ..INERT
            },
        );
        assert!(!headers.contains_key(X_FORWARDED_FOR));
    }

    #[test]
    fn every_existing_line_is_combined_into_one_inserted_line() {
        // A `HeaderMap` can hold one name as several field lines; `get` alone
        // sees only the first, so an append built on it would drop hops. The
        // result is a single combined line — standard XFF practice, and easy
        // to append to again downstream.
        let mut headers = HeaderMap::new();
        headers.append(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.1"));
        headers.append(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.2"));
        apply_forwarded(
            &mut headers,
            ip("203.0.113.9"),
            &ForwardedPolicy {
                xff: XffPolicy::Append,
                ..INERT
            },
        );
        assert_eq!(
            lines(&headers, X_FORWARDED_FOR),
            vec!["198.51.100.1, 198.51.100.2, 203.0.113.9"],
            "no hop may be dropped, and the combined chain is a single line"
        );
    }

    #[test]
    fn empty_and_non_utf8_existing_lines_are_dropped() {
        // Carried knowingly from limen: a line that is empty or not visible
        // ASCII is skipped rather than propagated. It cannot be a real hop,
        // and there is no rendering of it that a downstream parser would read
        // the same way.
        let mut headers = HeaderMap::new();
        headers.append(X_FORWARDED_FOR, HeaderValue::from_static(""));
        headers.append(
            X_FORWARDED_FOR,
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("opaque bytes are a legal header value"),
        );
        headers.append(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.1"));
        apply_forwarded(
            &mut headers,
            ip("203.0.113.9"),
            &ForwardedPolicy {
                xff: XffPolicy::Append,
                ..INERT
            },
        );
        assert_eq!(
            lines(&headers, X_FORWARDED_FOR),
            vec!["198.51.100.1, 203.0.113.9"]
        );
    }

    #[test]
    fn a_chain_of_only_unusable_lines_leaves_just_the_peer() {
        // The malformed-existing-header case: every line is dropped, so the
        // combined value is the peer alone — and it is still a legal header
        // value, which is what the render guard exists to keep true.
        let mut headers = HeaderMap::new();
        headers.append(
            X_FORWARDED_FOR,
            HeaderValue::from_bytes(&[0x80]).expect("opaque bytes are a legal header value"),
        );
        apply_forwarded(
            &mut headers,
            ip("203.0.113.9"),
            &ForwardedPolicy {
                xff: XffPolicy::Append,
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_FOR), vec!["203.0.113.9"]);
    }

    // --- X-Forwarded-For: FillIfAbsent / Untouched -------------------------

    #[test]
    fn fill_if_absent_sets_the_peer_when_the_header_is_absent() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            ip("203.0.113.9"),
            &ForwardedPolicy {
                xff: XffPolicy::FillIfAbsent,
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_FOR), vec!["203.0.113.9"]);
    }

    #[test]
    fn a_present_but_empty_header_suppresses_fill_if_absent() {
        // Presence is `contains_key`, not "has a usable value": an empty
        // client-supplied line counts as present and suppresses synthesis.
        // Parity with slauth's Python original, not endorsement — the
        // deployment's ingress owns this header.
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static(""));
        apply_forwarded(
            &mut headers,
            ip("203.0.113.9"),
            &ForwardedPolicy {
                xff: XffPolicy::FillIfAbsent,
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_FOR), vec![""]);
    }

    #[test]
    fn fill_if_absent_with_no_peer_writes_nothing() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xff: XffPolicy::FillIfAbsent,
                ..INERT
            },
        );
        assert!(!headers.contains_key(X_FORWARDED_FOR));
    }

    #[test]
    fn xff_untouched_neither_appends_nor_fills() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.1"));
        apply_forwarded(&mut headers, ip("203.0.113.9"), &INERT);
        assert_eq!(lines(&headers, X_FORWARDED_FOR), vec!["198.51.100.1"]);
    }

    // --- X-Forwarded-Proto -------------------------------------------------

    #[test]
    fn override_replaces_a_client_supplied_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::Override("https"),
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_PROTO), vec!["https"]);
    }

    #[test]
    fn repeated_inbound_proto_collapses_to_exactly_one_value_under_override() {
        // The one that makes `Override` a security control rather than a
        // convenience: a caller that sends the header twice must not leave the
        // upstream a choice of which line to believe.
        let mut headers = HeaderMap::new();
        headers.append(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
        headers.append(X_FORWARDED_PROTO, HeaderValue::from_static("gopher"));
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::Override("https"),
                ..INERT
            },
        );
        assert_eq!(
            lines(&headers, X_FORWARDED_PROTO),
            vec!["https"],
            "every inbound line must be replaced by exactly one authoritative value"
        );
    }

    #[test]
    fn override_beats_both_a_client_value_and_a_preserve_trusted_result() {
        // The interaction test the plan names. First hop runs
        // `PreserveTrustedOrSet`, which trusts the client's `http`; the second
        // hop runs `Override`, and its value is the one that reaches the
        // upstream. This is why slauth uses `Override` and not set-if-absent.
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));

        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::PreserveTrustedOrSet("https"),
                ..INERT
            },
        );
        assert_eq!(
            lines(&headers, X_FORWARDED_PROTO),
            vec!["http"],
            "set-if-absent semantics trust whatever arrived"
        );

        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::Override("https"),
                ..INERT
            },
        );
        assert_eq!(
            lines(&headers, X_FORWARDED_PROTO),
            vec!["https"],
            "Override is applied last and always wins"
        );
    }

    #[test]
    fn preserve_trusted_or_set_keeps_an_existing_value() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("https"));
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::PreserveTrustedOrSet("http"),
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_PROTO), vec!["https"]);
    }

    #[test]
    fn preserve_trusted_or_set_sets_the_scheme_when_absent() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::PreserveTrustedOrSet("http"),
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_PROTO), vec!["http"]);
    }

    #[test]
    fn a_present_but_empty_proto_suppresses_preserve_trusted_or_set() {
        // Same `contains_key` presence rule as the XFF fill — and a sharper
        // demonstration of what "trusted" costs: an empty client line is
        // enough to stop the authoritative value being written.
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static(""));
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::PreserveTrustedOrSet("https"),
                ..INERT
            },
        );
        assert_eq!(lines(&headers, X_FORWARDED_PROTO), vec![""]);
    }

    #[test]
    fn xfp_untouched_neither_sets_nor_replaces() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
        apply_forwarded(&mut headers, None, &INERT);
        assert_eq!(lines(&headers, X_FORWARDED_PROTO), vec!["http"]);

        let mut empty = HeaderMap::new();
        apply_forwarded(&mut empty, None, &INERT);
        assert!(!empty.contains_key(X_FORWARDED_PROTO));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "forwarded-proto scheme")]
    fn an_invalid_scheme_trips_the_debug_assert() {
        // A scheme with a newline in it would be request-header injection if
        // it were written verbatim, and silently skipping it would turn the
        // security control into a no-op. In debug it stops the developer.
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::Override("https\r\nx-injected: 1"),
                ..INERT
            },
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "forwarded-proto scheme")]
    fn a_multi_valued_scheme_trips_the_debug_assert() {
        // `"https, http"` is a legal header VALUE and an illegal scheme: a
        // downstream comma-split finds two, which is precisely the ambiguity
        // `Override` exists to remove. The URI-scheme grammar rejects it.
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::Override("https, http"),
                ..INERT
            },
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "forwarded-proto scheme")]
    fn a_preserve_trusted_or_set_scheme_is_judged_even_when_the_header_is_present() {
        // The constant is validated before the presence check, so a malformed
        // one is caught on every request rather than only on the requests that
        // happen to arrive without the header.
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::PreserveTrustedOrSet("https, http"),
                ..INERT
            },
        );
    }

    #[test]
    fn the_uri_scheme_grammar_accepts_real_schemes_and_rejects_the_rest() {
        // RFC 3986 §3.1: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
        for ok in ["http", "https", "HTTPS", "a", "coap+tcp", "x-my.scheme9"] {
            assert!(is_uri_scheme(ok), "{ok:?} is a URI scheme");
        }
        for bad in [
            "",
            "9http",
            "+http",
            "https, http",
            "https http",
            "https;q=1",
            "https\r\nx: 1",
            "http\u{00e9}",
        ] {
            assert!(!is_uri_scheme(bad), "{bad:?} is not a URI scheme");
        }
    }

    // --- the generic overrides list ----------------------------------------

    #[test]
    fn the_overrides_list_applies_str_pairs() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("198.51.100.1"));
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                overrides: &[("x-real-ip", "203.0.113.9"), ("x-tenant", "acme")],
                ..INERT
            },
        );
        assert_eq!(lines(&headers, "x-real-ip"), vec!["203.0.113.9"]);
        assert_eq!(lines(&headers, "x-tenant"), vec!["acme"]);
    }

    #[test]
    fn a_repeated_overridden_header_collapses_to_one_line() {
        let mut headers = HeaderMap::new();
        headers.append("x-real-ip", HeaderValue::from_static("198.51.100.1"));
        headers.append("x-real-ip", HeaderValue::from_static("198.51.100.2"));
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                overrides: &[("x-real-ip", "203.0.113.9")],
                ..INERT
            },
        );
        assert_eq!(lines(&headers, "x-real-ip"), vec!["203.0.113.9"]);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "x-forwarded-proto")]
    fn naming_the_proto_header_in_overrides_beside_an_xfp_policy_trips_the_debug_assert() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::Override("https"),
                overrides: &[(X_FORWARDED_PROTO, "http")],
                ..INERT
            },
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "x-forwarded-proto")]
    fn naming_the_proto_header_in_overrides_trips_the_debug_assert_even_when_untouched() {
        // The rule is unconditional. "The XfpPolicy is Untouched, so the
        // generic list may set the scheme" holds only until someone changes
        // the XfpPolicy — and that diff would touch neither the override list
        // nor the reader's attention.
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                overrides: &[(X_FORWARDED_PROTO, "https")],
                ..INERT
            },
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "x-forwarded-proto")]
    fn the_collision_guard_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                overrides: &[("X-Forwarded-Proto", "https")],
                ..INERT
            },
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "override header name")]
    fn an_invalid_override_name_trips_the_debug_assert() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                overrides: &[("not a header name", "v")],
                ..INERT
            },
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "override header value")]
    fn an_invalid_override_value_trips_the_debug_assert() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                overrides: &[("x-tenant", "acme\r\nx-injected: 1")],
                ..INERT
            },
        );
    }

    /// The skip half of the invalid-pair contract, which only a release build
    /// can observe: in a debug build the `debug_assert` fires first (the
    /// `should_panic` tests above), so this is compiled only when assertions
    /// are off. `cargo test --release` runs it.
    #[cfg(not(debug_assertions))]
    #[test]
    fn an_invalid_override_pair_is_skipped_and_the_rest_still_apply() {
        let mut headers = HeaderMap::new();
        apply_forwarded(
            &mut headers,
            None,
            &ForwardedPolicy {
                overrides: &[
                    ("not a header name", "v"),
                    ("x-tenant", "acme\r\nx-injected: 1"),
                    ("x-real-ip", "203.0.113.9"),
                ],
                ..INERT
            },
        );
        assert!(!headers.contains_key("x-tenant"));
        assert!(!headers.contains_key("x-injected"));
        assert_eq!(lines(&headers, "x-real-ip"), vec!["203.0.113.9"]);
    }

    /// The release half of the invalid-scheme contract, and the reason
    /// `Override` removes before it writes: a malformed constant must not
    /// leave the CALLER'S value standing. Absent is a safe answer; "http,
    /// because the client said so" is not.
    #[cfg(not(debug_assertions))]
    #[test]
    fn an_invalid_scheme_strips_the_inbound_header_rather_than_trusting_it() {
        for scheme in ["https\r\nx-injected: 1", "https, http"] {
            let mut headers = HeaderMap::new();
            headers.append(X_FORWARDED_PROTO, HeaderValue::from_static("https"));
            headers.append(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
            apply_forwarded(
                &mut headers,
                None,
                &ForwardedPolicy {
                    xfp: XfpPolicy::Override(scheme),
                    ..INERT
                },
            );
            assert!(
                !headers.contains_key(X_FORWARDED_PROTO),
                "{scheme:?}: a rejected Override scheme must fail closed, not fall back to the \
                 caller's value"
            );
            assert!(!headers.contains_key("x-injected"));
        }
    }

    /// `PreserveTrustedOrSet`'s release half: a rejected scheme is simply not
    /// written, and whatever arrived is left alone. There is nothing to fail
    /// closed to — trusting the inbound value is this variant's premise.
    #[cfg(not(debug_assertions))]
    #[test]
    fn a_rejected_preserve_trusted_or_set_scheme_writes_nothing() {
        let mut present = HeaderMap::new();
        present.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
        apply_forwarded(
            &mut present,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::PreserveTrustedOrSet("https, http"),
                ..INERT
            },
        );
        assert_eq!(lines(&present, X_FORWARDED_PROTO), vec!["http"]);

        let mut absent = HeaderMap::new();
        apply_forwarded(
            &mut absent,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::PreserveTrustedOrSet("https, http"),
                ..INERT
            },
        );
        assert!(!absent.contains_key(X_FORWARDED_PROTO));
    }

    /// The release behavior of the collision the debug assert catches: the
    /// pair is dropped, so the `XfpPolicy`'s answer stands. Two things had to
    /// be true for that — the pair is skipped by name, and the scheme is
    /// applied after the overrides loop — and either one alone would do it,
    /// which is the point of doing both.
    #[cfg(not(debug_assertions))]
    #[test]
    fn in_release_a_colliding_override_pair_is_skipped_and_the_policy_stands() {
        let mut overridden = HeaderMap::new();
        apply_forwarded(
            &mut overridden,
            None,
            &ForwardedPolicy {
                xfp: XfpPolicy::Override("https"),
                overrides: &[(X_FORWARDED_PROTO, "http"), ("x-tenant", "acme")],
                ..INERT
            },
        );
        assert_eq!(lines(&overridden, X_FORWARDED_PROTO), vec!["https"]);
        assert_eq!(
            lines(&overridden, "x-tenant"),
            vec!["acme"],
            "only the colliding pair is dropped"
        );

        // …including when the policy's answer is "do nothing": the generic
        // list is never a back door onto this header.
        let mut untouched = HeaderMap::new();
        apply_forwarded(
            &mut untouched,
            None,
            &ForwardedPolicy {
                overrides: &[(X_FORWARDED_PROTO, "https")],
                ..INERT
            },
        );
        assert!(!untouched.contains_key(X_FORWARDED_PROTO));
    }

    // --- the whole policy at once ------------------------------------------

    #[test]
    fn an_inert_policy_touches_nothing() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.1"));
        let before = headers.clone();
        apply_forwarded(&mut headers, ip("203.0.113.9"), &INERT);
        assert_eq!(headers, before);
    }

    #[test]
    fn the_slauth_shaped_policy_appends_the_peer_and_pins_the_scheme() {
        // The composed case: a caller-supplied chain and scheme, a real peer,
        // and a server-set override — the shape slauth's Hydra leg uses.
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.1"));
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
        apply_forwarded(
            &mut headers,
            ip("203.0.113.9"),
            &ForwardedPolicy {
                xff: XffPolicy::Append,
                xfp: XfpPolicy::Override("https"),
                overrides: &[("x-tenant", "acme")],
            },
        );
        assert_eq!(
            lines(&headers, X_FORWARDED_FOR),
            vec!["198.51.100.1, 203.0.113.9"]
        );
        assert_eq!(lines(&headers, X_FORWARDED_PROTO), vec!["https"]);
        assert_eq!(lines(&headers, "x-tenant"), vec!["acme"]);
    }
}
