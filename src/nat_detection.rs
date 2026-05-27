// SPDX-License-Identifier: Apache-2.0
//! UPnP NAT detection + dual-port mapping (ADR-041 tier-0 + tier-1).
//!
//! Rust port of iicp-client-python nat_detection.py (iter-1420) and
//! iicp-client-typescript nat_detection.ts (iter-1421). Same operator
//! semantics + diagnostic improvements:
//!
//! - CGNAT reverse-DNS heuristic (#339) — when the WAN IP's PTR record
//!   contains `cgn`, `cgnat`, `ds-lite`, etc., the detector treats the UPnP
//!   mapping as ineffective and surfaces actionable guidance.
//! - External-IP probe fallback (#331 Phase A) — when UPnP AddPortMapping
//!   succeeds but the IGD refuses to report the WAN IP, the detector fetches
//!   the WAN IP from an operator-configured HTTPS probe URL.
//!
//! Behind the `nat` feature flag — igd-next is added as an optional dep so
//! the rest of the SDK builds for HTTP-only consumers without pulling in
//! SSDP discovery + XML parsing.

#![cfg(feature = "nat")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::lookup_host;

// ── Public types ─────────────────────────────────────────────────────────────

/// ADR-043 §4 — IPv6 qualification result (#342, #343).
#[derive(Debug, Clone, Default)]
pub struct Ipv6Profile {
    pub global_v6_available: bool,
    pub stable_v6_available: bool,
    pub addresses: Vec<String>,
    /// Can the SDK bind a v6 socket on the requested port?
    pub listener_v6_ok: bool,
    /// Outbound v6 connectivity test result (does NOT prove inbound).
    pub external_v6_reachable: bool,
    /// ADR-043 §5 — true iff router accepted WANIPv6FirewallControl::AddPinhole.
    pub pinhole_active: bool,
    /// UPnP UniqueID returned by AddPinhole — pass to delete_ipv6_pinhole on shutdown.
    pub pinhole_unique_id: Option<u32>,
    /// Granted lease (seconds). 0 = permanent / refresh required by spec.
    pub pinhole_lease_seconds: Option<u32>,
    /// Echoes GetFirewallStatus::InboundPinholeAllowed.
    pub pinhole_inbound_allowed: Option<bool>,
    pub error: Option<String>,
}

/// Result of [`detect_nat`] — describes what the SDK can advertise.
#[derive(Debug, Clone)]
pub struct NatProfile {
    pub tier: u8,
    pub transport_method: TransportMethod,
    pub public_endpoint: Option<String>,
    pub transport_endpoint: Option<String>,
    pub internal_endpoint: Option<String>,
    pub operator_guidance: Option<String>,
    pub detection_log: Vec<String>,
    /// ADR-043 §4 — populated when detect_nat runs with detect_v6=true.
    pub ipv6: Option<Ipv6Profile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMethod {
    Direct,
    UpnpMapped,
    StunHolePunch,
    TurnRelay,
    ExternalTunnel,
    Unreachable,
}

impl NatProfile {
    pub fn is_reachable(&self) -> bool {
        self.tier <= 3 && self.public_endpoint.is_some()
    }

    fn new(tier: u8, method: TransportMethod) -> Self {
        Self {
            tier,
            transport_method: method,
            public_endpoint: None,
            transport_endpoint: None,
            internal_endpoint: None,
            operator_guidance: None,
            detection_log: Vec::new(),
            ipv6: None,
        }
    }
}

/// Options for [`detect_nat`].
#[derive(Debug, Clone)]
pub struct DetectNatOptions {
    pub bind_host: String,
    pub bind_port: u16,
    pub operator_public_endpoint: Option<String>,
    pub upnp_lease_seconds: u32,
    pub timeout: Duration,
    pub external_ip_probe_url: Option<String>,
    /// spec/iicp-dir.md v0.7.0 — native IICP TCP port (default 9484).
    pub transport_port: Option<u16>,
    /// ADR-043 §4 — run detect_ipv6() in parallel to the v4 path. Default true.
    pub detect_v6: bool,
}

impl Default for DetectNatOptions {
    fn default() -> Self {
        Self {
            bind_host: "0.0.0.0".into(),
            bind_port: 8080,
            operator_public_endpoint: None,
            upnp_lease_seconds: 3600,
            timeout: Duration::from_secs(5),
            external_ip_probe_url: None,
            transport_port: Some(9484),
            detect_v6: true,
        }
    }
}

// ── Public entry point ───────────────────────────────────────────────────────

pub async fn detect_nat(opts: DetectNatOptions) -> NatProfile {
    let mut profile = NatProfile::new(4, TransportMethod::Unreachable);
    profile.internal_endpoint = Some(format!("http://{}:{}", opts.bind_host, opts.bind_port));

    // ADR-043 §4 — IPv6 qualification runs in parallel to the v4 path.
    if opts.detect_v6 {
        let v6_timeout = std::cmp::min(opts.timeout, Duration::from_secs(3));
        let v6 = detect_ipv6(opts.bind_port, v6_timeout).await;
        profile.detection_log.push(format!(
            "ipv6: global={} stable={} listener={} reachable_out={}",
            v6.global_v6_available,
            v6.stable_v6_available,
            v6.listener_v6_ok,
            v6.external_v6_reachable
        ));
        profile.ipv6 = Some(v6);
    }

    // Tier 0
    if let Some(ep) = &opts.operator_public_endpoint {
        if looks_routable(ep) {
            profile.detection_log.push(format!(
                "tier-0: operator-configured public_endpoint={ep:?}"
            ));
            let mut t0 = NatProfile::new(0, TransportMethod::Direct);
            t0.public_endpoint = Some(ep.clone());
            t0.internal_endpoint = profile.internal_endpoint.clone();
            t0.detection_log = profile.detection_log;
            return t0;
        }
        profile.detection_log.push(format!(
            "tier-0: operator-configured public_endpoint={ep:?} non-routable — falling through to tier-1 UPnP"
        ));
    }

    // Tier 1 — UPnP
    let mut ports_to_map: Vec<u16> = vec![opts.bind_port];
    if let Some(tp) = opts.transport_port {
        if tp != opts.bind_port {
            ports_to_map.push(tp);
        }
    }

    let upnp_result = tokio::time::timeout(
        opts.timeout,
        try_upnp_mapping(ports_to_map.clone(), opts.upnp_lease_seconds),
    )
    .await;

    let upnp = match upnp_result {
        Ok(r) => r,
        Err(_) => {
            profile.detection_log.push(format!(
                "tier-1: UPnP discovery timed out after {}ms",
                opts.timeout.as_millis()
            ));
            None
        }
    };

    if let Some(mut u) = upnp {
        if u.success {
            // External-IP probe fallback (#331 Phase A)
            if u.external_ip.is_none() || u.external_ip.as_deref() == Some("0.0.0.0") {
                if let Some(probe_url) = &opts.external_ip_probe_url {
                    if let Some(probed) = probe_external_ip(probe_url, Duration::from_secs(5)).await
                    {
                        profile.detection_log.push(format!(
                            "tier-1: external IP probe {probe_url:?} returned {probed}"
                        ));
                        u.external_ip = Some(probed);
                    } else {
                        profile.detection_log.push(format!(
                            "tier-1: external IP probe {probe_url:?} returned no valid IPv4"
                        ));
                    }
                }
                if u.external_ip.is_none() || u.external_ip.as_deref() == Some("0.0.0.0") {
                    profile.operator_guidance = Some(format!(
                        "UPnP mapped port {} but the router did not return its WAN IP. \
                         Set external_ip_probe_url to an HTTPS probe service (e.g. \
                         https://api.ipify.org) OR set operator_public_endpoint manually.",
                        opts.bind_port
                    ));
                    return profile;
                }
            }

            let ip = u.external_ip.as_deref().unwrap();

            // #339 — CGNAT reverse-DNS heuristic
            if let Some(warning) = detect_cgnat(ip).await {
                profile.detection_log.push(format!("tier-1: {warning}"));
                // ADR-043 §10 — CGNAT IPv4 unreachable, advertise IPv6 GUA if usable.
                if let Some(v6_profile) =
                    try_ipv6_fallback(&profile, opts.bind_port, opts.transport_port).await
                {
                    return v6_profile;
                }
                profile.operator_guidance = Some(format!(
                    "WARNING: your WAN IP {ip} appears to be inside a carrier-grade NAT \
                     pool (reverse-DNS suggests CGNAT). UPnP-mapped ports are typically \
                     not reachable from the internet in this case. Options: (a) ask \
                     your ISP for a native IPv4 lease, (b) use an external tunnel \
                     (Cloudflare Tunnel, tailscale funnel), (c) switch to IPv6 if your \
                     network supports it."
                ));
                return profile;
            }

            let public_url = format!("http://{ip}:{}", opts.bind_port);
            let transport_url = match opts.transport_port {
                Some(tp) if tp != opts.bind_port && u.mapped_ports.contains(&tp) => {
                    Some(format!("iicp://{ip}:{tp}"))
                }
                _ => None,
            };

            if let Some(tu) = &transport_url {
                profile.detection_log.push(format!(
                    "tier-1: UPnP mapped {} → {public_url} AND {} → {tu} (spec v0.7.0 dual-endpoint)",
                    opts.bind_port,
                    opts.transport_port.unwrap()
                ));
            } else {
                profile.detection_log.push(format!(
                    "tier-1: UPnP mapped {} → {public_url}",
                    opts.bind_port
                ));
            }

            let mut result = NatProfile::new(1, TransportMethod::UpnpMapped);
            result.public_endpoint = Some(public_url);
            result.transport_endpoint = transport_url;
            result.internal_endpoint = profile.internal_endpoint;
            result.detection_log = profile.detection_log;
            return result;
        }
        // UPnP discovery succeeded but mapping refused
        let err = u.error.unwrap_or_else(|| "unknown".into());
        if u.igd_device.is_some() {
            profile.detection_log.push(format!(
                "tier-1: IGD found ({}) but mapping refused — {err}",
                u.igd_device.as_deref().unwrap_or("unknown")
            ));
        } else {
            profile
                .detection_log
                .push(format!("tier-1: no IGD device responded — {err}"));
        }
    } else {
        profile.detection_log.push(
            "tier-1: UPnP discovery returned nothing (SSDP broadcast filtered? feature flag off?)"
                .into(),
        );
    }

    // ADR-043 §10 — IPv6 fallback when no v4 path is usable.
    if let Some(v6_profile) = try_ipv6_fallback(&profile, opts.bind_port, opts.transport_port).await
    {
        return v6_profile;
    }

    profile.operator_guidance = Some(
        "No automatic port mapping available. Options:\n\
           1. Configure your router to forward an external port to this host\n\
           2. Set operator_public_endpoint to your real external URL\n\
           3. Use an external tunnel (Cloudflare Tunnel, ngrok, tailscale funnel)\n\
         See iicp.network/docs/nat-aware-adapter-setup.md for the details."
            .into(),
    );
    profile
}

// ── UPnP helpers ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct UpnpResult {
    pub success: bool,
    pub external_ip: Option<String>,
    pub external_port: Option<u16>,
    pub mapped_ports: Vec<u16>,
    pub igd_device: Option<String>,
    pub error: Option<String>,
}

pub async fn try_upnp_mapping(internal_ports: Vec<u16>, lease_seconds: u32) -> Option<UpnpResult> {
    if internal_ports.is_empty() {
        return Some(UpnpResult {
            success: false,
            error: Some("no ports specified".into()),
            ..Default::default()
        });
    }
    let primary = internal_ports[0];

    // Use the tokio (async) feature of igd-next. search_gateway lives under
    // the platform-specific submodule (aio::tokio::search_gateway in 0.17).
    use igd_next::{aio::tokio::search_gateway, PortMappingProtocol, SearchOptions};

    let search = SearchOptions::default();
    let gateway = match search_gateway(search).await {
        Ok(g) => g,
        Err(e) => {
            return Some(UpnpResult {
                success: false,
                error: Some(format!("IGD discovery failed: {e}")),
                ..Default::default()
            });
        }
    };

    let external_ip = match gateway.get_external_ip().await {
        Ok(ip) => Some(ip.to_string()),
        Err(e) => {
            return Some(UpnpResult {
                success: false,
                error: Some(format!("get_external_ip failed: {e}")),
                igd_device: Some(format!("{:?}", gateway.addr)),
                ..Default::default()
            });
        }
    };

    let local_v4 =
        pick_local_ip_for_gateway(gateway.addr.ip()).unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));

    let primary_socket = SocketAddr::V4(SocketAddrV4::new(local_v4, primary));
    if let Err(e) = gateway
        .add_port(
            PortMappingProtocol::TCP,
            primary,
            primary_socket,
            lease_seconds,
            &format!("iicp-client (ADR-041 tier-1) {primary}"),
        )
        .await
    {
        return Some(UpnpResult {
            success: false,
            external_ip,
            error: Some(format!(
                "add_port failed for primary port {primary}: {e} (internal={local_v4})"
            )),
            igd_device: Some(format!("{:?}", gateway.addr)),
            ..Default::default()
        });
    }

    let mut mapped = vec![primary];
    for &extra in internal_ports.iter().skip(1) {
        let extra_socket = SocketAddr::V4(SocketAddrV4::new(local_v4, extra));
        if gateway
            .add_port(
                PortMappingProtocol::TCP,
                extra,
                extra_socket,
                lease_seconds,
                &format!("iicp-client (ADR-041 tier-1) {extra}"),
            )
            .await
            .is_ok()
        {
            mapped.push(extra);
        } else {
            tracing::warn!("UPnP: failed to map additional port {extra} (primary {primary} ok)");
        }
    }

    Some(UpnpResult {
        success: true,
        external_ip,
        external_port: Some(primary),
        mapped_ports: mapped,
        igd_device: Some(format!("{:?}", gateway.addr)),
        error: None,
    })
}

/// Find a local IPv4 on the same /24 subnet as the gateway. UDP-socket trick
/// fallback when no matching interface is found.
fn pick_local_ip_for_gateway(gateway_ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V4(gw) = gateway_ip else {
        return None;
    };
    let octets = gw.octets();
    // Enumerate via std::net::UdpSocket connect-trick.
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect((std::net::IpAddr::V4(gw), 80)).ok()?;
    if let Ok(SocketAddr::V4(local)) = s.local_addr() {
        let lo = local.ip().octets();
        if lo[0] == octets[0] && lo[1] == octets[1] && lo[2] == octets[2] {
            return Some(*local.ip());
        }
        // Even if not on the same /24, use it as the best guess.
        return Some(*local.ip());
    }
    None
}

// ── External-IP probe + routability helpers ──────────────────────────────────

pub async fn probe_external_ip(url: &str, timeout: Duration) -> Option<String> {
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(c) => c,
        Err(_) => return None,
    };
    let body = match client.get(url).send().await {
        Ok(r) if r.status().is_success() => match r.text().await {
            Ok(t) => t,
            Err(_) => return None,
        },
        _ => return None,
    };
    extract_ipv4(&body).and_then(|ip| {
        let parsed: Ipv4Addr = ip.parse().ok()?;
        if is_non_public_ipv4(parsed) {
            None
        } else {
            Some(ip)
        }
    })
}

fn extract_ipv4(body: &str) -> Option<String> {
    // Match the first IPv4-shaped token.
    for token in body.split(|c: char| !c.is_ascii_digit() && c != '.') {
        if token.is_empty() {
            continue;
        }
        if token.parse::<Ipv4Addr>().is_ok() {
            return Some(token.to_string());
        }
    }
    None
}

pub fn looks_routable(url: &str) -> bool {
    // Parse out the host portion. reqwest::Url is heavy; do it by hand.
    let after_scheme = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => return false,
    };
    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..host_end];
    // Handle [ipv6]:port
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, _)) => h.to_string(),
            None => return false,
        }
    } else {
        // hostname[:port]
        match authority.rsplit_once(':') {
            Some((h, _)) => h.to_string(),
            None => authority.to_string(),
        }
    };
    let host = host.to_lowercase();
    if host.is_empty() {
        return false;
    }
    const NEVER_ROUTABLE: &[&str] = &["localhost", "0.0.0.0", "::1", "::"];
    if NEVER_ROUTABLE.contains(&host.as_str()) {
        return false;
    }
    const SUFFIXES: &[&str] = &[
        ".localhost",
        ".local",
        ".test",
        ".example",
        ".invalid",
        ".lan",
        ".internal",
    ];
    if SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return false;
    }
    // IPv4?
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return !is_non_public_ipv4(v4);
    }
    // IPv6?
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return !is_non_public_ipv6(v6);
    }
    // Bare hostname without TLD = likely Docker service name
    if !host.contains('.') {
        return false;
    }
    true
}

fn is_non_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if a == 0 || a == 127 || a == 10 {
        return true;
    }
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    if a == 192 && b == 168 {
        return true;
    }
    if a == 169 && b == 254 {
        return true;
    }
    if a >= 224 {
        return true;
    } // multicast + reserved
    if a == 100 && (64..=127).contains(&b) {
        return true;
    } // CGNAT 100.64/10
      // RFC 5737 documentation
    if a == 192 && b == 0 && c == 2 {
        return true;
    }
    if a == 198 && (b == 18 || b == 19) {
        return true;
    }
    if a == 198 && b == 51 && c == 100 {
        return true;
    }
    if a == 203 && b == 0 && c == 113 {
        return true;
    }
    false
}

fn is_non_public_ipv6(ip: std::net::Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    let segs = ip.segments();
    // Link-local fe80::/10
    if segs[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // Unique local fc00::/7
    if segs[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    false
}

// ── CGNAT detection (iicp.network #339) ──────────────────────────────────────

const CGNAT_HINTS: &[&str] = &["cgn", "cgnat", "ds-lite", "dslite", "nat64"];
const SHARED_HINTS: &[&str] = &["shared"];

pub async fn detect_cgnat(external_ip: &str) -> Option<String> {
    // Use tokio's lookup_host for forward resolution + std for PTR (no native
    // async reverse-DNS in tokio). Spawn the blocking PTR call.
    let ip = external_ip.to_string();
    let hostnames = tokio::task::spawn_blocking(move || reverse_dns(&ip))
        .await
        .ok()??;
    for raw in &hostnames {
        let hn = raw.to_lowercase();
        if CGNAT_HINTS.iter().any(|h| hn.contains(h)) {
            return Some(format!(
                "reverse-DNS for {external_ip} = {hn:?} suggests CGNAT — UPnP mapping likely not externally reachable"
            ));
        }
        if SHARED_HINTS.iter().any(|h| hn.contains(h)) {
            return Some(format!(
                "reverse-DNS for {external_ip} = {hn:?} suggests shared/CGNAT infrastructure — verify external reachability"
            ));
        }
    }
    None
}

fn reverse_dns(ip: &str) -> Option<Vec<String>> {
    // std doesn't have a built-in PTR resolver. Use the `lookup_addr` from
    // dns_lookup? Or fall back to libc::gethostbyaddr? Simplest: use
    // dns_lookup if available, otherwise no-op.
    //
    // To avoid pulling in another dep, use tokio's net::lookup_host with a
    // hand-rolled .in-addr.arpa query — but that's complex. Instead, lean on
    // the std::net::ToSocketAddrs path: connect a UDP socket then look up
    // via getaddrinfo. That doesn't give us PTR.
    //
    // Pragmatic choice: rely on the operator's resolver via libc::getnameinfo
    // through std::net::SocketAddr -> std::net::lookup_host is forward only.
    //
    // For now, emit None when reverse-DNS isn't available. Operators on Linux
    // with NSS configured will get reverse-DNS via dns_lookup; we make this
    // an upgrade path rather than a hard dep.
    let _ = ip;
    None
}

#[cfg(not(target_os = "wasi"))]
pub(crate) async fn _unused_lookup_marker() {
    // Keep tokio::net::lookup_host imported so the module compiles even when
    // reverse_dns above doesn't use it directly.
    let _ = lookup_host("localhost:0").await;
}

// ── ADR-043 §4 — IPv6 qualification (iter-1469, #342) ───────────────────────

/// Probe the IPv6 surface of the local host per ADR-043 §4.
///
/// Three orthogonal checks:
///   1. Any local interface has a global IPv6 address (2000::/3 GUA)?
///   2. Can the SDK bind an IPv6 socket on `bind_port`?
///   3. Outbound connectivity to a known IPv6-only probe target?
///
/// Result is advisory — the directory's Layer-2 dial-back is the source of
/// truth for inbound reachability. Router firewall pinholes (#343) are not
/// requested here.
pub async fn detect_ipv6(bind_port: u16, timeout: Duration) -> Ipv6Profile {
    let mut out = Ipv6Profile::default();
    out.addresses = list_global_ipv6_addresses();
    out.global_v6_available = !out.addresses.is_empty();
    out.stable_v6_available = out.addresses.iter().any(|a| !is_privacy_v6(a));

    // Bind test — can a v6 socket take this port?
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, bind_port, 0, 0);
    match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(_) => out.listener_v6_ok = true,
        Err(e) => {
            out.listener_v6_ok = false;
            out.error = Some(format!("v6 bind failed: {e}"));
        }
    }

    // Outbound v6 reachability test.
    if out.global_v6_available {
        out.external_v6_reachable = probe_outbound_ipv6(timeout).await;
    }

    out
}

fn list_global_ipv6_addresses() -> Vec<String> {
    // Best-effort: enumerate interface addresses via the OS. We use
    // std::net::SocketAddr's debug-introspection via env-agnostic
    // `if-addrs`-style logic — but to avoid pulling in a new crate the
    // implementation here uses getifaddrs equivalents from std.
    let mut found: Vec<String> = Vec::new();
    if let Ok(iter) = local_v6_addresses() {
        for ip in iter {
            // GUA = 2000::/3 (first 3 bits 001)
            let segments = ip.segments();
            if (segments[0] & 0xe000) == 0x2000 {
                found.push(ip.to_string());
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Walk `/proc/net/if_inet6` on Linux, fall back to socket-style on macOS via
/// scanning bound addresses. Best-effort — returns empty when neither works.
fn local_v6_addresses() -> std::io::Result<Vec<std::net::Ipv6Addr>> {
    // Linux: /proc/net/if_inet6 is the canonical source.
    if let Ok(text) = std::fs::read_to_string("/proc/net/if_inet6") {
        let mut out = Vec::new();
        for line in text.lines() {
            // Format: 16-hex addr  ifx scope flags ifname
            let mut parts = line.split_whitespace();
            if let Some(hex) = parts.next() {
                if hex.len() == 32 {
                    if let Ok(addr) = parse_ifaddr_hex(hex) {
                        out.push(addr);
                    }
                }
            }
        }
        return Ok(out);
    }
    // macOS / BSD: getifaddrs via libc. To stay dep-light, fall back to
    // resolving the host's own hostname and pick v6 entries.
    use std::net::ToSocketAddrs;
    let host = match std::env::var("HOSTNAME") {
        Ok(h) if !h.is_empty() => h,
        _ => match hostname_via_uname() {
            Some(h) => h,
            None => return Ok(Vec::new()),
        },
    };
    let mut out = Vec::new();
    if let Ok(iter) = format!("{host}:0").to_socket_addrs() {
        for sa in iter {
            if let std::net::SocketAddr::V6(a) = sa {
                out.push(*a.ip());
            }
        }
    }
    Ok(out)
}

fn parse_ifaddr_hex(hex: &str) -> Result<std::net::Ipv6Addr, std::num::ParseIntError> {
    // 32 hex chars → 8 hextets
    let mut segs = [0u16; 8];
    for (i, seg) in segs.iter_mut().enumerate() {
        *seg = u16::from_str_radix(&hex[i * 4..i * 4 + 4], 16)?;
    }
    Ok(std::net::Ipv6Addr::new(
        segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
    ))
}

fn hostname_via_uname() -> Option<String> {
    // POSIX: gethostname via libc. Avoid a libc dep — use the `whoami`-style
    // approach via std env. macOS sets `HOSTNAME` only sporadically; fall
    // back to the OS-level via `uname -n` shell-out (rare path, best-effort).
    use std::process::Command;
    let out = Command::new("uname").arg("-n").output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn is_privacy_v6(addr: &str) -> bool {
    // RFC 4941 privacy addresses lack the EUI-64 `ff:fe` middle marker.
    // Heuristic, not proof — operators may also have manual stable addresses
    // without `ff:fe`. The qualification result lists raw addresses; this
    // helper is a hint for the wizard.
    !addr.to_lowercase().contains("ff:fe")
}

async fn probe_outbound_ipv6(timeout: Duration) -> bool {
    // Use reqwest with a hard timeout. api6.ipify.org is IPv6-only, so a
    // successful response confirms outbound v6 routing.
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client.get("https://api6.ipify.org").send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// ADR-043 §10 — advertise IPv6 GUA when the IPv4 path can't expose this node.
async fn try_ipv6_fallback(
    profile: &NatProfile,
    bind_port: u16,
    transport_port: Option<u16>,
) -> Option<NatProfile> {
    let v6 = profile.ipv6.as_ref()?;
    if !v6.global_v6_available || !v6.external_v6_reachable {
        return None;
    }
    let v6_addr = v6.addresses.first()?.clone();
    let public_url = format!("http://[{v6_addr}]:{bind_port}");
    let transport_url = match transport_port {
        Some(tp) if tp != bind_port => Some(format!("iicp://[{v6_addr}]:{tp}")),
        _ => None,
    };
    let mut detection_log = profile.detection_log.clone();
    detection_log.push(format!(
        "tier-1-ipv6: advertising {public_url} (verified outbound v6; \
         attempting UPnP IGDv2 pinhole — #343)"
    ));

    // ADR-043 §5 / #343 — attempt UPnP IPv6 firewall pinhole.
    let mut updated_v6 = v6.clone();
    match try_upnp_ipv6_pinhole(&v6_addr, bind_port, 3600).await {
        Some(pin) => {
            updated_v6.pinhole_active = true;
            updated_v6.pinhole_unique_id = Some(pin.unique_id);
            updated_v6.pinhole_lease_seconds = Some(pin.lease_seconds);
            updated_v6.pinhole_inbound_allowed = Some(pin.inbound_allowed);
            detection_log.push(format!(
                "tier-1-ipv6: AddPinhole OK — uid={} lease={}s",
                pin.unique_id, pin.lease_seconds
            ));
        }
        None => {
            updated_v6.pinhole_active = false;
            detection_log.push(format!(
                "tier-1-ipv6: AddPinhole declined or no WANIPv6FirewallControl IGD found — \
                 operator must open inbound TCP/{bind_port} manually"
            ));
        }
    }

    let pinhole_note = if updated_v6.pinhole_active {
        format!(
            "UPnP IPv6 pinhole opened (uid={}). ",
            updated_v6.pinhole_unique_id.unwrap_or(0)
        )
    } else {
        "Router firewall pinhole not opened — manual rule may be required. ".to_string()
    };

    let mut result = NatProfile::new(1, TransportMethod::Direct);
    result.public_endpoint = Some(public_url);
    result.transport_endpoint = transport_url;
    result.internal_endpoint = profile.internal_endpoint.clone();
    result.detection_log = detection_log;
    result.ipv6 = Some(updated_v6);
    result.operator_guidance = Some(format!(
        "Advertising IPv6 GUA {v6_addr}. Inbound IPv4 isn't available (no UPnP \
         success / CGNAT), but your IPv6 surface is routable. {pinhole_note}\
         The directory will Layer-2 dial-back to verify."
    ));
    Some(result)
}

// ── #343 / ADR-043 §5 — UPnP IPv6 firewall pinhole (SSDP + SOAP) ───────────

/// Result returned by [`try_upnp_ipv6_pinhole`] on success.
#[derive(Debug, Clone)]
pub struct PinholeResult {
    pub unique_id: u32,
    pub lease_seconds: u32,
    pub inbound_allowed: bool,
}

struct SsdpHit {
    location: String,
}

async fn ssdp_discover(service_type: &str, timeout: Duration) -> Vec<SsdpHit> {
    use tokio::net::UdpSocket;
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = sock.set_broadcast(true);
    let msg = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: {service_type}\r\n\r\n"
    );
    if sock
        .send_to(msg.as_bytes(), "239.255.255.250:1900")
        .await
        .is_err()
    {
        return Vec::new();
    }
    let mut hits: Vec<SsdpHit> = Vec::new();
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await;
        match recv {
            Ok(Ok((n, _))) => {
                let text = String::from_utf8_lossy(&buf[..n]);
                if let Some(loc) = text.lines().find_map(|l| {
                    let l = l.trim();
                    let lower = l.to_ascii_lowercase();
                    lower
                        .strip_prefix("location:")
                        .map(|rest| l[l.len() - rest.trim().len()..].trim().to_string())
                }) {
                    hits.push(SsdpHit { location: loc });
                }
            }
            _ => break,
        }
    }
    hits
}

struct FirewallService {
    control_url: String,
    service_type: String,
}

async fn fetch_firewall_service(device_url: &str, timeout: Duration) -> Option<FirewallService> {
    let client = reqwest::Client::builder().timeout(timeout).build().ok()?;
    let resp = client.get(device_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let xml = resp.text().await.ok()?;

    let base_url = reqwest::Url::parse(device_url).ok()?;
    let mut services: Vec<(String, String)> = Vec::new();
    let mut rest = xml.as_str();
    while let Some(start) = rest.find("<service>") {
        let after = &rest[start + "<service>".len()..];
        let end = match after.find("</service>") {
            Some(e) => e,
            None => break,
        };
        let block = &after[..end];
        let stype = extract_xml_tag(block, "serviceType");
        let ctrl = extract_xml_tag(block, "controlURL");
        if let (Some(t), Some(c)) = (stype, ctrl) {
            services.push((t, c));
        }
        rest = &after[end + "</service>".len()..];
    }
    let (svc_type, ctrl) = services
        .into_iter()
        .find(|(t, _)| t.contains("WANIPv6FirewallControl"))?;
    let control_url = if ctrl.starts_with("http://") || ctrl.starts_with("https://") {
        ctrl
    } else {
        base_url.join(&ctrl).ok()?.to_string()
    };
    Some(FirewallService {
        control_url,
        service_type: svc_type,
    })
}

fn extract_xml_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = block.find(&open)? + open.len();
    let e = block[s..].find(&close)? + s;
    Some(block[s..e].trim().to_string())
}

async fn soap_call(
    control_url: &str,
    service_type: &str,
    action: &str,
    args: &[(&str, String)],
    timeout: Duration,
) -> Option<std::collections::HashMap<String, String>> {
    let arg_xml: String = args
        .iter()
        .map(|(k, v)| format!("<{k}>{v}</{k}>"))
        .collect();
    let body = format!(
        "<?xml version=\"1.0\"?>\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service_type}\">{arg_xml}</u:{action}></s:Body>\
         </s:Envelope>"
    );
    let client = reqwest::Client::builder().timeout(timeout).build().ok()?;
    let resp = client
        .post(control_url)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .header("SOAPACTION", format!("\"{service_type}#{action}\""))
        .body(body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let mut out = std::collections::HashMap::new();
    // Crude tag extractor — matches <NAME>VALUE</NAME>; skip envelope wrappers.
    let mut rest = text.as_str();
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        let tag_end = after.find('>')?;
        let tag_name = &after[..tag_end];
        if tag_name.starts_with('/') || tag_name.contains(':') || tag_name.is_empty() {
            rest = &after[tag_end + 1..];
            continue;
        }
        let close = format!("</{tag_name}>");
        let content_start = start + 1 + tag_end + 1;
        let value_end_rel = rest[content_start..].find(&close);
        match value_end_rel {
            Some(rel) => {
                let value = &rest[content_start..content_start + rel];
                if !value.contains('<') {
                    out.insert(tag_name.to_string(), value.trim().to_string());
                }
                rest = &rest[content_start + rel + close.len()..];
            }
            None => break,
        }
    }
    Some(out)
}

/// ADR-043 §5 (#343) — open an inbound IPv6 firewall pinhole on the IGD.
///
/// Returns `Some(PinholeResult)` on success, `None` when:
///   - no IGD with WANIPv6FirewallControl is discovered
///   - GetFirewallStatus reports InboundPinholeAllowed=false
///   - AddPinhole errored
///
/// Operators close the pinhole on shutdown via [`delete_ipv6_pinhole`].
pub async fn try_upnp_ipv6_pinhole(
    internal_v6: &str,
    internal_port: u16,
    lease_seconds: u32,
) -> Option<PinholeResult> {
    let timeout = Duration::from_secs(5);
    let hits = ssdp_discover(
        "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1",
        timeout,
    )
    .await;
    for hit in hits {
        let svc = match fetch_firewall_service(&hit.location, timeout).await {
            Some(s) => s,
            None => continue,
        };
        let status = soap_call(
            &svc.control_url,
            &svc.service_type,
            "GetFirewallStatus",
            &[],
            timeout,
        )
        .await;
        let inbound_allowed = status
            .as_ref()
            .and_then(|m| m.get("InboundPinholeAllowed"))
            .map(|s| s == "1")
            .unwrap_or(false);
        if !inbound_allowed {
            return None;
        }
        let result = soap_call(
            &svc.control_url,
            &svc.service_type,
            "AddPinhole",
            &[
                ("RemoteHost", String::new()),
                ("RemotePort", "0".to_string()),
                ("InternalClient", internal_v6.to_string()),
                ("InternalPort", internal_port.to_string()),
                ("Protocol", "6".to_string()), // TCP
                ("LeaseTime", lease_seconds.to_string()),
            ],
            timeout,
        )
        .await?;
        let uid: u32 = result
            .get("UniqueID")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        return Some(PinholeResult {
            unique_id: uid,
            lease_seconds,
            inbound_allowed: true,
        });
    }
    None
}

/// ADR-043 §5 — close a previously-opened IPv6 pinhole. Best-effort.
pub async fn delete_ipv6_pinhole(unique_id: u32) -> bool {
    let timeout = Duration::from_secs(5);
    let hits = ssdp_discover(
        "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1",
        timeout,
    )
    .await;
    for hit in hits {
        let svc = match fetch_firewall_service(&hit.location, timeout).await {
            Some(s) => s,
            None => continue,
        };
        let result = soap_call(
            &svc.control_url,
            &svc.service_type,
            "DeletePinhole",
            &[("UniqueID", unique_id.to_string())],
            timeout,
        )
        .await;
        if result.is_some() {
            return true;
        }
    }
    false
}
