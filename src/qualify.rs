//! ADR-043 §9/§11 — ServiceQualification: 8-category exposure enum + structured result.
//!
//! Maps a [`NatProfile`] to the canonical [`ExposureMode`] string and a
//! [`ServiceQualification`] struct suitable for directory storage as
//! `nodes.exposure_mode`.
//!
//! # Example
//! ```no_run
//! use iicp_client::{qualify_service, detect_nat, DetectNatOptions};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let profile = detect_nat(DetectNatOptions::default()).await?;
//! let sq = qualify_service(&profile);
//! println!("{}", sq.exposure_mode);  // e.g. "ipv4_public_direct"
//! # Ok(()) }
//! ```

use crate::nat_detection::{NatProfile, TransportMethod};

// ── 8-category exposure enum ──────────────────────────────────────────────────

/// ADR-043 §9 — canonical 8-category network exposure classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposureMode {
    OutboundOnly,
    Ipv4PublicDirect,
    Ipv4CgnatBlocked,
    Ipv6DirectFirewallRequired,
    Ipv6DirectPinholeAvailable,
    RelayRequired,
    TunnelRequired,
    DualStackAvailable,
}

impl ExposureMode {
    /// Canonical string value stored in `nodes.exposure_mode`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OutboundOnly => "outbound_only",
            Self::Ipv4PublicDirect => "ipv4_public_direct",
            Self::Ipv4CgnatBlocked => "ipv4_cgnat_blocked",
            Self::Ipv6DirectFirewallRequired => "ipv6_direct_firewall_required",
            Self::Ipv6DirectPinholeAvailable => "ipv6_direct_pinhole_available",
            Self::RelayRequired => "relay_required",
            Self::TunnelRequired => "tunnel_required",
            Self::DualStackAvailable => "dual_stack_available",
        }
    }
}

impl std::fmt::Display for ExposureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Result struct ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ipv4Qualification {
    pub public_ip: Option<String>,
    pub cgnat: bool,
    pub upnp_mapped: bool,
}

#[derive(Debug, Clone)]
pub struct Ipv6Qualification {
    pub routable: bool,
    pub pinhole_ok: bool,
    pub address: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExposureQualification {
    pub public_endpoint: Option<String>,
    pub transport_endpoint: Option<String>,
}

/// ADR-043 §11 — structured result of service qualification.
#[derive(Debug, Clone)]
pub struct ServiceQualification {
    pub exposure_mode: ExposureMode,
    pub ipv4: Ipv4Qualification,
    pub ipv6: Ipv6Qualification,
    pub exposure: ExposureQualification,
    pub recommendation: String,
}

// ── Core mapping ──────────────────────────────────────────────────────────────

/// Map a [`NatProfile`] to an ADR-043 [`ServiceQualification`].
///
/// Synchronous — call after awaiting [`detect_nat`].
/// For a combined detect + qualify flow use [`qualify_service_async`].
pub fn qualify_service(profile: &NatProfile) -> ServiceQualification {
    let ipv4 = build_ipv4(profile);
    let ipv6 = build_ipv6(profile);
    let exposure_mode = derive_exposure_mode(profile, &ipv4, &ipv6);
    let recommendation = build_recommendation(&exposure_mode, profile);

    ServiceQualification {
        exposure: ExposureQualification {
            public_endpoint: profile.public_endpoint.clone(),
            transport_endpoint: profile.transport_endpoint.clone(),
        },
        exposure_mode,
        ipv4,
        ipv6,
        recommendation,
    }
}

/// Run NAT detection and qualify the result in one async step.
pub async fn qualify_service_async(
    opts: crate::nat_detection::DetectNatOptions,
) -> ServiceQualification {
    let profile = crate::nat_detection::detect_nat(opts).await;
    qualify_service(&profile)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn extract_ip(endpoint: &Option<String>) -> Option<String> {
    let ep = endpoint.as_deref()?;
    let re = regex::Regex::new(r"https?://([^:/]+)").ok()?;
    re.captures(ep)?.get(1).map(|m| m.as_str().to_string())
}

fn build_ipv4(profile: &NatProfile) -> Ipv4Qualification {
    let cgnat = profile.detection_log.iter().any(|l| {
        let lo = l.to_lowercase();
        lo.contains("cgnat") || lo.contains("ds-lite") || lo.contains("carrier-grade")
    });
    Ipv4Qualification {
        public_ip: extract_ip(&profile.public_endpoint),
        cgnat,
        upnp_mapped: profile.transport_method == TransportMethod::UpnpMapped,
    }
}

fn build_ipv6(profile: &NatProfile) -> Ipv6Qualification {
    match &profile.ipv6 {
        None => Ipv6Qualification {
            routable: false,
            pinhole_ok: false,
            address: None,
        },
        Some(v6) => Ipv6Qualification {
            routable: !v6.addresses.is_empty(),
            pinhole_ok: v6.pinhole_active && v6.pinhole_inbound_allowed.unwrap_or(false),
            address: v6.addresses.first().cloned(),
        },
    }
}

fn derive_exposure_mode(
    profile: &NatProfile,
    ipv4: &Ipv4Qualification,
    ipv6: &Ipv6Qualification,
) -> ExposureMode {
    if profile.tier == 3 {
        return ExposureMode::RelayRequired;
    }
    if profile.tier == 2 || profile.transport_method == TransportMethod::ExternalTunnel {
        return ExposureMode::TunnelRequired;
    }
    if profile.tier == 4 || profile.public_endpoint.is_none() {
        return if ipv4.cgnat {
            ExposureMode::Ipv4CgnatBlocked
        } else {
            ExposureMode::OutboundOnly
        };
    }
    // tier 0 or 1
    let ipv4_ok = profile.public_endpoint.is_some();
    if ipv4_ok && ipv6.routable && ipv6.pinhole_ok {
        return ExposureMode::DualStackAvailable;
    }
    if !ipv4_ok && ipv6.routable {
        return if ipv6.pinhole_ok {
            ExposureMode::Ipv6DirectPinholeAvailable
        } else {
            ExposureMode::Ipv6DirectFirewallRequired
        };
    }
    ExposureMode::Ipv4PublicDirect
}

fn build_recommendation(mode: &ExposureMode, profile: &NatProfile) -> String {
    let base = match mode {
        ExposureMode::Ipv4PublicDirect => "Direct IPv4 connection available. No additional setup needed.",
        ExposureMode::DualStackAvailable => "Dual-stack (IPv4 + IPv6) available. Consumers can reach you on either path.",
        ExposureMode::Ipv6DirectPinholeAvailable => "IPv6 direct connection available with firewall pinhole. IPv4 unreachable.",
        ExposureMode::Ipv6DirectFirewallRequired => "IPv6 address routable but firewall is blocking. Open the relevant port.",
        ExposureMode::RelayRequired => "Behind CGNAT or strict firewall — use relay mode (iicp-node --relay-worker-endpoint).",
        ExposureMode::TunnelRequired => "External tunnel detected (ngrok/Tailscale). Advertise the tunnel URL as public endpoint.",
        ExposureMode::Ipv4CgnatBlocked => "Carrier-grade NAT detected. Relay mode is the recommended path.",
        ExposureMode::OutboundOnly => "No inbound connectivity detected. Set --public-endpoint manually or use relay mode.",
    };
    match &profile.operator_guidance {
        Some(g) => format!("{base} {g}"),
        None => base.to_string(),
    }
}
