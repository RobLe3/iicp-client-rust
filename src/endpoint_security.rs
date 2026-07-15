// SPDX-License-Identifier: Apache-2.0
//! DNS-aware endpoint validation and connection pinning (#667).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use reqwest::Url;

use crate::errors::{IicpError, Result};

const BLOCKED_SUFFIXES: &[&str] = &[
    ".local",
    ".internal",
    ".lan",
    ".test",
    ".invalid",
    ".localhost",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedEndpoint {
    pub(crate) url: Url,
    pub(crate) host: String,
    pub(crate) addresses: Vec<SocketAddr>,
}

pub(crate) fn private_endpoints_allowed() -> bool {
    matches!(
        std::env::var("IICP_PROXY_ALLOW_LOOPBACK_NODES")
            .as_deref()
            .map(str::trim),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

pub(crate) fn hostname_allowed(host: &str, allow_private: bool) -> bool {
    if host.is_empty() {
        return false;
    }
    if allow_private {
        return true;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if matches!(host.as_str(), "localhost" | "0.0.0.0" | "::1" | "::") {
        return false;
    }
    if BLOCKED_SUFFIXES.iter().any(|suffix| host.ends_with(suffix)) {
        return false;
    }
    host.parse::<IpAddr>().is_ok() || host.contains('.') || host.contains(':')
}

pub(crate) fn address_allowed(address: IpAddr, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    match address {
        IpAddr::V4(v4) => ipv4_allowed(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(ipv4_allowed)
            .unwrap_or_else(|| ipv6_allowed(v6)),
    }
}

fn ipv4_allowed(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn ipv6_allowed(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || segments[0] == 0x0100
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

pub(crate) async fn resolve_endpoint(url: &str) -> Result<ResolvedEndpoint> {
    resolve_endpoint_with_policy(url, private_endpoints_allowed()).await
}

pub(crate) async fn resolve_endpoint_with_policy(
    url: &str,
    allow_private: bool,
) -> Result<ResolvedEndpoint> {
    let parsed = Url::parse(url)
        .map_err(|_| IicpError::EndpointRefused("provider endpoint is not a valid URL".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(IicpError::EndpointRefused(
            "provider endpoint must use HTTP or HTTPS".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(IicpError::EndpointRefused(
            "provider endpoint must not contain user info".into(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| IicpError::EndpointRefused("provider endpoint has no host".into()))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !hostname_allowed(&host, allow_private) {
        return Err(IicpError::EndpointRefused(
            "provider hostname is prohibited by network policy".into(),
        ));
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| IicpError::EndpointRefused("provider endpoint has no usable port".into()))?;

    let mut unique = BTreeSet::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        unique.insert(SocketAddr::new(ip, port));
    } else {
        let resolved = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| {
                IicpError::EndpointRefused("provider hostname resolution failed".into())
            })?;
        unique.extend(resolved);
    }
    if unique.is_empty() {
        return Err(IicpError::EndpointRefused(
            "provider hostname returned no addresses".into(),
        ));
    }
    if unique
        .iter()
        .any(|address| !address_allowed(address.ip(), allow_private))
    {
        return Err(IicpError::EndpointRefused(
            "provider hostname resolved to a prohibited address".into(),
        ));
    }
    Ok(ResolvedEndpoint {
        url: parsed,
        host,
        addresses: unique.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_policy_covers_mapped_and_private_classes() {
        assert!(address_allowed("93.184.216.34".parse().unwrap(), false));
        assert!(!address_allowed("127.0.0.1".parse().unwrap(), false));
        assert!(!address_allowed("169.254.169.254".parse().unwrap(), false));
        assert!(!address_allowed("::ffff:127.0.0.1".parse().unwrap(), false));
        assert!(!address_allowed("fd00::1".parse().unwrap(), false));
        assert!(address_allowed("10.0.0.5".parse().unwrap(), true));
    }

    #[test]
    fn hostname_policy_blocks_local_names() {
        assert!(hostname_allowed("provider.example.com", false));
        assert!(!hostname_allowed("localhost", false));
        assert!(!hostname_allowed("provider.internal", false));
        assert!(!hostname_allowed("ollama", false));
    }

    #[test]
    fn shared_fixture_matches_rust_policy() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/endpoint-security-v1.json"))
                .unwrap();
        for vector in fixture["address_vectors"].as_array().unwrap() {
            let allow_private = vector["allow_private"].as_bool().unwrap();
            let actual = vector["addresses"]
                .as_array()
                .unwrap()
                .iter()
                .all(|address| {
                    address_allowed(address.as_str().unwrap().parse().unwrap(), allow_private)
                });
            assert_eq!(
                actual,
                vector["allowed"].as_bool().unwrap(),
                "{}",
                vector["id"]
            );
        }
        for vector in fixture["hostname_vectors"].as_array().unwrap() {
            assert_eq!(
                hostname_allowed(vector["host"].as_str().unwrap(), false),
                vector["allowed"].as_bool().unwrap(),
                "{}",
                vector["id"]
            );
        }
    }

    #[tokio::test]
    async fn literal_endpoint_is_resolved_without_dns() {
        let resolved = resolve_endpoint_with_policy("https://93.184.216.34/v1", false)
            .await
            .unwrap();
        assert_eq!(
            resolved.addresses[0].ip(),
            "93.184.216.34".parse::<IpAddr>().unwrap()
        );
    }
}
