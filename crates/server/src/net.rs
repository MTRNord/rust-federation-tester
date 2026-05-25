//! Shared IP address utilities used across multiple API modules.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

use crate::config::IpNet;

/// Returns `true` if `ip` is a private, loopback, link-local, broadcast, or
/// unspecified address (any address that should not be reachable from the public
/// internet). Used to guard against SSRF via webhook URLs.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Returns `true` if `ip` is contained in any of `nets`.
pub fn nets_contain(nets: &[IpNet], ip: IpAddr) -> bool {
    nets.iter().any(|net| net.contains(&ip))
}

/// Resolve the effective client IP: if the direct connection comes from a
/// trusted proxy, use the rightmost value in `X-Forwarded-For`; otherwise
/// use the direct connection IP.
pub fn resolve_client_ip(
    direct_ip: IpAddr,
    trusted_proxy_nets: &[IpNet],
    headers: &HeaderMap,
) -> IpAddr {
    if nets_contain(trusted_proxy_nets, direct_ip) {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next_back())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .unwrap_or(direct_ip)
    } else {
        direct_ip
    }
}

/// Returns `true` if the effective client for `addr` (after trusted-proxy
/// resolution) is permitted by `allowed_nets`.
pub fn is_allowed(
    addr: &SocketAddr,
    trusted_proxy_nets: &[IpNet],
    allowed_nets: &[IpNet],
    headers: &HeaderMap,
) -> bool {
    let client_ip = resolve_client_ip(addr.ip(), trusted_proxy_nets, headers);
    nets_contain(allowed_nets, client_ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn parse_nets(cidrs: &[&str]) -> Vec<IpNet> {
        cidrs.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn xff_headers(value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert("x-forwarded-for", value.parse().unwrap());
        map
    }

    fn sock(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), 0)
    }

    // ── is_private_ip ─────────────────────────────────────────────────────────

    #[test]
    fn private_ip_loopback_v4() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn private_ip_rfc1918_10() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn private_ip_rfc1918_172() {
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn private_ip_rfc1918_192() {
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn private_ip_link_local() {
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));
    }

    #[test]
    fn private_ip_broadcast() {
        assert!(is_private_ip("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn private_ip_unspecified_v4() {
        assert!(is_private_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn private_ip_public_is_not_private() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn private_ip_loopback_v6() {
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn private_ip_unspecified_v6() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn private_ip_public_v6_is_not_private() {
        assert!(!is_private_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    // ── nets_contain ──────────────────────────────────────────────────────────

    #[test]
    fn nets_contain_empty_always_false() {
        assert!(!nets_contain(&[], "127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn nets_contain_loopback_in_slash8() {
        let nets = parse_nets(&["127.0.0.0/8"]);
        assert!(nets_contain(&nets, "127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn nets_contain_public_not_in_private() {
        let nets = parse_nets(&["127.0.0.0/8", "192.168.0.0/16"]);
        assert!(!nets_contain(&nets, "8.8.8.8".parse().unwrap()));
    }

    // ── resolve_client_ip ─────────────────────────────────────────────────────

    #[test]
    fn no_trusted_proxy_returns_direct_ip() {
        let direct: IpAddr = "203.0.113.1".parse().unwrap();
        let result = resolve_client_ip(direct, &[], &HeaderMap::new());
        assert_eq!(result, direct);
    }

    #[test]
    fn no_trusted_proxy_ignores_xff() {
        let direct: IpAddr = "203.0.113.1".parse().unwrap();
        let result = resolve_client_ip(direct, &[], &xff_headers("10.0.0.1"));
        assert_eq!(result, direct);
    }

    #[test]
    fn trusted_proxy_uses_rightmost_xff() {
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = parse_nets(&["10.0.0.0/8"]);
        let headers = xff_headers("203.0.113.99, 172.16.1.1, 10.0.0.2");
        let result = resolve_client_ip(proxy_ip, &trusted, &headers);
        assert_eq!(result, "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn trusted_proxy_missing_xff_falls_back_to_direct() {
        let proxy_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = parse_nets(&["10.0.0.0/8"]);
        let result = resolve_client_ip(proxy_ip, &trusted, &HeaderMap::new());
        assert_eq!(result, proxy_ip);
    }

    // ── is_allowed ────────────────────────────────────────────────────────────

    #[test]
    fn is_allowed_direct_match() {
        let nets = parse_nets(&["127.0.0.0/8"]);
        assert!(is_allowed(
            &sock([127, 0, 0, 1]),
            &[],
            &nets,
            &HeaderMap::new()
        ));
    }

    #[test]
    fn is_allowed_public_ip_rejected() {
        let nets = parse_nets(&["127.0.0.0/8"]);
        assert!(!is_allowed(
            &sock([8, 8, 8, 8]),
            &[],
            &nets,
            &HeaderMap::new()
        ));
    }

    #[test]
    fn is_allowed_via_trusted_proxy_xff() {
        let proxy_nets = parse_nets(&["10.0.0.0/8"]);
        let allowed_nets = parse_nets(&["127.0.0.0/8"]);
        // Direct connection is from trusted proxy (10.x); XFF claims 127.0.0.1
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
        assert!(is_allowed(
            &sock([10, 0, 0, 1]),
            &proxy_nets,
            &allowed_nets,
            &headers
        ));
    }
}
