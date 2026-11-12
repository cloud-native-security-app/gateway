//! Política de objetivos del escaneo en modo `network` (feature
//! `network_scan_mode`, NS-03). Lógica pura, sin IO.
//!
//! En modo `network` `ms-nmap` escanea la IP desde su propio contenedor, así
//! que el Gateway es quien evita que ese poder apunte al propio host, a
//! metadatos de nube o a direcciones no unicast:
//!
//! 1. **Denylist fija** ([`TargetRejection`]): loopback, link-local (incluye
//!    `169.254.169.254`), unique-local IPv6 (`fc00::/7`, incluye el metadata
//!    `fd00:ec2::254`), multicast, broadcast y sin especificar, para IPv4 y
//!    IPv6. Las formas IPv6 que envuelven un IPv4 (IPv4-mapped
//!    `::ffff:a.b.c.d` y el obsoleto IPv4-compatible `::a.b.c.d`) se
//!    canonicalizan a su IPv4 ([`canonical_target`]) antes de evaluar y
//!    publicar, para que no sean un desvío.
//! 2. **Allowlist opcional** (`NETWORK_SCAN_ALLOWED_CIDRS`): si no está
//!    vacía, el objetivo debe caer dentro de alguno de sus CIDR. La denylist
//!    se evalúa primero y no se puede anular con la allowlist.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Por qué se rechazó un objetivo del modo `network`. Cada variante tiene un
/// código estable ([`TargetRejection::reason_code`]) que viaja en la
/// respuesta `422` para que `front` lo muestre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TargetRejection {
    /// 127.0.0.0/8 o `::1`.
    #[error("el objetivo es una dirección de loopback")]
    Loopback,
    /// 169.254.0.0/16 (incluye el servicio de metadatos de nube) o fe80::/10.
    #[error("el objetivo es una dirección link-local")]
    LinkLocal,
    /// fc00::/7 (unique-local IPv6; incluye el metadata IPv6 de AWS,
    /// `fd00:ec2::254`).
    #[error("el objetivo es una dirección unique-local")]
    UniqueLocal,
    /// 224.0.0.0/4 o ff00::/8.
    #[error("el objetivo es una dirección multicast")]
    Multicast,
    /// 255.255.255.255.
    #[error("el objetivo es la dirección de broadcast")]
    Broadcast,
    /// 0.0.0.0 o `::`.
    #[error("el objetivo es la dirección sin especificar")]
    Unspecified,
    /// Hay una allowlist configurada y el objetivo no cae en ninguno de sus
    /// CIDR.
    #[error("el objetivo está fuera de los rangos permitidos para escaneo de red")]
    OutsideAllowedRanges,
}

impl TargetRejection {
    /// Código estable, en `snake_case`, para el campo `reason` de la
    /// respuesta `422`.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Loopback => "target_loopback",
            Self::LinkLocal => "target_link_local",
            Self::UniqueLocal => "target_unique_local",
            Self::Multicast => "target_multicast",
            Self::Broadcast => "target_broadcast",
            Self::Unspecified => "target_unspecified",
            Self::OutsideAllowedRanges => "target_outside_allowed_ranges",
        }
    }
}

/// Forma canónica de `ip`, la única que se evalúa (denylist y allowlist) y se
/// publica: un IPv4-mapped (`::ffff:a.b.c.d`) o IPv4-compatible (`::a.b.c.d`)
/// pasa a su IPv4; `::` y `::1` siguen siendo IPv6; el resto queda igual.
pub fn canonical_target(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => ipv4_compatible(v6).map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// IPv4 envuelto en un IPv6 IPv4-compatible obsoleto (`::a.b.c.d`), excluidos
/// `::` y `::1` (que son direcciones IPv6 propias).
fn ipv4_compatible(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let embedded = s[..6].iter().all(|&seg| seg == 0) && !matches!((s[6], s[7]), (0, 0) | (0, 1));
    embedded.then(|| Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8))
}

fn denylisted_v4(ip: Ipv4Addr) -> Option<TargetRejection> {
    if ip.is_unspecified() {
        Some(TargetRejection::Unspecified)
    } else if ip.is_loopback() {
        Some(TargetRejection::Loopback)
    } else if ip.is_link_local() {
        Some(TargetRejection::LinkLocal)
    } else if ip.is_multicast() {
        Some(TargetRejection::Multicast)
    } else if ip.is_broadcast() {
        Some(TargetRejection::Broadcast)
    } else {
        None
    }
}

fn denylisted(ip: IpAddr) -> Option<TargetRejection> {
    match ip {
        IpAddr::V4(v4) => denylisted_v4(v4),
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                Some(TargetRejection::Unspecified)
            } else if v6.is_loopback() {
                Some(TargetRejection::Loopback)
            } else if v6.segments()[0] & 0xffc0 == 0xfe80 {
                Some(TargetRejection::LinkLocal)
            } else if v6.segments()[0] & 0xfe00 == 0xfc00 {
                Some(TargetRejection::UniqueLocal)
            } else if v6.is_multicast() {
                Some(TargetRejection::Multicast)
            } else {
                None
            }
        }
    }
}

/// Política de objetivos del modo `network`: denylist fija más allowlist de
/// CIDR opcional (vacía = cualquier objetivo que pase la denylist).
#[derive(Debug, Clone, Default)]
pub struct NetworkScanPolicy {
    allowed: Vec<IpNet>,
}

impl NetworkScanPolicy {
    /// Política con la allowlist `allowed` (vacía = sin restricción extra).
    pub fn new(allowed: Vec<IpNet>) -> Self {
        Self { allowed }
    }

    /// Solo la denylist fija, sin allowlist.
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// Evalúa `ip`: primero la denylist, luego la allowlist si la hay. Ambas
    /// sobre la forma canónica ([`canonical_target`]), así que
    /// `::ffff:10.0.0.7` se trata como `10.0.0.7`. Devuelve esa forma
    /// canónica, que es la que debe publicarse.
    pub fn check_target(&self, ip: IpAddr) -> Result<IpAddr, TargetRejection> {
        let ip = canonical_target(ip);
        if let Some(rejection) = denylisted(ip) {
            return Err(rejection);
        }
        if !self.allowed.is_empty() && !self.allowed.iter().any(|net| net.contains(&ip)) {
            return Err(TargetRejection::OutsideAllowedRanges);
        }
        Ok(ip)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("IP de prueba válida")
    }

    #[test]
    fn denylist_rejects_every_forbidden_range_with_its_reason_code() {
        let cases = [
            ("127.0.0.1", "target_loopback"),
            ("127.255.255.254", "target_loopback"),
            ("::1", "target_loopback"),
            ("169.254.0.1", "target_link_local"),
            ("169.254.169.254", "target_link_local"),
            ("fe80::1", "target_link_local"),
            ("febf::1", "target_link_local"),
            ("224.0.0.1", "target_multicast"),
            ("239.255.255.255", "target_multicast"),
            ("ff02::1", "target_multicast"),
            ("ffff::1", "target_multicast"),
            ("255.255.255.255", "target_broadcast"),
            ("0.0.0.0", "target_unspecified"),
            ("::", "target_unspecified"),
            // IPv4-mapped IPv6: mismas reglas que el IPv4 que envuelven.
            ("::ffff:127.0.0.1", "target_loopback"),
            ("::ffff:169.254.169.254", "target_link_local"),
            ("::ffff:224.0.0.1", "target_multicast"),
            ("::ffff:255.255.255.255", "target_broadcast"),
            ("::ffff:0.0.0.0", "target_unspecified"),
            // IPv4-compatible (obsoleto) con el mismo riesgo.
            ("::127.0.0.1", "target_loopback"),
            ("::169.254.169.254", "target_link_local"),
            // Unique-local fc00::/7 (incluye el metadata IPv6 de AWS).
            ("fd00:ec2::254", "target_unique_local"),
            ("fc00::1", "target_unique_local"),
            ("fdff:ffff::1", "target_unique_local"),
        ];
        let policy = NetworkScanPolicy::unrestricted();
        for (raw, reason) in cases {
            let rejection = policy
                .check_target(ip(raw))
                .expect_err(&format!("{raw} debe rechazarse"));
            assert_eq!(rejection.reason_code(), reason, "target {raw}");
        }
    }

    #[test]
    fn denylist_accepts_ordinary_public_and_private_targets() {
        let policy = NetworkScanPolicy::unrestricted();
        for raw in [
            "192.0.2.10",
            "10.0.0.5",
            "172.31.86.37",
            "168.254.0.1",
            "223.255.255.255",
            "2001:db8::1",
            "::ffff:10.0.0.5",
            "fec0::1",
            "fbff::1",
            "fe00::1",
        ] {
            assert!(policy.check_target(ip(raw)).is_ok(), "{raw} debe aceptarse");
        }
    }

    #[test]
    fn allowlist_accepts_inside_and_rejects_outside() {
        let policy = NetworkScanPolicy::new(vec![
            "10.0.0.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);
        assert!(policy.check_target(ip("10.0.0.7")).is_ok());
        assert!(policy.check_target(ip("2001:db8::9")).is_ok());
        assert_eq!(
            policy
                .check_target(ip("10.0.1.7"))
                .expect_err("fuera del rango")
                .reason_code(),
            "target_outside_allowed_ranges"
        );
        assert_eq!(
            policy
                .check_target(ip("192.0.2.1"))
                .expect_err("fuera del rango")
                .reason_code(),
            "target_outside_allowed_ranges"
        );
    }

    #[test]
    fn allowlist_matches_the_canonical_form_of_ipv4_mapped_targets() {
        let policy = NetworkScanPolicy::new(vec!["10.0.0.0/24".parse().unwrap()]);
        assert!(policy.check_target(ip("::ffff:10.0.0.7")).is_ok());
        assert!(policy.check_target(ip("::ffff:10.0.1.7")).is_err());
    }

    #[test]
    fn allowlist_matches_the_canonical_form_of_ipv4_compatible_targets() {
        let policy = NetworkScanPolicy::new(vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(policy.check_target(ip("::10.0.0.7")).is_ok());
        assert!(policy.check_target(ip("::192.0.2.7")).is_err());
    }

    #[test]
    fn denylist_wins_over_an_allowlist_that_contains_the_target() {
        let policy = NetworkScanPolicy::new(vec![
            "127.0.0.0/8".parse().unwrap(),
            "169.254.0.0/16".parse().unwrap(),
        ]);
        assert_eq!(
            policy
                .check_target(ip("127.0.0.1"))
                .expect_err("loopback sigue prohibido")
                .reason_code(),
            "target_loopback"
        );
        assert_eq!(
            policy
                .check_target(ip("169.254.169.254"))
                .expect_err("metadata sigue prohibido")
                .reason_code(),
            "target_link_local"
        );
    }

    #[test]
    fn check_target_returns_the_canonical_ip_to_publish() {
        let policy = NetworkScanPolicy::unrestricted();
        assert_eq!(policy.check_target(ip("::10.0.0.7")), Ok(ip("10.0.0.7")));
        assert_eq!(
            policy.check_target(ip("::ffff:10.0.0.7")),
            Ok(ip("10.0.0.7"))
        );
        assert_eq!(
            policy.check_target(ip("2001:db8::1")),
            Ok(ip("2001:db8::1"))
        );
    }

    #[test]
    fn canonical_target_unwraps_ipv4_mapped_addresses() {
        assert_eq!(canonical_target(ip("::ffff:10.0.0.5")), ip("10.0.0.5"));
        assert_eq!(canonical_target(ip("2001:db8::1")), ip("2001:db8::1"));
    }

    #[test]
    fn canonical_target_unwraps_ipv4_compatible_but_keeps_unspecified_and_loopback() {
        assert_eq!(canonical_target(ip("::10.0.0.7")), ip("10.0.0.7"));
        assert_eq!(canonical_target(ip("::")), ip("::"));
        assert_eq!(canonical_target(ip("::1")), ip("::1"));
    }
}
