//! Objetivo del escaneo en modo `network` (feature `network_scan_url_target`,
//! UT-03): parseo de `target` (IP, nombre de host o URL `http`/`https`),
//! puerto de resolución DNS y fijado de una dirección.
//!
//! `ms-nmap` nunca resuelve nombres: el Gateway resuelve, evalúa **todas** las
//! direcciones contra [`NetworkScanPolicy`] y publica una sola IP ("pinned")
//! como `ip`, de modo que lo evaluado y lo escaneado son la misma dirección
//! (sin ventana de DNS rebinding entre la política y el escaneo). Ver
//! `docs/decisions.md` D-20.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use crate::domain::{ScanSubmission, ScanSubmissionError};
use crate::network_scan::NetworkScanPolicy;

/// Host de un objetivo `network`: una IP (se evalúa tal cual) o un nombre
/// (en minúsculas, RFC 1123) que hay que resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetHost {
    /// IP literal (bare o dentro de una URL).
    Ip(IpAddr),
    /// Nombre de host válido, sin punto final y en minúsculas.
    Name(String),
}

/// Objetivo `network` ya parseado, sin DNS ni política aplicados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTarget {
    /// IP literal o nombre a resolver.
    pub host: TargetHost,
    /// Puerto de la URL que se escanea además de los de nmap por defecto.
    ///
    /// Decisión (UT-03): solo se envía cuando la URL trae un puerto explícito
    /// distinto de 80 y 443, porque ambos ya están en el conjunto por defecto
    /// de nmap (`--top-ports 1000`); enviarlos sería ruido que además dispara
    /// el preflight de puertos de `nmap-service`. Un nombre o IP sin URL, o
    /// una URL sin puerto, no llevan `extra_port`.
    pub extra_port: Option<u16>,
}

impl NetworkTarget {
    /// Interpreta `raw` como IP (o CIDR de un host, igual que antes), nombre
    /// de host o URL `http`/`https`.
    pub fn parse(raw: &str) -> Result<Self, ScanSubmissionError> {
        let raw = raw.trim();
        if raw.contains("://") || raw.starts_with("//") {
            return parse_url(raw);
        }
        match ScanSubmission::parse(raw) {
            Ok(submission) => {
                let ip = submission
                    .target
                    .parse()
                    .map_err(|_| ScanSubmissionError::InvalidNetworkTarget)?;
                Ok(Self {
                    host: TargetHost::Ip(ip),
                    extra_port: None,
                })
            }
            // Un rango o un valor vacío conservan su error de siempre; solo
            // lo que no es una IP se reintenta como nombre de host.
            Err(ScanSubmissionError::InvalidTarget { .. }) => Ok(Self {
                host: TargetHost::Name(
                    validate_hostname(raw).ok_or(ScanSubmissionError::InvalidNetworkTarget)?,
                ),
                extra_port: None,
            }),
            Err(other) => Err(other),
        }
    }
}

/// Puertos que nmap ya escanea por defecto y que, por lo tanto, no se envían
/// como `extra_port`.
const DEFAULT_URL_PORTS: [u16; 2] = [80, 443];

fn parse_url(raw: &str) -> Result<NetworkTarget, ScanSubmissionError> {
    let invalid = || ScanSubmissionError::InvalidNetworkTarget;
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid());
    }
    let (scheme, rest) = raw.split_once("://").ok_or_else(invalid)?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid());
    }
    // Sin credenciales (`user[:pass]@host`) y sin `\`, que las URL tratan
    // como `/` y desplazaría el host real.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return Err(invalid());
    }
    let url = url::Url::parse(raw).map_err(|_| invalid())?;
    let host = match url.host().ok_or_else(invalid)? {
        url::Host::Domain(domain) => {
            TargetHost::Name(validate_hostname(domain).ok_or_else(invalid)?)
        }
        url::Host::Ipv4(ip) => TargetHost::Ip(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => TargetHost::Ip(IpAddr::V6(ip)),
    };
    // `port()` ya omite el puerto por defecto del esquema; el 0 nunca es válido.
    if url.port() == Some(0) {
        return Err(invalid());
    }
    let extra_port = url.port().filter(|port| !DEFAULT_URL_PORTS.contains(port));
    Ok(NetworkTarget { host, extra_port })
}

/// Valida `raw` como nombre de host RFC 1123 (mismo patrón que
/// `target_host` en `broker/contracts/scan-request.schema.json`) y lo
/// devuelve en minúsculas: 1..=253 caracteres, etiquetas de 1..=63 con
/// letras, dígitos y guion (sin guion al inicio ni al final), sin punto
/// final. Además la última etiqueta no puede ser solo numérica, para que
/// `10.0.0` o `127.1` no pasen por nombres.
fn validate_hostname(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = raw.split('.').collect();
    let label_ok = |label: &&str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if !labels.iter().all(label_ok) {
        return None;
    }
    if labels
        .last()
        .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

/// Fallo de resolución DNS (sin detalle: no se expone al cliente).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// La resolución superó el tiempo máximo.
    #[error("la resolución DNS superó el tiempo máximo")]
    Timeout,
    /// El nombre no existe o el resolvedor falló.
    #[error("no se pudo resolver el nombre")]
    Failed,
}

/// Puerto de resolución de nombres. Un adaptador real
/// ([`SystemHostResolver`]) y uno determinista para tests
/// ([`StaticHostResolver`]).
#[async_trait]
pub trait HostResolver: Send + Sync {
    /// Direcciones del nombre `host`, en el orden del resolvedor.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError>;
}

/// Resolvedor real sobre `tokio::net::lookup_host` con un tiempo máximo.
#[derive(Debug, Clone)]
pub struct SystemHostResolver {
    timeout: Duration,
}

impl SystemHostResolver {
    /// Resolvedor con el tiempo máximo `timeout` por consulta.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[async_trait]
impl HostResolver for SystemHostResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        // El puerto 0 es solo el exigido por la API; nunca se usa.
        lookup_with_timeout(self.timeout, tokio::net::lookup_host((host, 0))).await
    }
}

/// Espera `lookup` como mucho `timeout`: vencido el plazo es
/// [`ResolveError::Timeout`]; un error de resolución es [`ResolveError::Failed`].
async fn lookup_with_timeout<I>(
    timeout: Duration,
    lookup: impl Future<Output = std::io::Result<I>>,
) -> Result<Vec<IpAddr>, ResolveError>
where
    I: Iterator<Item = SocketAddr>,
{
    let addrs = tokio::time::timeout(timeout, lookup)
        .await
        .map_err(|_| ResolveError::Timeout)?
        .map_err(|_| ResolveError::Failed)?;
    Ok(addrs.map(|addr| addr.ip()).collect())
}

/// Resolvedor determinista: respuestas fijas por nombre, y registro de las
/// consultas recibidas. Un nombre sin respuesta falla como un NXDOMAIN.
#[derive(Debug, Default)]
pub struct StaticHostResolver {
    answers: Mutex<HashMap<String, Result<Vec<IpAddr>, ResolveError>>>,
    calls: Mutex<Vec<String>>,
}

impl StaticHostResolver {
    /// Resolvedor sin respuestas.
    pub fn new() -> Self {
        Self::default()
    }

    /// `host` resuelve a `ips`, en ese orden.
    pub fn with_answer(self, host: &str, ips: &[&str]) -> Self {
        let ips = ips
            .iter()
            .map(|ip| ip.parse().expect("IP de prueba válida"))
            .collect();
        self.answers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(host.to_string(), Ok(ips));
        self
    }

    /// `host` falla con `error`.
    pub fn with_failure(self, host: &str, error: ResolveError) -> Self {
        self.answers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(host.to_string(), Err(error));
        self
    }

    /// Nombres consultados hasta ahora, en orden.
    pub fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}

#[async_trait]
impl HostResolver for StaticHostResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        self.calls
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(host.to_string());
        self.answers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(host)
            .cloned()
            .unwrap_or(Err(ResolveError::Failed))
    }
}

/// Por qué se rechazó un nombre del modo `network` tras resolverlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostRejection {
    /// Sin direcciones, error de DNS o tiempo agotado.
    #[error("el nombre no se pudo resolver")]
    Unresolvable,
    /// Al menos una dirección resuelta incumple la denylist o la allowlist.
    #[error("el nombre resuelve a una dirección no permitida")]
    ResolvesToDenied,
}

impl HostRejection {
    /// Código estable para el campo `reason` de la respuesta `422`.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unresolvable => "target_unresolvable",
            Self::ResolvesToDenied => "target_resolves_to_denied",
        }
    }
}

/// Resuelve `host`, evalúa **cada** dirección con `policy` y devuelve la
/// dirección fijada: la primera IPv4 en el orden del resolvedor, o si no hay
/// ninguna, la primera IPv6. Una sola dirección rechazada rechaza el nombre.
pub async fn resolve_and_pin(
    resolver: &dyn HostResolver,
    policy: &NetworkScanPolicy,
    host: &str,
) -> Result<IpAddr, HostRejection> {
    let resolved = resolver
        .resolve(host)
        .await
        .map_err(|_| HostRejection::Unresolvable)?;
    if resolved.is_empty() {
        return Err(HostRejection::Unresolvable);
    }
    let mut allowed = Vec::with_capacity(resolved.len());
    for addr in resolved {
        allowed.push(
            policy
                .check_target(addr)
                .map_err(|_| HostRejection::ResolvesToDenied)?,
        );
    }
    let pinned = allowed
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| allowed.first());
    pinned.copied().ok_or(HostRejection::Unresolvable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("IP de prueba válida")
    }

    fn name(raw: &str) -> TargetHost {
        TargetHost::Name(raw.to_string())
    }

    fn parsed(raw: &str) -> NetworkTarget {
        NetworkTarget::parse(raw).unwrap_or_else(|e| panic!("{raw:?} debe parsear: {e}"))
    }

    #[test]
    fn bare_ip_keeps_the_existing_behaviour_and_has_no_extra_port() {
        assert_eq!(
            parsed("192.0.2.10"),
            NetworkTarget {
                host: TargetHost::Ip(ip("192.0.2.10")),
                extra_port: None
            }
        );
        assert_eq!(
            parsed(" 2001:db8::1 ").host,
            TargetHost::Ip(ip("2001:db8::1"))
        );
        // Un /32 se normaliza a la IP simple, como siempre.
        assert_eq!(
            parsed("192.0.2.10/32").host,
            TargetHost::Ip(ip("192.0.2.10"))
        );
        assert_eq!(
            NetworkTarget::parse("10.0.0.0/24"),
            Err(ScanSubmissionError::UnsupportedRange {
                target: "10.0.0.0/24".to_string()
            })
        );
        assert_eq!(
            NetworkTarget::parse("  "),
            Err(ScanSubmissionError::EmptyTarget)
        );
    }

    #[test]
    fn bare_hostname_is_lowercased_and_has_no_extra_port() {
        let target = parsed("App.Example.COM");
        assert_eq!(target.host, name("app.example.com"));
        assert_eq!(target.extra_port, None);
        assert_eq!(parsed("localhost").host, name("localhost"));
        assert_eq!(parsed("a-b.c1.example").host, name("a-b.c1.example"));
    }

    #[test]
    fn url_takes_host_and_port_and_ignores_path_query_and_fragment() {
        let target = parsed("https://App.Example.com:8443/login?next=/x#frag");
        assert_eq!(target.host, name("app.example.com"));
        assert_eq!(target.extra_port, Some(8443));
        assert_eq!(parsed("HTTP://example.com:8080").extra_port, Some(8080));
    }

    #[test]
    fn extra_port_is_omitted_for_default_ports_because_nmap_already_covers_them() {
        assert_eq!(parsed("https://example.com").extra_port, None);
        assert_eq!(parsed("http://example.com/").extra_port, None);
        assert_eq!(parsed("https://example.com:443").extra_port, None);
        assert_eq!(parsed("http://example.com:80").extra_port, None);
        // 80 sobre https (y 443 sobre http) también están en el conjunto por defecto.
        assert_eq!(parsed("https://example.com:80").extra_port, None);
        assert_eq!(parsed("http://example.com:443").extra_port, None);
    }

    #[test]
    fn url_with_an_ip_literal_host_behaves_like_a_bare_ip_plus_the_port() {
        let v4 = parsed("http://192.0.2.10:8080/x");
        assert_eq!(v4.host, TargetHost::Ip(ip("192.0.2.10")));
        assert_eq!(v4.extra_port, Some(8080));
        let v6 = parsed("https://[2001:db8::1]:8443/");
        assert_eq!(v6.host, TargetHost::Ip(ip("2001:db8::1")));
        assert_eq!(v6.extra_port, Some(8443));
        assert_eq!(parsed("https://192.0.2.10").extra_port, None);
        // La forma decimal de una IP se interpreta como IP (y la política la ve).
        assert_eq!(
            parsed("http://2130706433/").host,
            TargetHost::Ip(ip("127.0.0.1"))
        );
    }

    #[test]
    fn malformed_targets_are_rejected_without_echoing_the_input() {
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}.com", vec!["a".repeat(60); 5].join("."));
        let rejected = [
            "ftp://example.com",
            "ssh://example.com",
            "//example.com",
            "http://",
            "https:///path",
            "http://user@example.com",
            "https://user:secret@example.com:8443/",
            "http://@example.com",
            "http://example.com\\@evil.test",
            "http://exa mple.com",
            "http://example.com:0",
            "http://example.com:65536",
            "http://example.com:abc",
            "bad_host",
            "-bad.example.com",
            "bad-.example.com",
            "a..example.com",
            ".example.com",
            "example.com.",
            "http://example.com./",
            "10.0.0",
            "example.com:8443",
            "example.com/path",
            "exa mple.com",
            "ejemplo.ñandú.cl",
            &long_label,
            &long_name,
        ];
        for raw in rejected {
            let error = NetworkTarget::parse(raw).expect_err(raw);
            assert_eq!(error, ScanSubmissionError::InvalidNetworkTarget, "{raw:?}");
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn hostname_of_exactly_253_characters_is_accepted() {
        let label = "a".repeat(61);
        let host = format!("{label}.{label}.{label}.{}.com", "b".repeat(61));
        assert!(host.len() <= 253);
        assert_eq!(parsed(&host).host, TargetHost::Name(host));
    }

    fn resolver(answers: &[(&str, &[&str])]) -> StaticHostResolver {
        answers
            .iter()
            .fold(StaticHostResolver::new(), |r, (h, ips)| {
                r.with_answer(h, ips)
            })
    }

    #[tokio::test]
    async fn pins_the_first_ipv4_in_resolver_order() {
        let r = resolver(&[("h.test", &["2001:db8::1", "192.0.2.20", "192.0.2.10"])]);
        let pinned = resolve_and_pin(&r, &NetworkScanPolicy::unrestricted(), "h.test").await;
        assert_eq!(pinned, Ok(ip("192.0.2.20")));
        assert_eq!(r.calls(), vec!["h.test".to_string()]);
    }

    #[tokio::test]
    async fn pins_the_first_ipv6_when_there_is_no_ipv4() {
        let r = resolver(&[("h.test", &["2001:db8::2", "2001:db8::1"])]);
        let pinned = resolve_and_pin(&r, &NetworkScanPolicy::unrestricted(), "h.test").await;
        assert_eq!(pinned, Ok(ip("2001:db8::2")));
    }

    #[tokio::test]
    async fn pins_the_canonical_form_of_a_wrapped_ipv4() {
        let r = resolver(&[("h.test", &["::ffff:192.0.2.7"])]);
        let pinned = resolve_and_pin(&r, &NetworkScanPolicy::unrestricted(), "h.test").await;
        assert_eq!(pinned, Ok(ip("192.0.2.7")));
    }

    #[tokio::test]
    async fn one_denied_address_rejects_the_whole_name_whatever_its_position() {
        for answers in [
            ["192.0.2.10", "127.0.0.1"],
            ["169.254.169.254", "192.0.2.10"],
            ["192.0.2.10", "::ffff:127.0.0.1"],
            ["192.0.2.10", "fd00:ec2::254"],
        ] {
            let r = resolver(&[("h.test", &answers)]);
            let pinned = resolve_and_pin(&r, &NetworkScanPolicy::unrestricted(), "h.test").await;
            assert_eq!(pinned, Err(HostRejection::ResolvesToDenied), "{answers:?}");
        }
    }

    #[tokio::test]
    async fn an_address_outside_the_allowlist_rejects_the_name() {
        let policy = NetworkScanPolicy::new(vec!["10.0.0.0/24".parse().unwrap()]);
        let r = resolver(&[
            ("in.test", &["10.0.0.7"]),
            ("mixed.test", &["10.0.0.7", "192.0.2.1"]),
        ]);
        assert_eq!(
            resolve_and_pin(&r, &policy, "in.test").await,
            Ok(ip("10.0.0.7"))
        );
        assert_eq!(
            resolve_and_pin(&r, &policy, "mixed.test").await,
            Err(HostRejection::ResolvesToDenied)
        );
    }

    #[tokio::test]
    async fn no_addresses_or_a_resolver_failure_is_unresolvable() {
        let r = StaticHostResolver::new()
            .with_answer("empty.test", &[])
            .with_failure("slow.test", ResolveError::Timeout)
            .with_failure("down.test", ResolveError::Failed);
        for host in ["empty.test", "slow.test", "down.test", "unknown.test"] {
            let pinned = resolve_and_pin(&r, &NetworkScanPolicy::unrestricted(), host).await;
            assert_eq!(pinned, Err(HostRejection::Unresolvable), "{host}");
        }
    }

    #[test]
    fn rejection_reason_codes_are_stable() {
        assert_eq!(
            HostRejection::Unresolvable.reason_code(),
            "target_unresolvable"
        );
        assert_eq!(
            HostRejection::ResolvesToDenied.reason_code(),
            "target_resolves_to_denied"
        );
    }

    #[tokio::test]
    async fn system_resolver_resolves_localhost_and_fails_on_an_invalid_tld() {
        let resolver = SystemHostResolver::new(Duration::from_secs(5));
        let addrs = resolver.resolve("localhost").await.expect("localhost");
        assert!(addrs.iter().any(|a| a.is_loopback()));
        // `.invalid` está reservado (RFC 6761): nunca resuelve.
        assert!(resolver.resolve("nope.invalid").await.is_err());
    }

    #[tokio::test]
    async fn a_lookup_that_never_answers_times_out_instead_of_hanging() {
        // Un lookup que nunca responde: el resultado depende solo del
        // timeout, no de la velocidad del DNS de la máquina que corre el test.
        let never = std::future::pending::<std::io::Result<std::vec::IntoIter<SocketAddr>>>();
        assert_eq!(
            lookup_with_timeout(Duration::from_millis(20), never).await,
            Err(ResolveError::Timeout)
        );
    }

    #[tokio::test]
    async fn a_failed_lookup_maps_to_failed() {
        let failed = std::future::ready(Err::<std::vec::IntoIter<SocketAddr>, _>(
            std::io::Error::other("nxdomain"),
        ));
        assert_eq!(
            lookup_with_timeout(Duration::from_secs(5), failed).await,
            Err(ResolveError::Failed)
        );
    }
}
