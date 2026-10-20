# scan-target-single-ip

## Objetivo
`POST /api/scans` solo acepta un único host como `target`.

## Causa
`ScanSubmission::parse` aceptaba cualquier CIDR y `submit_scan` lo reenviaba tal cual como `ScanRequest.ip`. El contrato de `nmap-service` (`ip: IpAddr`, una IP por escaneo, decisión Q2 del broker) lo rechazaba: un target `172.31.86.37/32` terminó en dead-letter y el escaneo quedó "pendiente" para siempre.

## Fix
- `ScanSubmission::parse` acepta IPv4/IPv6 simples o CIDR `/32` (IPv4) / `/128` (IPv6), normalizados a la IP simple. Esa IP simple es la que viaja a `ms-usuarios` (resolución de credenciales e histórico) y al `ScanRequest`.
- Rangos más amplios -> `ScanSubmissionError::UnsupportedRange` (400); formato inválido -> `InvalidTarget` (400). Mensajes en español indicando que solo se admite una única IP.
- OpenAPI (`status = 400`), doc comments y `docs/` actualizados.

## Evidencia
- RED: `cargo test --lib domain` no compilaba (falta `UnsupportedRange`); `cargo test --test scan_submission` fallaba: `/32` publicaba `172.31.86.37/32` y `/24` respondía 504 en vez de 400.
- GREEN: ver cierre (`make verify`).

## Tareas
- [x] Tests unitarios de normalización/rechazo (domain)
- [x] Tests API: IP simple, /32, IPv6, /128, /24 -> 400, ScanRequest con IP simple
- [x] Implementación y docs
