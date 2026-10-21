# vuln-confidence (gateway part)

Feature id: `vuln-confidence` | Branch: `feature/vuln_confidence`

## Objective

Aceptar y relayar el campo opcional `confidence` de `VulnFinding` sin romper el parseo de resultados antiguos.

## Contract (compartido con nmap-service y front)

`VulnFinding.confidence`: opcional, `"confirmed"` | `"version_match"` (snake_case). Ausente = desconocido (resultados antiguos). Se omite al serializar cuando es `None`.

## Deploy order

gateway -> nmap-service -> front. `ScanResult`/`PortFinding`/`VulnFinding` usan `deny_unknown_fields`: si nmap-service emitiera `confidence` antes, todo outcome `completed` fallaría al parsear. El gateway debe desplegarse primero.

## Tasks

- [x] T1 Tests primero (domain): sin `confidence` parsea y re-serializa igual; `confirmed`/`version_match` round-trip verbatim; `"maybe"` se rechaza.
- [x] T2 `Confidence` enum + `VulnFinding.confidence` + registro en OpenAPI (`api.rs`).
- [x] T3 `make verify`.

TDD: enabled, runner `cargo test`. Route: delegated direct, single writer.

## Decision: valores desconocidos

Se RECHAZAN (estricto). Razones: es coherente con el resto del contrato (`deny_unknown_fields`, schema del broker cerrado); aceptar en silencio como `None` ocultaría datos y desalinearía el relay verbatim (se perdería el valor al re-serializar). Riesgo asumido: un valor nuevo iría a DLQ si nmap-service lo emite antes; se mitiga con el mismo orden de despliegue (gateway primero) cada vez que se amplíe el enum.

## Evidence

- RED: `cargo test --lib vuln_finding` -> no compila (`Confidence` indefinido, sin campo `confidence`).
- GREEN: mismos 3 tests pasan (3 passed).
- `make verify`: ver reporte final.
