#!/usr/bin/env bash
# init.sh — Verificación e inicialización del entorno
#
# Este script lo ejecuta el agente al COMENZAR una sesión y antes de
# declarar cualquier tarea como `done`. Si falla, la sesión no debe avanzar.
#
# Salida esperada: códigos de salida claros y bloques marcados con [OK]/[FAIL].

set -u
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
fail()  { printf "${RED}[FAIL]${NC}  %s\n" "$1"; }

EXIT_CODE=0

# La toolchain de Rust suele instalarse vía rustup en ~/.cargo/bin, que no
# siempre está en el PATH de shells no interactivos. Lo añadimos si hace falta.
if ! command -v cargo >/dev/null 2>&1 && [ -d "$HOME/.cargo/bin" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "── 1. Verificando entorno ─────────────────────────────"

if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo (Rust) no está instalado"
  exit 1
fi
ok "cargo -> $(cargo --version)"

if ! command -v rustc >/dev/null 2>&1; then
  fail "rustc no está instalado"
  exit 1
fi
ok "rustc -> $(rustc --version)"

if command -v docker >/dev/null 2>&1; then
  ok "docker -> $(docker --version)"
else
  warn "docker no está disponible — los tests de integración contra RabbitMQ real (testcontainers) lo requieren"
fi

echo ""
echo "── 2. Verificando archivos base del arnés ──────────────"

for f in AGENTS.md feature_list.json progress/current.md docs/architecture.md docs/conventions.md docs/verification.md docs/security-scope.md CHECKPOINTS.md; do
  if [ ! -f "$f" ]; then
    fail "Falta archivo base: $f"
    EXIT_CODE=1
  else
    ok "Existe $f"
  fi
done

echo ""
echo "── 3. Validando feature_list.json ──────────────────────"

if command -v jq >/dev/null 2>&1; then
  IN_PROGRESS_COUNT=$(jq '[.features[] | select(.status == "in_progress")] | length' feature_list.json)
  INVALID_STATUS_COUNT=$(jq '[.features[] | select(.status as $s | ["pending","in_progress","done","blocked"] | index($s) | not)] | length' feature_list.json)
  TOTAL=$(jq '.features | length' feature_list.json)

  if [ "$IN_PROGRESS_COUNT" -gt 1 ]; then
    fail "Hay $IN_PROGRESS_COUNT features en in_progress (máximo 1)"
    EXIT_CODE=1
  elif [ "$INVALID_STATUS_COUNT" -gt 0 ]; then
    fail "Hay $INVALID_STATUS_COUNT feature(s) con estado inválido"
    EXIT_CODE=1
  else
    ok "feature_list.json válido ($TOTAL features)"
  fi
else
  warn "jq no está instalado — se omite la validación de feature_list.json"
fi

echo ""
echo "── 4. Compilando, probando y documentando el crate ─────"

if [ ! -f "Cargo.toml" ]; then
  warn "Cargo.toml no existe todavía — scaffolding pendiente (ver feature 'scaffolding')"
else
  if cargo fmt --check 2>&1; then
    ok "cargo fmt --check sin diferencias"
  else
    fail "cargo fmt --check encontró diferencias de formato"
    EXIT_CODE=1
  fi

  if cargo clippy --all-targets -- -D warnings 2>&1; then
    ok "cargo clippy sin warnings"
  else
    fail "cargo clippy encontró warnings"
    EXIT_CODE=1
  fi

  if cargo test 2>&1; then
    ok "Tests unitarios pasan (los que requieren Docker están marcados #[ignore] y se omiten aquí)"
  else
    fail "Hay tests unitarios rotos"
    EXIT_CODE=1
  fi

  if cargo test -- --ignored 2>&1; then
    ok "Tests de integración con Docker (testcontainers, #[ignore]) pasan o no hay ninguno todavía"
  else
    fail "Hay tests de integración (testcontainers) rotos, o Docker no está disponible. Si es por Docker, documenta el bloqueo en progress/current.md (ver docs/verification.md) — no los reemplaces por mocks."
    EXIT_CODE=1
  fi

  if cargo doc --no-deps 2>&1; then
    ok "cargo doc genera sin errores (rustdoc de ítems públicos)"
  else
    fail "cargo doc falló — falta rustdoc en algún ítem público (#![deny(missing_docs)])"
    EXIT_CODE=1
  fi
fi

echo ""
echo "── 5. Resumen ──────────────────────────────────────────"

if [ $EXIT_CODE -eq 0 ]; then
  ok "Entorno listo. Puedes empezar a trabajar."
else
  fail "Entorno NO está listo. Resuelve los errores antes de avanzar."
fi

exit $EXIT_CODE
