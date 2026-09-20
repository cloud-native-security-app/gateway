# syntax=docker/dockerfile:1
#
# Imagen de producción de gateway (feature 11: containerization).
#
# Multi-stage:
#   - builder: toolchain Rust completa, compila el binario `gateway` (nombre
#     por defecto del paquete: Cargo.toml no declara `[[bin]]`) en release.
#   - runtime: distroless/cc (glibc + certificados CA + usuario `nonroot`),
#     contiene únicamente el binario `gateway`. Sin toolchain, sin código
#     fuente, sin shell/coreutils. Los certificados CA de la imagen base
#     cubren el TLS saliente que este binario negocia hacia 3 destinos:
#     Google (OIDC), `ms-usuarios` (si su URL es https) y el Broker (AMQPS).
#
# Las imágenes base se fijan por tag concreto Y por digest (`@sha256:...`) para
# builds reproducibles. Mismos digests que ya usa `user-service/Dockerfile`
# (mismo `rustc`/`cargo` 1.98 que reporta `./init.sh` de este repo) — al
# actualizar una base, refresca el digest con
# `docker buildx imagetools inspect <imagen:tag>`.

# ---------------------------------------------------------------------------
# Stage 1 — builder
# ---------------------------------------------------------------------------
FROM rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder

WORKDIR /app

# 1) Cachea la compilación de dependencias: con solo Cargo.toml/Cargo.lock y un
#    árbol de fuentes mínimo, `cargo build --release` compila todas las deps.
#    Mientras Cargo.toml/Cargo.lock no cambien, esta capa se reutiliza aunque
#    cambie `src/`.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo '//! placeholder para cachear dependencias' > src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# 2) Copia el código real y compila el binario. Este repo no tiene
#    migraciones ni otros artefactos que un `sqlx::migrate!` u similar
#    necesite embeber en tiempo de compilación (a diferencia de
#    `user-service`) — solo `src/` alimenta el binario final. Solo se
#    recompila el crate propio, no las dependencias ya cacheadas.
COPY src ./src
RUN touch src/lib.rs src/main.rs \
    && cargo build --release \
    && strip target/release/gateway

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
# distroless/cc-debian12: glibc + libgcc (para el binario Rust), paquete
# ca-certificates (TLS saliente hacia Google, ms-usuarios y el Broker vía
# rustls) y el usuario no-root `nonroot` (uid 65532). No trae shell ni
# gestor de paquetes.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

LABEL org.opencontainers.image.title="gateway" \
      org.opencontainers.image.description="API Manager / Gateway: único componente público de la plataforma blue/red team" \
      org.opencontainers.image.source="https://github.com/o-aguirre/gateway"

COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway

USER nonroot

ENTRYPOINT ["/usr/local/bin/gateway"]
