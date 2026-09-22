#!/usr/bin/env bash
# rabbitmq/generate-lab-certs.sh
#
# Genera una CA de laboratorio y un certificado de servidor firmado por
# ella, para habilitar AMQPS (TLS) en el contenedor rabbitmq:4.3.5-management
# que levantan los tests de integración de `broker` (ver
# tests/scan_submission.rs, feature `scan_submission`, y
# docs/security-scope.md). Mismo patrón que broker/rabbitmq/generate-lab-certs.sh
# (misma plataforma) — no se re-deriva, se adapta literalmente.
#
# NO usar en producción: la CA y la clave privada quedan en texto plano en
# rabbitmq/tls/, pensadas para ser regeneradas y/o descartadas, nunca como
# material real (por eso rabbitmq/tls/*.pem y *.key están en .gitignore).
# El CN/O del subject (`security-app-lab`) deja explícito que no es válido
# para producción.
#
# Uso: ./rabbitmq/generate-lab-certs.sh
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tls"
DAYS=825           # tope aceptado por navegadores/clientes modernos para hojas
CA_DAYS=3650        # la CA de laboratorio puede vivir más
SUBJ_CA="/C=CL/O=security-app-lab/OU=gateway/CN=security-app-lab-CA"
SUBJ_SERVER="/C=CL/O=security-app-lab/OU=gateway/CN=rabbitmq"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# --- 1. CA de laboratorio ---------------------------------------------
openssl genrsa -out ca_key.pem 4096
openssl req -x509 -new -nodes \
  -key ca_key.pem \
  -sha256 -days "$CA_DAYS" \
  -subj "$SUBJ_CA" \
  -out ca_certificate.pem

# --- 2. Clave + CSR del servidor, con SAN para el testcontainer --------
# SAN incluye:
#   - rabbitmq   -> nombre de host habitual dentro de la red del contenedor
#   - localhost  -> conexiones desde el host (tests de integración corridos
#                    fuera de la red del contenedor, vía puerto publicado)
#   - 127.0.0.1  -> IP loopback explícita
cat > server_ext.cnf <<'EOF'
subjectAltName = DNS:rabbitmq,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl genrsa -out server_key.pem 4096
openssl req -new \
  -key server_key.pem \
  -subj "$SUBJ_SERVER" \
  -out server_request.csr

openssl x509 -req \
  -in server_request.csr \
  -CA ca_certificate.pem -CAkey ca_key.pem -CAcreateserial \
  -sha256 -days "$DAYS" \
  -extfile server_ext.cnf \
  -out server_certificate.pem

rm -f server_request.csr server_ext.cnf ca_certificate.srl

chmod 640 ca_key.pem
# server_key.pem debe ser legible por el usuario "rabbitmq" (no-root) dentro
# del contenedor oficial, que no coincide con el UID del host que generó el
# archivo (bind-mount, no un volumen gestionado por Docker) — sin esto,
# RabbitMQ falla al arrancar con "ssl_options.keyfile invalid, PEM file does
# not exist, cannot be read...". Aceptable para material exclusivamente de
# laboratorio, nunca real.
chmod 644 server_key.pem
chmod 644 ca_certificate.pem server_certificate.pem

echo "Certificados de laboratorio generados en $CERT_DIR:"
echo "  ca_certificate.pem      (CA de laboratorio, publica)"
echo "  ca_key.pem              (clave privada de la CA de laboratorio)"
echo "  server_certificate.pem  (cert de servidor, firmado por la CA de arriba)"
echo "  server_key.pem          (clave privada del servidor)"
