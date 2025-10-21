#!/usr/bin/env bash
set -euo pipefail

# Generates a test CA and a server certificate with SANs suitable for docker-compose tests.
# Output directory: test/certs

OUTDIR="test/certs"
mkdir -p "$OUTDIR"

echo "Generating CA and server certificate into $OUTDIR"

# 1) Generate CA key and self-signed certificate
openssl genrsa -out "$OUTDIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$OUTDIR/ca.key" -sha256 -days 3650 \
  -subj "/C=US/ST=Test/L=Test/O=Test CA/CN=Test Root CA" \
  -out "$OUTDIR/ca.crt"

# 2) Generate server key and CSR
openssl genrsa -out "$OUTDIR/server.key" 2048
openssl req -new -key "$OUTDIR/server.key" -subj "/CN=vnt-control" -out "$OUTDIR/server.csr"

# 3) Create SAN config for server certificate
cat > "$OUTDIR/san.cnf" <<EOF
[ v3_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = vnt-control
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# 4) Sign the CSR with the CA, producing a server certificate with SANs
openssl x509 -req -in "$OUTDIR/server.csr" -CA "$OUTDIR/ca.crt" -CAkey "$OUTDIR/ca.key" \
  -CAcreateserial -out "$OUTDIR/server.crt" -days 365 -sha256 -extfile "$OUTDIR/san.cnf" -extensions v3_ext

# 5) Set safe permissions
chmod 644 "$OUTDIR"/*.crt || true
chmod 600 "$OUTDIR"/*.key || true

echo "Certificate generation complete. Files in $OUTDIR:"
ls -la "$OUTDIR"
