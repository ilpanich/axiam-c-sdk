#!/bin/sh
# Generate throwaway test PKI at BUILD time into $1. These keys are created at
# runtime and MUST NOT be committed (see .gitignore / secret-scan gate).
set -e
DIR="$1"
[ -n "$DIR" ] || { echo "usage: gen_pki.sh <out-dir>" >&2; exit 2; }
mkdir -p "$DIR"

# Self-signed test CA.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/ca.key" -out "$DIR/ca.crt" -days 2 \
    -subj "/CN=AXIAM Test CA" >/dev/null 2>&1

# Client identity certificate signed by the test CA (for mTLS wiring).
openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/client.key" -out "$DIR/client.csr" \
    -subj "/CN=test-device" >/dev/null 2>&1
openssl x509 -req -in "$DIR/client.csr" \
    -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
    -out "$DIR/client.crt" -days 2 >/dev/null 2>&1

# Server certificate signed by the test CA, with a loopback SAN (IP 127.0.0.1 +
# DNS localhost) so a real TLS handshake passes libcurl's strict hostname
# verification (CURLOPT_SSL_VERIFYHOST=2) when the client connects to
# https://127.0.0.1. Used by the loopback TLS-server round-trip test.
openssl req -newkey rsa:2048 -nodes \
    -keyout "$DIR/server.key" -out "$DIR/server.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1
cat > "$DIR/server_ext.cnf" <<'EOF'
subjectAltName = IP:127.0.0.1, DNS:localhost
EOF
openssl x509 -req -in "$DIR/server.csr" \
    -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
    -extfile "$DIR/server_ext.cnf" \
    -out "$DIR/server.crt" -days 2 >/dev/null 2>&1

echo "generated test PKI in $DIR"
