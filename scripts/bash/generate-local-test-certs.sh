#!/usr/bin/env bash

set -euo pipefail

out_dir="${1:-.tmp/local-certs}"
mkdir -p "${out_dir}"

certificate_path="${out_dir}/loopback-server.pem"
private_key_path="${out_dir}/loopback-server.key"
roots_path="${out_dir}/roots.pem"
config_path="$(mktemp "${out_dir%/}/openssl-local-certs.XXXXXX.cnf")"

cleanup() {
  rm -f "${config_path}"
}
trap cleanup EXIT

cat > "${config_path}" <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = localhost

[v3_req]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = loopback.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "${private_key_path}"
openssl req \
  -x509 \
  -new \
  -sha256 \
  -key "${private_key_path}" \
  -out "${certificate_path}" \
  -days 825 \
  -config "${config_path}" \
  -extensions v3_req

cp "${certificate_path}" "${roots_path}"

printf 'Generated local TLS credentials:\n'
printf '  Certificate: %s\n' "${certificate_path}"
printf '  Private key: %s\n' "${private_key_path}"
printf '  Trust roots: %s\n' "${roots_path}"
