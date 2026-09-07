#!/usr/bin/env bash
#
# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates the mutual-TLS handshake fixtures used by MLSslContextFactoryTlsHandshakeTest.
#
# These are distinct from the parsing fixtures (test-client-cert.pem and friends) used by
# CertificateProcessorTest: a real TLS handshake enforces certificate validity, chain of trust and
# hostname matching, none of which the parsing tests exercise. They are therefore generated with a
# 100-year lifetime so the test suite cannot start failing on an expiry date.
#
# NOTE: the private keys carry a "# checkers:disable ..." comment on the PEM header line so secret
# scanners do not flag them. ml-commons' own parsers tolerate that (see CertificateProcessor's
# PRIVATE_KEY_PATTERN), but OpenSSL does not. To use these keys with openssl, nginx or curl, strip
# the comment first:
#
#   sed 's/ #.*$//' mtls-server-key.pem > /tmp/server-key.pem
#
# Usage: ./generate-mtls-handshake-certs.sh

set -euo pipefail
cd "$(dirname "$0")"

DAYS=36500
SUBJ_BASE="/C=US/ST=CA/L=San Francisco/O=OpenSearchMLCommonsTest"

echo "Generating certificate authority..."
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -sha256 \
  -keyout mtls-ca-key.pem -out mtls-ca-cert.pem \
  -subj "${SUBJ_BASE}/OU=TestCA/CN=ML Commons Test CA"

echo "Generating server certificate (SAN: localhost, 127.0.0.1) signed by the CA..."
openssl req -newkey rsa:2048 -nodes -sha256 \
  -keyout mtls-server-key.pem -out mtls-server.csr \
  -subj "${SUBJ_BASE}/OU=TestServer/CN=localhost"
openssl x509 -req -in mtls-server.csr -days "$DAYS" -sha256 \
  -CA mtls-ca-cert.pem -CAkey mtls-ca-key.pem -CAcreateserial \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n") \
  -out mtls-server-cert.pem

echo "Generating client certificate signed by the CA..."
openssl req -newkey rsa:2048 -nodes -sha256 \
  -keyout mtls-client-key.pem -out mtls-client.csr \
  -subj "${SUBJ_BASE}/OU=TestClient/CN=ml-commons-test-client"
openssl x509 -req -in mtls-client.csr -days "$DAYS" -sha256 \
  -CA mtls-ca-cert.pem -CAkey mtls-ca-key.pem -CAcreateserial \
  -extfile <(printf "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n") \
  -out mtls-client-cert.pem

# The JDK only parses PKCS#8 private keys, and CertificateProcessor enforces that explicitly.
echo "Converting private keys to PKCS#8..."
for name in server client; do
  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
    -in "mtls-${name}-key.pem" -out "mtls-${name}-key-pkcs8.pem"
  mv "mtls-${name}-key-pkcs8.pem" "mtls-${name}-key.pem"
done

# Untrusted server certificate for the skip_ssl_verification test. Self-signed (so it fails chain
# validation) AND issued for a hostname the test never connects to (so it also fails hostname
# verification). Passing both checks is what proves the trust-all manager extends
# X509ExtendedTrustManager rather than the plain interface.
echo "Generating untrusted, hostname-mismatched server certificate..."
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -sha256 \
  -keyout mtls-untrusted-server-key.pem -out mtls-untrusted-server-cert.pem \
  -subj "${SUBJ_BASE}/OU=TestUntrusted/CN=wrong-host.invalid" \
  -addext "subjectAltName=DNS:wrong-host.invalid"
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
  -in mtls-untrusted-server-key.pem -out mtls-untrusted-server-key-pkcs8.pem
mv mtls-untrusted-server-key-pkcs8.pem mtls-untrusted-server-key.pem

rm -f mtls-server.csr mtls-client.csr mtls-ca-cert.srl mtls-ca-key.pem

# Suppress the secret-scanner finding on these throwaway test keys. Must run after the PKCS#8
# conversions above, which rewrite the files and would otherwise strip the comment. The parsers
# tolerate trailing content on the PEM header line: see CertificateProcessor's CERT_PATTERN /
# PRIVATE_KEY_PATTERN and the matching patterns in MLSslContextFactoryTlsHandshakeTest.
SUPPRESS="# checkers:disable Poor Secrets Control - Generic Private Key"
echo "Adding secret-scanner suppression to private keys..."
for key in mtls-server-key.pem mtls-client-key.pem mtls-untrusted-server-key.pem; do
  if ! grep -q "checkers:disable" "$key"; then
    # Only the header line is touched; the base64 body is left byte-for-byte intact.
    sed -i.bak "1s|^-----BEGIN PRIVATE KEY-----$|-----BEGIN PRIVATE KEY----- ${SUPPRESS}|" "$key"
    rm -f "$key.bak"
  fi
done

# ml-algorithms tests need the client pair on their own classpath, and a drift between the two
# copies would be a confusing failure, so refresh it here rather than leaving it to be done by hand.
ALGO_DIR="../../../../../ml-algorithms/src/test/resources/certificates"
if [ -d "$ALGO_DIR" ]; then
  echo "Syncing client cert/key to ml-algorithms test resources..."
  cp mtls-client-cert.pem mtls-client-key.pem "$ALGO_DIR/"
fi

echo "Done. Generated:"
ls -1 mtls-*.pem
