#!/bin/sh
set -eu

dir="${1:-certs}"
mkdir -p "$dir"
cd "$dir"

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=GophKeeper dev CA" 2>/dev/null

openssl req -newkey rsa:4096 -sha256 -nodes \
  -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null

printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256 -extfile server.ext 2>/dev/null

rm -f server.csr server.ext ca.srl
chmod 600 ca.key server.key
echo "certificates written to $dir: ca.crt, server.crt, server.key"
