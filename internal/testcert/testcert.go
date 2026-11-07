// Package testcert issues a throwaway CA and a server certificate for tests that need real TLS.
package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
)

// Hosts are the names the server certificate is valid for.
var Hosts = []string{"localhost", "bufnet"}

// Files are the paths of the PEM files written by Write.
type Files struct {
	CA   string
	Cert string
	Key  string
}

// Write issues a CA and a server certificate for Hosts and 127.0.0.1, valid for an hour,
// and writes them to dir.
func Write(tb testing.TB, dir string) Files {
	tb.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		tb.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		tb.Fatal(err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: Hosts[0]},
		DNSNames:     Hosts,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		tb.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		tb.Fatal(err)
	}

	f := Files{
		CA:   filepath.Join(dir, "ca.crt"),
		Cert: filepath.Join(dir, "server.crt"),
		Key:  filepath.Join(dir, "server.key"),
	}
	writePEM(tb, f.CA, "CERTIFICATE", caDER)
	writePEM(tb, f.Cert, "CERTIFICATE", srvDER)
	writePEM(tb, f.Key, "EC PRIVATE KEY", keyDER)
	return f
}

// Credentials issues certificates into a temporary directory and returns the server TLS credentials
// with the path of the CA certificate that verifies them.
func Credentials(tb testing.TB) (credentials.TransportCredentials, string) {
	tb.Helper()
	f := Write(tb, tb.TempDir())
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		tb.Fatal(err)
	}
	return credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), f.CA
}

func writePEM(tb testing.TB, path, kind string, der []byte) {
	tb.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		tb.Fatal(err)
	}
}
