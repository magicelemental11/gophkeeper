package testcert

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)

func TestWrite(t *testing.T) {
	f := Write(t, t.TempDir())
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(f.CA)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range append(Hosts, "127.0.0.1") {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
}

func TestCredentials(t *testing.T) {
	creds, ca := Credentials(t)
	if creds.Info().SecurityProtocol != "tls" {
		t.Fatalf("protocol %q", creds.Info().SecurityProtocol)
	}
	if _, err := os.Stat(ca); err != nil {
		t.Fatal(err)
	}
}
