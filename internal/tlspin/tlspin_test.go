// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package tlspin

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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSignedServer starts a TLS server with its own fresh certificate
// (httptest's default certificate is the same for every server).
func selfSignedServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func writeCertPEM(t *testing.T, path string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConfig_PinsTheClusterCertificate(t *testing.T) {
	cluster := selfSignedServer(t)
	stranger := selfSignedServer(t)
	t.Cleanup(func() { SetFile("") })

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: Config(), DisableKeepAlives: true}}
	get := func(url string) error {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	SetFile("")
	if err := get(stranger.URL); err != nil {
		t.Errorf("without a pin, connections must work as before: %v", err)
	}

	pin := filepath.Join(t.TempDir(), "cert.pem")
	writeCertPEM(t, pin, cluster.TLS.Certificates[0].Certificate[0])
	SetFile(pin)
	if err := get(cluster.URL); err != nil {
		t.Errorf("cluster certificate refused: %v", err)
	}
	if err := get(stranger.URL); err == nil {
		t.Error("a different certificate was accepted")
	} else if !strings.Contains(err.Error(), "peer sha256 ") {
		t.Errorf("refusal does not name the peer certificate: %v", err)
	}

	writeCertPEM(t, pin, stranger.TLS.Certificates[0].Certificate[0])
	if err := get(stranger.URL); err != nil {
		t.Errorf("rotated certificate in the pinned file not picked up: %v", err)
	}
}
