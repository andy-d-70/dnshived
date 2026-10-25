// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnshived/internal/tlspin"
)

func otherCertPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestFetchProbeConfig_PinsTheClusterCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(probeConfigResponse{Role: "core-1"})
	}))
	defer srv.Close()
	t.Cleanup(func() { tlspin.SetFile("") })
	clusterHTTPClient.Transport.(*http.Transport).DisableKeepAlives = true
	node := ClusterNode{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "https://"), TLS: true}

	if err := tlspin.SetPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchProbeConfig(node, "tok"); err != nil {
		t.Errorf("pinned cluster certificate refused: %v", err)
	}

	if err := tlspin.SetPEM(otherCertPEM(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchProbeConfig(node, "tok"); err == nil || !strings.Contains(err.Error(), "not the cluster certificate") {
		t.Errorf("a core with a different certificate was accepted: %v", err)
	}
}
