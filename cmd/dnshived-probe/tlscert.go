// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"dnshived/internal/probepin"
)

// probeCertDir holds the probe's own API certificate. It is a separate identity from the cluster's:
// the probe never holds the cluster key.
var probeCertDir = "/var/lib/dnshived-probe/tls"

// probeTLSPort is the port of the probe's TLS API; the plain API stays on listen_addr until every probe is upgraded.
const probeTLSPort = "9445"

func loadOrCreateProbeCert(dir string) (tls.Certificate, string, error) {
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := createProbeCert(dir, certPath, keyPath); err != nil {
			return tls.Certificate{}, "", err
		}
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("load probe certificate: %w", err)
	}
	return pair, probepin.Fingerprint(pair.Certificate[0]), nil
}

// createProbeCert writes the key before the certificate, so an interrupted run leaves no certificate and the next start retries.
func createProbeCert(dir, certPath, keyPath string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate probe key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return fmt.Errorf("probe certificate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dnshived-probe"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("sign probe certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal probe key: %w", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return fmt.Errorf("write probe key: %w", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return fmt.Errorf("write probe certificate: %w", err)
	}
	return nil
}

// liveCert is the certificate the TLS listener serves; an uploaded
// certificate replaces it without a restart.
var (
	liveCert        atomic.Pointer[tls.Certificate]
	liveFingerprint atomic.Value
)

func setLiveCert(c tls.Certificate, fp string) {
	liveCert.Store(&c)
	liveFingerprint.Store(fp)
}

func currentFingerprint() string {
	if v, ok := liveFingerprint.Load().(string); ok {
		return v
	}
	return ""
}

func serveLiveCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := liveCert.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no probe certificate loaded")
}

const maxUploadedPEM = 64 << 10

// installUploadedCert checks an operator's certificate and key and makes
// them the probe's own. The pair is written to a new directory that then
// replaces the old one, so a failure leaves the previous certificate.
func installUploadedCert(dir string, certPEM, keyPEM []byte) (tls.Certificate, string, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 || len(certPEM) > maxUploadedPEM || len(keyPEM) > maxUploadedPEM {
		return tls.Certificate{}, "", fmt.Errorf("certificate and key are both required, at most %d bytes each", maxUploadedPEM)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("the key does not match the certificate or one of them is not PEM: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("parse certificate: %w", err)
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return tls.Certificate{}, "", fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
	}
	if now.Add(24 * time.Hour).Before(leaf.NotBefore) {
		return tls.Certificate{}, "", fmt.Errorf("the certificate is not valid before %s", leaf.NotBefore.Format("2006-01-02"))
	}
	if len(pair.Certificate) > 8 {
		return tls.Certificate{}, "", errors.New("at most 8 certificates in the chain")
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return tls.Certificate{}, "", errors.New("an RSA key needs at least 2048 bits")
		}
	case *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return tls.Certificate{}, "", errors.New("unsupported key type")
	}

	fresh := dir + ".new"
	if err := os.RemoveAll(fresh); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.MkdirAll(fresh, 0o700); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(filepath.Join(fresh, "key.pem"), keyPEM, 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(filepath.Join(fresh, "cert.pem"), certPEM, 0o644); err != nil {
		return tls.Certificate{}, "", err
	}
	old := dir + ".old"
	os.RemoveAll(old)
	if err := os.Rename(dir, old); err != nil && !os.IsNotExist(err) {
		return tls.Certificate{}, "", err
	}
	if err := os.Rename(fresh, dir); err != nil {
		os.Rename(old, dir)
		return tls.Certificate{}, "", err
	}
	os.RemoveAll(old)
	return pair, probepin.Fingerprint(pair.Certificate[0]), nil
}
