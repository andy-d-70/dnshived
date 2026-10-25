// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package tlspin verifies cluster peers against the one shared, self-signed
// cluster certificate that every core API and web UI serves. Hostname and
// CA checks cannot work for a self-signed cert reached by IP, but a pin can.
package tlspin

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"dnshived/internal/loglevel"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
)

var pin struct {
	mu     sync.RWMutex
	path   string
	certs  [][]byte
	warned bool
}

// SetFile pins the certificate(s) in path; "" disables pinning.
func SetFile(path string) {
	pin.mu.Lock()
	pin.path = path
	pin.mu.Unlock()
	if path != "" {
		if err := reload(); err != nil {
			loglevel.Warnf("[TLS] cannot read the cluster certificate %s for pinning: %v — connections to cluster peers will fail until it is readable", path, err)
		}
	}
}

// inlinePath marks a pin set from PEM data; there is no file to reload.
const inlinePath = "<inline>"

// SetPEM pins the certificate(s) in pemData, for a process that has no certificate file.
func SetPEM(pemData []byte) error {
	certs := parseCerts(pemData)
	if len(certs) == 0 {
		return errors.New("no certificate in PEM data")
	}
	pin.mu.Lock()
	pin.path = inlinePath
	pin.certs = certs
	pin.mu.Unlock()
	return nil
}

func reload() error {
	pin.mu.RLock()
	path := pin.path
	pin.mu.RUnlock()
	if path == inlinePath {
		return errors.New("inline pin has no file to reload")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	certs := parseCerts(data)
	if len(certs) == 0 {
		return errors.New("no certificate in file")
	}
	pin.mu.Lock()
	pin.certs = certs
	pin.mu.Unlock()
	return nil
}

func parseCerts(data []byte) [][]byte {
	var certs [][]byte
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
	return certs
}

func matches(leaf []byte) (matched, pinning bool) {
	pin.mu.RLock()
	defer pin.mu.RUnlock()
	if pin.path == "" {
		return false, false
	}
	for _, c := range pin.certs {
		if bytes.Equal(c, leaf) {
			return true, true
		}
	}
	return false, true
}

// ErrNotClusterCert is wrapped by every refusal.
var ErrNotClusterCert = errors.New("peer certificate is not the cluster certificate")

func verifyPeer(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return ErrNotClusterCert
	}
	leaf := cs.PeerCertificates[0].Raw
	matched, pinning := matches(leaf)
	if !pinning {
		pin.mu.Lock()
		if !pin.warned {
			pin.warned = true
			loglevel.Warnf("[TLS] no cluster certificate configured — connections to cluster peers are not verified")
		}
		pin.mu.Unlock()
		return nil
	}
	if matched {
		return nil
	}
	if reload() == nil {
		if matched, _ = matches(leaf); matched {
			return nil
		}
	}
	sum := sha256.Sum256(leaf)
	return fmt.Errorf("%w (peer sha256 %s)", ErrNotClusterCert, hex.EncodeToString(sum[:]))
}

// Config verifies peers against the pinned cluster certificate instead of
// a CA chain and hostname.
func Config() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection:   verifyPeer,
	}
}
