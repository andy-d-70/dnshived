// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package probepin pins a probe host's own API certificate by its SHA-256 fingerprint.
package probepin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Valid reports whether fp has the form sha256:<64 lowercase hex digits>.
func Valid(fp string) bool {
	return fingerprintPattern.MatchString(fp)
}

// Fingerprint returns the fingerprint of a DER-encoded certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return fmt.Sprintf("sha256:%x", sum)
}

// Config returns a client TLS config that accepts only the certificate with fingerprint fp.
// Chain and name checks are skipped: the probe's certificate is self-signed, and the pin is the check.
func Config(fp string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("probe presented no certificate")
			}
			if Fingerprint(raw[0]) != fp {
				return errors.New("probe certificate does not match the pinned fingerprint")
			}
			return nil
		},
	}
}

// ParsePin parses a pin given as host:port=sha256:<fingerprint>.
func ParsePin(v string) (addr, fp string, err error) {
	addr, fp, ok := strings.Cut(v, "=")
	if !ok || addr == "" || !Valid(fp) {
		return "", "", fmt.Errorf("want host:port=sha256:<64 hex digits>, got %q", v)
	}
	return addr, fp, nil
}
