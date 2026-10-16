// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package trustedhosts

import "net"

// Set is a source-IP allowlist.
type Set map[string]bool

// New builds a Set from a list of bare IP addresses (no port).
func New(hosts []string) Set {
	if len(hosts) == 0 {
		return nil
	}
	s := make(Set, len(hosts))
	for _, h := range hosts {
		s[h] = true
	}
	return s
}

// Allowed reports whether remoteAddr (an http.Request.RemoteAddr-shaped
// "host:port" string, or a bare host) is permitted.
func (s Set) Allowed(remoteAddr string) bool {
	if len(s) == 0 {
		return true
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return s[host]
}
