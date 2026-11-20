// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package transport tunes the HTTP transports that talk to cluster nodes and
// probe hosts. A page asks the same host for dozens of things at once; with
// the defaults of a transport that has its own TLS config (HTTP/1.1, two idle
// connections per host) every burst opens a new connection and runs a full
// TLS handshake for each request.
package transport

import (
	"net/http"
	"time"
)

const (
	maxIdleConns        = 128
	maxIdleConnsPerHost = 32
	maxConnsPerHost     = 8
	idleConnTimeout     = 90 * time.Second
	handshakeTimeout    = 10 * time.Second
)

// Tune makes t reuse connections: HTTP/2 when the peer offers it (one
// connection carries all parallel requests), at most maxConnsPerHost
// connections per host (a burst waits for a free one instead of dialing and
// handshaking once per request; each request still honours its own timeout),
// and a bounded handshake. t is returned for chaining.
func Tune(t *http.Transport) *http.Transport {
	t.ForceAttemptHTTP2 = true
	t.MaxIdleConns = maxIdleConns
	t.MaxIdleConnsPerHost = maxIdleConnsPerHost
	t.MaxConnsPerHost = maxConnsPerHost
	t.IdleConnTimeout = idleConnTimeout
	t.TLSHandshakeTimeout = handshakeTimeout
	return t
}
