// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package probepin

import (
	"net/http"
	"sync/atomic"
)

// Router sends a request for a pinned host:port to that host's own transport, and every other request to Next.
type Router struct {
	Next http.RoundTripper
	pins atomic.Pointer[map[string]http.RoundTripper]
}

func (r *Router) RoundTrip(req *http.Request) (*http.Response, error) {
	if pins := r.pins.Load(); pins != nil {
		if rt, ok := (*pins)[req.URL.Host]; ok {
			return rt.RoundTrip(req)
		}
	}
	return r.Next.RoundTrip(req)
}

// SetPins replaces the pins: pins maps a host:port to its certificate fingerprint. Idle connections of the
// replaced transports are closed.
func (r *Router) SetPins(pins map[string]string) {
	m := make(map[string]http.RoundTripper, len(pins))
	for addr, fp := range pins {
		m[addr] = &http.Transport{TLSClientConfig: Config(fp)}
	}
	if old := r.pins.Swap(&m); old != nil {
		for _, rt := range *old {
			if t, ok := rt.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
		}
	}
}
