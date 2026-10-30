// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "sync/atomic"

// configRef is the single, live, atomically-swappable *WebConfig every
// request-handling goroutine (and background ticker) reads through.
type configRef struct {
	p atomic.Pointer[WebConfig]
}

// newConfigRef wraps cfg as the initial live value.
func newConfigRef(cfg *WebConfig) *configRef {
	r := &configRef{}
	r.Store(cfg)
	return r
}

// Load returns the current live *WebConfig.
func (r *configRef) Load() *WebConfig {
	return r.p.Load()
}

// Store atomically publishes cfg as the new live value.
func (r *configRef) Store(cfg *WebConfig) {
	probePinTransport.SetPins(probePinsOf(cfg.ProbeHosts))
	r.p.Store(cfg)
}
