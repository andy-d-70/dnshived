// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "sync"

type monotonicIdentity struct {
	mu     sync.Mutex
	epoch  uint64
	gen    uint64
	onPush func(epoch, gen uint64)
}

func newMonotonicIdentity(epoch, gen uint64, onPush func(epoch, gen uint64)) *monotonicIdentity {
	return &monotonicIdentity{epoch: epoch, gen: gen, onPush: onPush}
}

// applyEpoch applies epoch if it is strictly newer than what's already
// applied, pushing the combined identity.
func (p *monotonicIdentity) applyEpoch(epoch uint64) bool {
	p.mu.Lock()
	if epoch <= p.epoch {
		p.mu.Unlock()
		return false
	}
	p.epoch = epoch
	e, g := p.epoch, p.gen
	p.mu.Unlock()
	p.onPush(e, g)
	return true
}

// applyGeneration applies gen if it is strictly newer than what's already
// applied, pushing the combined identity.
func (p *monotonicIdentity) applyGeneration(gen uint64) bool {
	p.mu.Lock()
	if gen <= p.gen {
		p.mu.Unlock()
		return false
	}
	p.gen = gen
	e, g := p.epoch, p.gen
	p.mu.Unlock()
	p.onPush(e, g)
	return true
}
