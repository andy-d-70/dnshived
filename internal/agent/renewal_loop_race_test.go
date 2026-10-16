// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"sync"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestRenewalLoop_SurvivesConcurrentTeardown(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "test-psk", "/tmp", nil, nil)

	const iterations = 200
	var wg sync.WaitGroup

	for i := 0; i < iterations; i++ {
		a.mu.Lock()
		ticker := time.NewTicker(time.Millisecond)
		quit := make(chan struct{})
		a.renewTicker = ticker
		a.quitRenew = quit
		a.mu.Unlock()

		wg.Add(1)
		go func(ticker *time.Ticker, quit chan struct{}) {
			defer wg.Done()
			a.renewalLoop(ticker, quit)
		}(ticker, quit)

		time.Sleep(2 * time.Millisecond)

		a.mu.Lock()
		ticker.Stop()
		close(quit)
		a.renewTicker = nil
		a.mu.Unlock()
	}

	wg.Wait() // no panic anywhere in this whole loop is the actual assertion
}
