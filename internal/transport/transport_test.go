// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package transport

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// burst fires n parallel requests twice, with a pause in between, and returns
// how many TCP connections the server saw.
func burst(t *testing.T, tr *http.Transport, http2 bool, n int) int64 {
	t.Helper()
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = http2
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	for round := 0; round < 2; round++ {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(srv.URL)
				if err != nil {
					t.Error(err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}()
		}
		wg.Wait()
	}
	return conns.Load()
}

func TestTune_AParallelBurstDoesNotDialPerRequest(t *testing.T) {
	const n = 60
	for _, tc := range []struct {
		name  string
		http2 bool
	}{{"HTTP/2", true}, {"HTTP/1.1 fallback", false}} {
		t.Run(tc.name, func(t *testing.T) {
			got := burst(t, Tune(&http.Transport{}), tc.http2, n)
			if got > maxConnsPerHost {
				t.Errorf("%d connections for two bursts of %d requests, want at most %d", got, n, maxConnsPerHost)
			}
		})
	}
}

func TestTune_AWaitingRequestStillHonoursItsTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	defer srv.Close()
	defer close(block)
	tr := Tune(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}})
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 300 * time.Millisecond}
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4*maxConnsPerHost; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, err := client.Get(srv.URL); err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("a hung server held %d queued requests for %v; each must give up at its own timeout", 4*maxConnsPerHost, el)
	}
}

func TestTune_Settings(t *testing.T) {
	tr := Tune(&http.Transport{})
	if !tr.ForceAttemptHTTP2 || tr.MaxIdleConnsPerHost < 16 || tr.MaxConnsPerHost == 0 || tr.IdleConnTimeout == 0 || tr.TLSHandshakeTimeout == 0 {
		t.Errorf("%+v", tr)
	}
}
