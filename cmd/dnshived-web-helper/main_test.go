// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// TestRestartSelf_Throttled mirrors dnshived-probe-helper's own identical
// test.
func TestRestartSelf_Throttled(t *testing.T) {
	restartMu.Lock()
	lastRestartAt = time.Now()
	restartMu.Unlock()

	throttled, err := restartSelf()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !throttled {
		t.Errorf("throttled = false, want true — a restart within 10s of the last one must be reported as suppressed")
	}
}

// TestRestartSelf_NotThrottledAfterWindow verifies the rate limit doesn't
// fire once the 10s window has passed.
func TestRestartSelf_NotThrottledAfterWindow(t *testing.T) {
	restartMu.Lock()
	lastRestartAt = time.Now().Add(-11 * time.Second)
	restartMu.Unlock()

	throttled, _ := restartSelf()
	if throttled {
		t.Errorf("throttled = true, want false — restart should not be rate-limited once the 10s window has passed")
	}
}

func TestHandleConn_UnknownCommandRespondsWithError(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go handleConn(server)

	if err := json.NewEncoder(client).Encode(Request{Command: "not-a-real-command"}); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK {
		t.Error("resp.OK = true for an unknown command, want false")
	}
	if resp.Error == "" {
		t.Error("resp.Error is empty, want an explanation")
	}
}

// TestHandleConn_RestartSelf_AlwaysRespondsOverTheRealSocket mirrors
// dnshived-helper's own
// TestHandleConn_RestartHelper_RespondsBeforeSelfRestarting in shape.
func TestHandleConn_RestartSelf_AlwaysRespondsOverTheRealSocket(t *testing.T) {
	restartMu.Lock()
	lastRestartAt = time.Time{}
	restartMu.Unlock()

	server, client := net.Pipe()
	defer client.Close()
	go handleConn(server)

	if err := json.NewEncoder(client).Encode(Request{Command: "restart-self"}); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
