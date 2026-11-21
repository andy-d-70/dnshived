// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsrepl

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	TokenHeader  = "X-Dnsrepl-Token"
	pathVote     = "/internal/dnsrepl/vote"
	pathAppend   = "/internal/dnsrepl/append"
	pathSnapshot = "/internal/dnsrepl/snapshot"

	maxVoteBody   = 16 << 10
	maxAppendBody = 256 << 20
	maxSnapBody   = 1 << 30
)

// HTTPTransport sends the replication messages to a peer's API; Addr resolves a peer id to host:port.
type HTTPTransport struct {
	Client *http.Client
	Scheme string
	Addr   func(peer string) (string, bool)
	Token  string
}

func (t *HTTPTransport) post(ctx context.Context, peer, path string, in, out any) error {
	addr, ok := t.Addr(peer)
	if !ok {
		return fmt.Errorf("dnsrepl: no address for %s", peer)
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Scheme+"://"+addr+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(TokenHeader, t.Token)
	resp, err := t.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("dnsrepl: %s answered %d: %s", peer, resp.StatusCode, bytes.TrimSpace(msg))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxSnapBody)).Decode(out)
}

func (t *HTTPTransport) Vote(ctx context.Context, peer string, req VoteReq) (VoteResp, error) {
	var out VoteResp
	return out, t.post(ctx, peer, pathVote, req, &out)
}

func (t *HTTPTransport) Append(ctx context.Context, peer string, req AppendReq) (AppendResp, error) {
	var out AppendResp
	return out, t.post(ctx, peer, pathAppend, req, &out)
}

func (t *HTTPTransport) Snapshot(ctx context.Context, peer string, req SnapReq) (SnapResp, error) {
	var out SnapResp
	return out, t.post(ctx, peer, pathSnapshot, req, &out)
}

// Routes registers the three receiving endpoints. allow gates the caller (trusted hosts); the token is the shared secret.
func (d *Driver) Routes(mux *http.ServeMux, token string, allow func(*http.Request) bool) {
	guard := func(limit int64, h func(body []byte) (any, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if allow != nil && !allow(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get(TokenHeader)), []byte(token)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			out, err := h(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		}
	}
	decode := func(body []byte, v any) error {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		return dec.Decode(v)
	}
	mux.HandleFunc("POST "+pathVote, guard(maxVoteBody, func(b []byte) (any, error) {
		var req VoteReq
		if err := decode(b, &req); err != nil {
			return nil, err
		}
		return d.HandleVote(req)
	}))
	mux.HandleFunc("POST "+pathAppend, guard(maxAppendBody, func(b []byte) (any, error) {
		var req AppendReq
		if err := decode(b, &req); err != nil {
			return nil, err
		}
		return d.HandleAppend(req)
	}))
	mux.HandleFunc("POST "+pathSnapshot, guard(maxSnapBody, func(b []byte) (any, error) {
		var req SnapReq
		if err := decode(b, &req); err != nil {
			return nil, err
		}
		return d.HandleSnapshot(req)
	}))
}
