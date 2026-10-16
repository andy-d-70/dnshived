// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net"
	"testing"
)

// BenchmarkCacheShardIndex measures cacheShardIndex's own per-call cost.
func BenchmarkCacheShardIndex(b *testing.B) {
	key := cacheKey{qnameRaw: string(mustEncodeName(b, "www.example.com")), qtype: 1, qclass: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cacheShardIndex(key)
	}
}

func BenchmarkCacheGet_Hit(b *testing.B) {
	ip := net.ParseIP("10.9.9.9").To4()
	resp := buildMessage(b, 0x1234, 0x8180, "www.example.com", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))
	key := cacheKey{qnameRaw: "www.example.com", qtype: 1, qclass: 1}
	cacheSet(key, resp, 300)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := cacheGet(key); !ok {
			b.Fatal("expected a cache hit")
		}
	}
}

// BenchmarkCacheGet_Miss measures the cost of the common "nothing cached
// yet" path -- shard lookup + a failed map lookup, no copy/TTL work at
// all.
func BenchmarkCacheGet_Miss(b *testing.B) {
	key := cacheKey{qnameRaw: "never-cached.example.com", qtype: 1, qclass: 1}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := cacheGet(key); ok {
			b.Fatal("expected a cache miss")
		}
	}
}

// BenchmarkCacheSet measures insertion cost under sustained load with
// DISTINCT keys every call.
func BenchmarkCacheSet(b *testing.B) {
	ip := net.ParseIP("10.9.9.9").To4()
	resp := buildMessage(b, 1, 0x8180, "bench.example.com", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))

	keys := make([]cacheKey, b.N)
	for i := range keys {
		keys[i] = cacheKey{qnameRaw: syntheticQName(i), qtype: 1, qclass: 1}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cacheSet(keys[i], resp, 300)
	}
}

// syntheticQName produces a distinct, realistic-length raw qname for
// benchmark key generation.
func syntheticQName(i int) string {
	const digits = "0123456789"
	b := make([]byte, 0, 24)
	b = append(b, "host"...)
	n := i
	if n == 0 {
		b = append(b, '0')
	}
	for n > 0 {
		b = append(b, digits[n%10])
		n /= 10
	}
	b = append(b, ".bench.example.com"...)
	return string(b)
}

// BenchmarkRewriteResponseNames measures the full uncompressed re-encode
// rewriteResponseNames always does.
func BenchmarkRewriteResponseNames(b *testing.B) {
	ip := net.ParseIP("10.9.9.9").To4()
	resp := buildMessage(b, 0x1234, 0x8180, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rewriteResponseNames(resp, "backend.internal.test", "app.dantetest.local"); err != nil {
			b.Fatalf("rewriteResponseNames: %v", err)
		}
	}
}

// BenchmarkRewriteResponseNames_MultiAnswer exercises the same rewrite
// against a larger, multi-answer response.
func BenchmarkRewriteResponseNames_MultiAnswer(b *testing.B) {
	resp := buildMessage(b, 0x1234, 0x8180, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, net.ParseIP("10.9.9.1").To4()),
		buildPointerRR(12, 1, 1, 300, net.ParseIP("10.9.9.2").To4()),
		buildPointerRR(12, 1, 1, 300, net.ParseIP("10.9.9.3").To4()),
		buildPointerRR(12, 1, 1, 300, net.ParseIP("10.9.9.4").To4()),
	)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rewriteResponseNames(resp, "backend.internal.test", "app.dantetest.local"); err != nil {
			b.Fatalf("rewriteResponseNames: %v", err)
		}
	}
}
