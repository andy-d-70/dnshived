// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package daemonstatus

import (
	"reflect"
	"testing"
	"time"
)

func fakeCache(maxAge time.Duration, calls *int, gotPatterns *[]string) *Cache {
	c := NewCache(maxAge, "dnshived-dnsmasq@*.service", "dnshived-relay.service")
	c.query = func(p []string) map[string]Status {
		*calls++
		*gotPatterns = p
		return map[string]Status{
			"dnshived-dnsmasq@core-dns.service": {Unit: "dnshived-dnsmasq@core-dns.service", ActiveState: "active"},
			"dnshived-relay.service":            {Unit: "dnshived-relay.service", ActiveState: "inactive"},
		}
	}
	return c
}

func TestCache_OneQueryServesManyReads(t *testing.T) {
	var calls int
	var patterns []string
	c := fakeCache(time.Minute, &calls, &patterns)
	if c.Get("dnshived-relay.service").ActiveState != "inactive" {
		t.Error("relay state wrong")
	}
	if len(c.Prefixed("dnshived-dnsmasq@")) != 1 {
		t.Error("prefix filter wrong")
	}
	c.Get("dnshived-dnsmasq@core-dns.service")
	if calls != 1 {
		t.Errorf("systemctl queried %d times for 3 reads, want 1", calls)
	}
	if !reflect.DeepEqual(patterns, []string{"dnshived-dnsmasq@*.service", "dnshived-relay.service"}) {
		t.Errorf("queried patterns %v", patterns)
	}
}

func TestCache_UnknownUnitIsNotActive(t *testing.T) {
	var calls int
	var patterns []string
	c := fakeCache(time.Minute, &calls, &patterns)
	if st := c.Get("dnshived-keepalived.service"); st.ActiveState != "" || st.Unit != "dnshived-keepalived.service" {
		t.Errorf("unknown unit = %+v", st)
	}
}

func TestCache_InvalidateAndExpiryRequery(t *testing.T) {
	var calls int
	var patterns []string
	c := fakeCache(time.Minute, &calls, &patterns)
	c.Get("dnshived-relay.service")
	c.Invalidate()
	c.Get("dnshived-relay.service")
	if calls != 2 {
		t.Errorf("after Invalidate: %d queries, want 2", calls)
	}
	c.maxAge = 0
	c.Get("dnshived-relay.service")
	if calls != 3 {
		t.Errorf("after expiry: %d queries, want 3", calls)
	}
}
