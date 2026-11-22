// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hotChanges gives, for every setting a reload applies at once, a changed value and how to read it back.
var hotChanges = map[string]struct {
	json string
	got  func(*Config) any
	want any
}{
	"upstreams":                 {`["127.0.0.2"]`, func(c *Config) any { return c.Upstreams }, []string{"127.0.0.2"}},
	"allowed_interfaces":        {`["lo"]`, func(c *Config) any { return c.AllowedInterfaces }, []string{"lo"}},
	"rate_limit":                {`7`, func(c *Config) any { return c.RateLimit }, 7},
	"rate_burst":                {`9`, func(c *Config) any { return c.RateBurst }, 9},
	"rate_limit_scope":          {`"host"`, func(c *Config) any { return c.RateLimitScope }, "host"},
	"interface_rate_limit":      {`11`, func(c *Config) any { return c.InterfaceRateLimit }, 11},
	"interface_rate_burst":      {`12`, func(c *Config) any { return c.InterfaceRateBurst }, 12},
	"upstream_socket_pool_size": {`3`, func(c *Config) any { return c.UpstreamSocketPoolSize }, 3},
	"cache_size":                {`77`, func(c *Config) any { return c.CacheSize }, 77},
	"cache_max_bytes":           {`1000`, func(c *Config) any { return c.CacheMaxBytes }, 1000},
	"max_outstanding":           {`5`, func(c *Config) any { return c.MaxOutstanding }, 5},
	"max_tcp_connections":       {`6`, func(c *Config) any { return c.MaxTCPConnections }, 6},
	"max_tcp_per_source":        {`2`, func(c *Config) any { return c.MaxTCPPerSource }, 2},
	"timeout":                   {`"3s"`, func(c *Config) any { return c.Timeout.D() }, 3 * time.Second},
	"tcp_timeout":               {`"4s"`, func(c *Config) any { return c.TCPTimeout.D() }, 4 * time.Second},
	"addr_refresh_interval":     {`"1s"`, func(c *Config) any { return c.AddrRefreshInterval.D() }, time.Second},
	"interface_acls":            {`{"lo":{"rate_limit":3}}`, func(c *Config) any { return *c.InterfaceACLs["lo"].RateLimit }, 3},
	"rewrites":                  {`[{"match":"x.test","answer":"1.2.3.4"}]`, func(c *Config) any { return c.Rewrites[0].Match }, "x.test"},
	"table_file":                {`"/nonexistent/table.bin"`, func(c *Config) any { return c.TableFile }, "/nonexistent/table.bin"},
	"feed_socket":               {`""`, func(c *Config) any { return c.FeedSocket }, ""},
}

var restartChanges = map[string]struct {
	json string
	got  func(*Config) any
}{
	"listen_addr":     {`"127.0.0.1:5353"`, func(c *Config) any { return c.ListenAddr }},
	"log_file":        {`"/nonexistent/relay.log"`, func(c *Config) any { return c.LogFile }},
	"max_packet_size": {`2048`, func(c *Config) any { return c.MaxPacketSize }},
}

func jsonKeys() []string {
	var keys []string
	rt := reflect.TypeOf(Config{})
	for i := 0; i < rt.NumField(); i++ {
		keys = append(keys, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
	}
	return keys
}

func TestConfig_EverySettingIsEitherAppliedAtOnceOrNamedAsRestartOnly(t *testing.T) {
	for _, k := range jsonKeys() {
		_, hot := hotChanges[k]
		_, restart := restartChanges[k]
		if k == "access" || k == "access_always" {
			continue
		}
		if hot == restart {
			t.Errorf("setting %q must be listed exactly once, as applied at once or as restart-only", k)
		}
		if restart != restartOnly[k] {
			t.Errorf("setting %q: the test table and restartOnly disagree", k)
		}
	}
	if len(restartOnly) != len(restartChanges) {
		t.Fatal("restartOnly names a setting the test does not know")
	}
}

func baseJSON(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(`{"upstreams":["127.0.0.1"],"allowed_interfaces":["lo"],"listen_addr":"0.0.0.0:0","max_packet_size":4096}`), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func writeCfg(t *testing.T, m map[string]json.RawMessage) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func resetReloadState(t *testing.T) {
	t.Helper()
	oldCfg, oldIfaces, oldPools := conf(), allowedIfaces.Load(), upstreamPools.Load()
	t.Cleanup(func() {
		cfgPtr.Store(oldCfg)
		allowedIfaces.Store(oldIfaces)
		for _, p := range pools() {
			found := false
			if oldPools != nil {
				for _, o := range *oldPools {
					found = found || o == p
				}
			}
			if !found {
				p.close()
			}
		}
		upstreamPools.Store(oldPools)
		setTablePath("")
		setFeedSocket(shutdownCtx, "")
	})
	if ok := reconfigureInterfaces([]string{"lo"}); !ok {
		t.Fatal("setup: no usable interface")
	}
}

func TestReload_EverySettingTakesEffectWithoutARestart(t *testing.T) {
	resetReloadState(t)
	for key, c := range hotChanges {
		t.Run(key, func(t *testing.T) {
			m := baseJSON(t)
			m[key] = json.RawMessage(c.json)
			reloadConfig(writeCfg(t, m))
			if got := c.got(conf()); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("%s: running value %v, want %v", key, got, c.want)
			}
		})
	}
}

func TestReload_RestartOnlySettingsKeepTheirRunningValue(t *testing.T) {
	resetReloadState(t)
	for key, c := range restartChanges {
		t.Run(key, func(t *testing.T) {
			before := c.got(conf())
			m := baseJSON(t)
			m[key] = json.RawMessage(c.json)
			reloadConfig(writeCfg(t, m))
			if got := c.got(conf()); !reflect.DeepEqual(got, before) {
				t.Fatalf("%s changed from %v to %v without a restart", key, before, got)
			}
		})
	}
}

func TestReload_ABadConfigurationChangesNothing(t *testing.T) {
	resetReloadState(t)
	before := conf()
	pb := pools()
	for name, body := range map[string]string{
		"not json":          `{`,
		"bad scope":         `{"upstreams":["127.0.0.1"],"allowed_interfaces":["lo"],"rate_limit_scope":"galaxy"}`,
		"no upstreams":      `{"allowed_interfaces":["lo"]}`,
		"upstream port":     `{"upstreams":["127.0.0.1:5353"],"allowed_interfaces":["lo"]}`,
		"upstream not ipv4": `{"upstreams":["::1"],"allowed_interfaces":["lo"]}`,
		"bad duration":      `{"upstreams":["127.0.0.1"],"allowed_interfaces":["lo"],"timeout":"soon"}`,
	} {
		p := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		reloadConfig(p)
		if conf() != before || !reflect.DeepEqual(pools(), pb) {
			t.Fatalf("%s: a refused reload changed the running configuration", name)
		}
	}
	reloadConfig(filepath.Join(t.TempDir(), "missing.json"))
	if conf() != before {
		t.Fatal("a missing file changed the running configuration")
	}
}

func TestReload_UpstreamPoolsAreKeptReplacedAndClosed(t *testing.T) {
	resetReloadState(t)
	m := baseJSON(t)
	m["upstreams"] = json.RawMessage(`["127.0.0.1","127.0.0.2"]`)
	reloadConfig(writeCfg(t, m))
	two := pools()
	if len(two) != 2 {
		t.Fatalf("%d pools", len(two))
	}
	m["rate_limit"] = json.RawMessage(`50`)
	reloadConfig(writeCfg(t, m))
	if got := pools(); len(got) != 2 || got[0] != two[0] || got[1] != two[1] {
		t.Fatal("pools whose address and size did not change are kept as they are")
	}
	m["upstreams"] = json.RawMessage(`["127.0.0.2"]`)
	reloadConfig(writeCfg(t, m))
	got := pools()
	if len(got) != 1 || got[0] != two[1] {
		t.Fatal("the pool of the remaining upstream is kept")
	}
	if _, _, err := two[0].clients[0].query(make([]byte, 12), 50*time.Millisecond); err == nil {
		t.Fatal("the removed pool's sockets are closed")
	}
	m["upstream_socket_pool_size"] = json.RawMessage(`4`)
	reloadConfig(writeCfg(t, m))
	if after := pools(); len(after) != 1 || after[0] == two[1] || len(after[0].clients) != 4 {
		t.Fatal("a changed pool size makes a new pool")
	}
}

func TestReload_TheOutstandingLimitFollowsTheConfiguration(t *testing.T) {
	resetReloadState(t)
	m := baseJSON(t)
	m["max_outstanding"] = json.RawMessage(`2`)
	reloadConfig(writeCfg(t, m))
	var allowed []bool
	for i := 0; i < 3; i++ {
		allowed = append(allowed, acquireOutstanding())
	}
	if !reflect.DeepEqual(allowed, []bool{true, true, false}) {
		t.Fatalf("two queries are allowed, the third is refused: %v", allowed)
	}
	m["max_outstanding"] = json.RawMessage(`3`)
	reloadConfig(writeCfg(t, m))
	if !acquireOutstanding() {
		t.Fatal("a raised limit applies at once")
	}
	for i := 0; i < 3; i++ {
		releaseOutstanding()
	}
	if outstandingQueries.Load() != 0 {
		t.Fatalf("every acquired slot was released: %d", outstandingQueries.Load())
	}
}

func TestReload_ReadersNeverSeeAHalfAppliedConfiguration(t *testing.T) {
	resetReloadState(t)
	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				c := conf()
				if c.RateBurst != c.RateLimit*2 && c.RateBurst != 0 && c.RateLimit != 0 {
					if c.RateBurst != c.RateLimit+1 {
						t.Errorf("rate limit %d with burst %d belong to no configuration", c.RateLimit, c.RateBurst)
						return
					}
				}
				if acquireOutstanding() {
					releaseOutstanding()
				}
				_ = pools()
			}
		}()
	}
	for i := 0; i < 40; i++ {
		m := baseJSON(t)
		m["rate_limit"] = json.RawMessage(`20`)
		m["rate_burst"] = json.RawMessage(`21`)
		if i%2 == 0 {
			m["rate_limit"] = json.RawMessage(`30`)
			m["rate_burst"] = json.RawMessage(`60`)
			m["upstreams"] = json.RawMessage(`["127.0.0.1","127.0.0.2"]`)
		}
		reloadConfig(writeCfg(t, m))
	}
	stop.Store(true)
	wg.Wait()
}
