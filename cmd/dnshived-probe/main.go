// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"dnshived/internal/auth"
	"dnshived/internal/eventlog"
	"dnshived/internal/tlspin"
)

var version = "0.9.7-dev"

func main() {
	cfgPath := flag.String("config", "/etc/dnshived/probe.json", "dnshived-probe config path")
	showVersion := flag.Bool("version", false, "print version and exit")
	bootstrapAddr := flag.String("bootstrap-addr", ":9444",
		"listen address for bootstrap mode — only used when no config file exists yet")
	bootstrapOTPPath := flag.String("bootstrap-otp-path", defaultProbeBootstrapOTPPath,
		"where bootstrap mode persists its join code — production deploys never need this override")

	once := flag.Bool("once", false, "run a single ad-hoc DHCP/DNS probe directly against -iface and exit — no config file, no cluster needed (see -iface, -dhcp-wait, -dns-name, -dns-target, -json)")
	iface := flag.String("iface", "", "(with -once) VLAN sub-interface to test directly, e.g. ens19.111")
	dhcpWait := flag.Duration("dhcp-wait", 5*time.Second, "(with -once) how long to listen for DHCP offers")
	dnsName := flag.String("dns-name", "", "(with -once) DNS name to query — DNS check skipped if unset")
	dnsType := flag.String("dns-type", "A", "(with -once) DNS record type to query: A, AAAA, CNAME, TXT, SRV, PTR, MX, NAPTR, CAA, or a bare numeric RR type (for RAW/dns-rr records)")
	dnsTarget := flag.String("dns-target", "", "(with -once) IP address to send the DNS query to — required if -dns-name is set")
	asJSON := flag.Bool("json", false, "(with -once) machine-readable JSON output on stdout, in addition to the human-readable report")
	fullWait := flag.Bool("full-wait", false, "(with -once) listen out the full -dhcp-wait window for a real dual-active check, instead of stopping at the first offer (the default, for fast feedback)")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-probe", version)
		os.Exit(0)
	}

	if *once {
		runManualProbe(*iface, *dhcpWait, *dnsName, *dnsType, *dnsTarget, *asJSON, *fullWait)
		return
	}

	cfg, err := loadProbeConfig(*cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			runProbeBootstrapMode(*cfgPath, *bootstrapAddr, *bootstrapOTPPath)
		}
		log.Fatalf("config: %v", err)
	}

	log.Printf("dnshived-probe %s starting — trunk_parent=%s, %d cluster node(s), probe every %dms",
		version, cfg.TrunkParent, len(cfg.ClusterNodes), cfg.probeInterval())
	if cfg.ClusterCertPEM != "" {
		if err := tlspin.SetPEM([]byte(cfg.ClusterCertPEM)); err != nil {
			log.Fatalf("config: cluster_cert_pem: %v", err)
		}
	}

	store := newResultStore()
	tracker := newProbeLogTracker(newProbeFailureLog(cfg.EventLogPath))
	incarnations := newIncarnationTracker()
	debounce := newOwnershipDebounce()
	events := eventlog.New(2000, "probe")
	authMw := auth.New(cfg.APITokens)
	startedAt := time.Now()
	if err := startAPIServer(cfg, *cfgPath, store, tracker, events, debounce, startedAt, authMw); err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("[INIT] API listening on %s", cfg.ListenAddr)

	waitForConvergence(cfg)

	runProbeSweep(cfg, store, tracker, events, incarnations, debounce)

	go func() {
		scopeTicker := time.NewTicker(time.Duration(cfg.probeInterval()) * time.Millisecond)
		sigs := newScopeSigTracker()
		for range scopeTicker.C {
			// A scope whose probe config changed (re-enabled, moved) is
			// probed right away, off the slow sweep's schedule.
			for _, scope := range refreshScopeSetTracking(cfg, store, tracker, sigs) {
				go func(scope string) {
					if _, _, err := probeScopeNow(cfg, store, tracker, events, debounce, scope); err != nil {
						log.Printf("[PROBE:CONFIG] immediate re-probe of %s: %v", scope, err)
					}
				}(scope)
			}
		}
	}()

	ticker := time.NewTicker(time.Duration(cfg.probeInterval()) * time.Millisecond)
	for range ticker.C {
		runProbeSweep(cfg, store, tracker, events, incarnations, debounce)
	}
}
