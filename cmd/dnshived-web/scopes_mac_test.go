// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestChangeReservationMAC(t *testing.T) {
	sc := config.ScopeConfig{Reservations: []config.Reservation{
		{MAC: "aa:bb:cc:00:00:01", IP: "10.0.0.50", Hostname: "nas", Names: []string{"files"}},
		{MAC: "aa:bb:cc:00:00:02", IP: "10.0.0.51", ID: "r-keep"},
	}}
	got, err := changeReservationMAC(sc, "AA:BB:CC:00:00:01", "AA-BB-CC-00-00-99")
	if err != nil {
		t.Fatal(err)
	}
	r := got[0]
	if r.MAC != "aa:bb:cc:00:00:99" || r.IP != "10.0.0.50" || r.Hostname != "nas" || len(r.Names) != 1 || !strings.HasPrefix(r.ID, "r-") {
		t.Errorf("the reservation keeps everything but the MAC and gains an id: %+v", r)
	}
	if sc.Reservations[0].MAC != "aa:bb:cc:00:00:01" || sc.Reservations[0].ID != "" {
		t.Error("the stored scope must not be modified")
	}
	if got[1].ID != "r-keep" {
		t.Error("other reservations stay as they are")
	}
	for name, args := range map[string][2]string{
		"taken":   {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"},
		"invalid": {"aa:bb:cc:00:00:01", "nope"},
		"unknown": {"aa:bb:cc:00:00:77", "aa:bb:cc:00:00:78"},
	} {
		if _, err := changeReservationMAC(sc, args[0], args[1]); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}
