// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package timehealth

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestStatusFromTimex(t *testing.T) {
	cases := []struct {
		name   string
		tx     syscall.Timex
		synced bool
		offset time.Duration
	}{
		{"synced, microsecond offset", syscall.Timex{Maxerror: 250000, Offset: 1500}, true, 1500 * time.Microsecond},
		{"synced, nanosecond offset", syscall.Timex{Maxerror: 1000, Offset: -2000, Status: staNano}, true, -2000 * time.Nanosecond},
		{"unsynced at 16s max error", syscall.Timex{Maxerror: 16000000}, false, 0},
	}
	for _, c := range cases {
		st := statusFromTimex(c.tx)
		if !st.Available || st.Synchronized != c.synced || st.Offset != c.offset {
			t.Errorf("%s: got %+v, want synced=%v offset=%v", c.name, st, c.synced, c.offset)
		}
	}
}

func TestDoCheck_AdjtimexFailureIsUnavailable(t *testing.T) {
	orig := adjtimex
	adjtimex = func(*syscall.Timex) error { return errors.New("EPERM") }
	t.Cleanup(func() { adjtimex = orig })
	if st := doCheck(); st.Available {
		t.Errorf("doCheck after adjtimex failure = %+v, want Available=false", st)
	}
}

func TestDoCheck_RealKernel(t *testing.T) {
	st := doCheck()
	if !st.Available {
		t.Skip("adjtimex not readable here")
	}
	t.Logf("kernel clock: synced=%v offset=%v", st.Synchronized, st.Offset)
}
