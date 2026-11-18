// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"reflect"
	"testing"

	"dnshived/internal/access"
	"dnshived/internal/config"
)

func TestWithAccess(t *testing.T) {
	a := &Agent{}
	base := config.Cluster{NodeID: "n1"}
	if got := a.withAccess(base); got.Access != nil || got.AccessListActive {
		t.Fatal("before SetAccess the cluster copy carries no list")
	}
	list := &access.Config{Mode: access.ModeEnforce}
	a.SetAccess(list, []string{"192.0.2.1"}, false)
	got := a.withAccess(base)
	if got.Access != list || got.AccessListActive {
		t.Fatalf("an inactive latch must not mark the list active: %+v", got)
	}
	if !reflect.DeepEqual(got.AccessAlways(), []string{"192.0.2.1"}) {
		t.Fatalf("the agent's always-allowed list must replace the derived one, got %v", got.AccessAlways())
	}
	a.SetAccess(list, nil, true)
	if got := a.withAccess(base); !got.AccessListActive {
		t.Fatal("an active latch must reach the renderer")
	}
}
