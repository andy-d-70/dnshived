// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"strings"
	"testing"
)

func TestVRRPPassword_EightCharactersStableAndPerInstance(t *testing.T) {
	a := vrrpPassword("psk-one", "scope:office:vrid:2")
	if len(a) != 8 {
		t.Fatalf("password %q has %d characters, want 8", a, len(a))
	}
	if a != vrrpPassword("psk-one", "scope:office:vrid:2") {
		t.Fatal("password differs between calls with the same inputs")
	}
	if a == vrrpPassword("psk-one", "scope:test-21:vrid:21") {
		t.Fatal("two instances share a password")
	}
	if a == vrrpPassword("psk-two", "scope:office:vrid:2") {
		t.Fatal("password does not depend on the PSK")
	}
	if strings.Contains(a, "psk-one") {
		t.Fatal("password contains the PSK")
	}
}

func TestKeepalivedTemplate_CarriesAuthenticationBlock(t *testing.T) {
	var b strings.Builder
	err := keepalivedAllTmpl.Execute(&b, []keepalivedInstanceData{{
		Scope: "office", Interface: "ens19.2", VRRPID: 2, Priority: 100, AdvertInt: "1",
		VIP: "192.168.2.254/24", AuthPass: "AbCd1234",
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"authentication {", "auth_type PASS", "auth_pass AbCd1234"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered config lacks %q:\n%s", want, out)
		}
	}
}
