// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package passpolicy

import (
	"strings"
	"testing"
)

func TestClampMin(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{"zero selects the default", 0, 12},
		{"below the floor", 3, 8},
		{"at the floor", 8, 8},
		{"inside the range", 20, 20},
		{"above the ceiling", 500, 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClampMin(tt.in); got != tt.want {
				t.Errorf("ClampMin(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	long := strings.Repeat("Xk7!", 8) + "pQ"
	tests := []struct {
		name string
		pw   string
		c    Context
		want string
	}{
		{"meets the policy", "Tn4#kWz8@Lq2", Context{}, ""},
		{"too short", "Tn4#kWz8@L", Context{}, "needs at least 12 characters"},
		{"no uppercase", "tn4#kwz8@lq2", Context{}, "needs an uppercase letter"},
		{"no digit", "Tn#kWz@LqRmV", Context{}, "needs a digit"},
		{"no special character", "Tn4kWz8LqRm2", Context{}, "needs a special character"},
		{"too few different characters", "Aa1!Aa1!Aa1!", Context{}, "needs at least 5 different characters"},
		{"ascending letters", "Tn4#abcdWz8@", Context{}, "simple sequence"},
		{"descending digits", "Tn#kWz@4321Lq", Context{}, "simple sequence"},
		{"keyboard row", "Tn4#qwerWz8@", Context{}, "simple sequence"},
		{"one block repeated", "Xk7!pQ2#Xk7!pQ2#", Context{}, "is one block repeated"},
		{"contains the user name", "Tn4#jordanWz8@", Context{Names: []string{"Jordan"}}, "user name"},
		{"short names are ignored", "Tn4#abWz8@Lq2", Context{Names: []string{"ab"}}, ""},
		{"raised minimum", "Tn4#kWz8@Lq2", Context{MinLength: 16}, "needs at least 16 characters"},
		{"lowered minimum", "Tn4#kWz8", Context{MinLength: 8}, ""},
		{"minimum below the floor is raised", "Tn4#kWz", Context{MinLength: 2}, "needs at least 8 characters"},
		{"very long", strings.Repeat("a", 2000), Context{}, "longer than"},
		{"long and mixed", long, Context{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(Check(tt.pw, tt.c), "; ")
			if tt.want == "" {
				if got != "" {
					t.Errorf("unexpected problems: %s", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("problems %q do not contain %q", got, tt.want)
			}
		})
	}
}

func TestRate(t *testing.T) {
	tests := []struct {
		name      string
		pw        string
		wantLevel int
		wantMax   bool
	}{
		{"empty", "", 0, false},
		{"fails the policy, capped at weak", "correct horse battery staple", 1, true},
		{"meets the policy, 12 mixed characters", "Tn4#kWz8@Lq2", 3, false},
		{"meets the policy, 20 mixed characters", "Tn4#kWz8@Lq2Rm5%Vb7!", 4, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Rate(tt.pw, Context{})
			if tt.wantMax && r.Level > tt.wantLevel {
				t.Errorf("level %d above the cap %d", r.Level, tt.wantLevel)
			}
			if !tt.wantMax && r.Level != tt.wantLevel {
				t.Errorf("level = %d (%s), want %d", r.Level, r.Label, tt.wantLevel)
			}
			if r.Problems == nil {
				t.Error("Problems must never be nil (JSON)")
			}
		})
	}
}

func TestNamesFor(t *testing.T) {
	got := strings.Join(NamesFor("ops", "ops.team@example.org", "core-1.example.org"), ",")
	if got != "ops,ops.team,core-1" {
		t.Errorf("NamesFor = %q", got)
	}
	if got := NamesFor("", "", ""); len(got) != 0 {
		t.Errorf("empty input gave %v", got)
	}
}

func TestTextBar(t *testing.T) {
	if got := (Rating{Level: 2, Label: "fair"}).TextBar(); got != "[###--] fair" {
		t.Errorf("TextBar = %q", got)
	}
	if got := (Rating{Level: 0, Label: "very weak"}).TextBar(); got != "[#----] very weak" {
		t.Errorf("TextBar = %q", got)
	}
}

func TestCheckToken(t *testing.T) {
	good := "k8Zp2QvN7xLw4RtY9bGd3HsF6mCj1VeA"
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"random token", good, ""},
		{"hex token", "9f2c41d8b7a3e605f1d4c8a29b7e3f60", ""},
		{"too short", "k8Zp2QvN7xLw4RtY9bGd", "at least 32 characters"},
		{"whitespace inside", "k8Zp2QvN7xLw4RtY 9bGd3HsF6mCj1VeAy", "whitespace"},
		{"few different characters", strings.Repeat("ab", 20) + "xy", "at least 10 different"},
		{"simple sequence", "k8Zp2QvN7xLw4RtY9bGd3HsF6mabcdVeA", "simple sequence"},
		{"one block repeated", strings.Repeat("k8Zp2QvN7xLw4RtY", 2), "one block repeated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Join(CheckToken(tt.token))
			if tt.want == "" && got != "" {
				t.Errorf("unexpected problems: %s", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("problems %q do not contain %q", got, tt.want)
			}
		})
	}
}
