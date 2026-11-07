// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package activation decides whether a cluster-wide feature may switch on.
// A feature that changes what is stored on every node switches on only when
// every configured core member runs at least a given version.
package activation

import (
	"sort"
	"strconv"
	"strings"
)

// FeatureVersion is the version every core member must run before the
// features that change the stored format switch on. Nothing consults it yet.
const FeatureVersion = "0.9.9.0"

// OutageRulesVersion is the version every core member must run before the
// outage rules (write quorum, stale-base refusal, config verification,
// membership epoch) are enforced. It is the first lab build that has them;
// the release is higher.
const OutageRulesVersion = "0.9.8.9~dev-3"

// Member is one configured core member as seen by the node asking.
type Member struct {
	Name      string `json:"name"`
	Role      string `json:"role,omitempty"`
	Version   string `json:"version,omitempty"`
	Reachable bool   `json:"reachable"`
}

// Blocker is a member that keeps the feature off, with the reason.
type Blocker struct {
	Name    string `json:"name"`
	Role    string `json:"role,omitempty"`
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason"`
}

// Result is the outcome of Evaluate.
type Result struct {
	Required string    `json:"required"`
	Active   bool      `json:"active"`
	Members  int       `json:"members"`
	Blocking []Blocker `json:"blocking,omitempty"`
}

type parsed struct {
	nums []int
	pre  string
}

func parse(v string) (parsed, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return parsed{}, false
	}
	num := v
	var pre string
	if i := strings.IndexAny(v, "~-"); i >= 0 {
		num, pre = v[:i], v[i+1:]
		if pre == "" {
			pre = "-"
		}
		if _, err := strconv.Atoi(pre); err == nil {
			pre = "dev-" + pre
		}
	}
	var p parsed
	p.pre = pre
	for _, part := range strings.Split(num, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return parsed{}, false
		}
		p.nums = append(p.nums, n)
	}
	return p, true
}

// Compare orders two version strings: -1, 0 or 1. Build metadata after a "+"
// is ignored. A pre-release suffix ("0.9.9.0~dev-3", a binary's "0.9.9.0-3",
// "0.9.7-dev") sorts before the same number without one.
// ok is false when either string is not a version.
func Compare(a, b string) (cmp int, ok bool) {
	pa, oka := parse(a)
	pb, okb := parse(b)
	if !oka || !okb {
		return 0, false
	}
	n := max(len(pa.nums), len(pb.nums))
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa.nums) {
			x = pa.nums[i]
		}
		if i < len(pb.nums) {
			y = pb.nums[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case pa.pre == "" && pb.pre == "":
		return 0, true
	case pa.pre == "":
		return 1, true
	case pb.pre == "":
		return -1, true
	}
	return comparePre(pa.pre, pb.pre), true
}

func comparePre(a, b string) int {
	la, na := preNumber(a)
	lb, nb := preNumber(b)
	if la != lb {
		return strings.Compare(la, lb)
	}
	switch {
	case na < nb:
		return -1
	case na > nb:
		return 1
	}
	return 0
}

func preNumber(s string) (label string, n int) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	n, _ = strconv.Atoi(s[i:])
	return s[:i], n
}

// Evaluate reports whether every member runs at least required. No members,
// an unreachable member and a version that cannot be read all keep it off.
func Evaluate(required string, members []Member) Result {
	res := Result{Required: required, Members: len(members)}
	for _, m := range members {
		switch {
		case !m.Reachable:
			res.Blocking = append(res.Blocking, Blocker{Name: m.Name, Role: m.Role, Reason: "not reachable"})
		case m.Version == "":
			res.Blocking = append(res.Blocking, Blocker{Name: m.Name, Role: m.Role, Reason: "does not report a version"})
		default:
			c, ok := Compare(m.Version, required)
			switch {
			case !ok:
				res.Blocking = append(res.Blocking, Blocker{Name: m.Name, Role: m.Role, Version: m.Version, Reason: "version not readable"})
			case c < 0:
				res.Blocking = append(res.Blocking, Blocker{Name: m.Name, Role: m.Role, Version: m.Version, Reason: "older than " + required})
			}
		}
	}
	sort.Slice(res.Blocking, func(i, j int) bool { return res.Blocking[i].Name < res.Blocking[j].Name })
	res.Active = len(members) > 0 && len(res.Blocking) == 0
	return res
}
