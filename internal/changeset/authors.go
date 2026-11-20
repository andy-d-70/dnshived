// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package changeset

import "strings"

// Mixed marks a unit that more than one author has changed.
const Mixed = "*"

// Attribute returns the journal after cand replaced base as the staged
// document. A path that still differs from live keeps its author unless this
// save changed it; a path that no longer differs from live is dropped. A save
// without an author clears the author of the paths it changed.
func Attribute(live, base, cand any, author string, prev map[string]string) map[string]string {
	pending := Changes(live, cand)
	saved := Changes(base, cand)
	out := make(map[string]string, len(pending))
	for _, p := range pending {
		if a, ok := prev[p]; ok {
			out[p] = a
		}
	}
	set := make(map[string]bool, len(pending))
	for _, p := range pending {
		set[p] = true
	}
	for _, q := range saved {
		p := owningUnit(set, q)
		if p == "" {
			continue
		}
		prior, had := out[p]
		switch {
		case author == "":
			delete(out, p)
		case p == q || !had:
			out[p] = author
		case prior != author:
			out[p] = Mixed
		}
	}
	return out
}

func owningUnit(pending map[string]bool, q string) string {
	for p := q; p != ""; {
		if pending[p] {
			return p
		}
		i := strings.LastIndex(p, "/")
		if i < 0 {
			return ""
		}
		p = p[:i]
	}
	return ""
}

// Prune keeps only the entries whose path still differs between live and cand.
func Prune(live, cand any, journal map[string]string) map[string]string {
	out := make(map[string]string, len(journal))
	for _, p := range Changes(live, cand) {
		if a, ok := journal[p]; ok {
			out[p] = a
		}
	}
	return out
}

// Mine lists the pending paths whose sole author is user.
func Mine(live, cand any, journal map[string]string, user string) []string {
	var out []string
	for _, p := range Changes(live, cand) {
		if journal[p] == user && user != "" && user != Mixed {
			out = append(out, p)
		}
	}
	return out
}

// Label turns a path into text for people: segments joined with " › ", the
// element keys without brackets.
func Label(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		p = strings.TrimSuffix(strings.TrimPrefix(p, "["), "]")
		parts[i] = labelUnescaper.Replace(p)
	}
	return strings.Join(parts, " › ")
}

var labelUnescaper = strings.NewReplacer("~1", "/", "~2", "[", "~3", "]", "~0", "~")
