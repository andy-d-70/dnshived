// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package passpolicy checks and rates web-UI passwords.
package passpolicy

import (
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	DefaultMinLength = 12
	FloorMinLength   = 8
	CeilingMinLength = 64

	maxLength     = 1024
	minDistinct   = 5
	minSequence   = 4
	minNameLength = 3
)

// Context is what a password is judged against.
type Context struct {
	// MinLength 0 selects DefaultMinLength; other values are clamped to the floor and ceiling.
	MinLength int
	// Names must not appear inside the password: user name, mail local part, host name.
	Names []string
}

// ClampMin returns the effective minimum length for a configured value.
func ClampMin(n int) int {
	switch {
	case n == 0:
		return DefaultMinLength
	case n < FloorMinLength:
		return FloorMinLength
	case n > CeilingMinLength:
		return CeilingMinLength
	}
	return n
}

// NamesFor collects the strings a password for this user must not contain.
func NamesFor(userName, email, host string) []string {
	var out []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	add(userName)
	if at := strings.IndexByte(email, '@'); at > 0 {
		add(email[:at])
	}
	if dot := strings.IndexByte(host, '.'); dot > 0 {
		host = host[:dot]
	}
	add(host)
	return out
}

var keyboardRows = []string{"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"}

// Check returns what the password lacks; an empty result means it meets the policy.
func Check(pw string, c Context) []string {
	var problems []string
	runes := []rune(pw)
	if len(runes) > maxLength {
		return []string{fmt.Sprintf("is longer than %d characters", maxLength)}
	}
	if min := ClampMin(c.MinLength); len(runes) < min {
		problems = append(problems, fmt.Sprintf("needs at least %d characters", min))
	}
	var upper, digit, special bool
	distinct := map[rune]struct{}{}
	for _, r := range runes {
		distinct[r] = struct{}{}
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLetter(r):
		case unicode.IsDigit(r):
			digit = true
		default:
			special = true
		}
	}
	if !upper {
		problems = append(problems, "needs an uppercase letter")
	}
	if !digit {
		problems = append(problems, "needs a digit")
	}
	if !special {
		problems = append(problems, "needs a special character")
	}
	if len(distinct) < minDistinct {
		problems = append(problems, fmt.Sprintf("needs at least %d different characters", minDistinct))
	}
	lower := strings.ToLower(pw)
	if hasSequence(lower) {
		problems = append(problems, "contains a simple sequence such as abcd, 1234 or qwer")
	}
	if isRepeatedBlock(runes) {
		problems = append(problems, "is one block repeated")
	}
	for _, name := range c.Names {
		name = strings.ToLower(strings.TrimSpace(name))
		if utf8.RuneCountInString(name) >= minNameLength && strings.Contains(lower, name) {
			problems = append(problems, "contains the user name, mail address or host name")
			break
		}
	}
	return problems
}

func kind(r rune) int {
	switch {
	case r >= 'a' && r <= 'z':
		return 1
	case r >= '0' && r <= '9':
		return 2
	}
	return 0
}

func hasSequence(lower string) bool {
	rs := []rune(lower)
	run, dir := 1, 0
	for i := 1; i < len(rs); i++ {
		d := int(rs[i]) - int(rs[i-1])
		if (d == 1 || d == -1) && kind(rs[i]) != 0 && kind(rs[i]) == kind(rs[i-1]) {
			if d == dir {
				run++
			} else {
				run, dir = 2, d
			}
			if run >= minSequence {
				return true
			}
		} else {
			run, dir = 1, 0
		}
	}
	for _, row := range keyboardRows {
		rev := reverse(row)
		for i := 0; i+minSequence <= len(row); i++ {
			if strings.Contains(lower, row[i:i+minSequence]) || strings.Contains(lower, rev[i:i+minSequence]) {
				return true
			}
		}
	}
	return false
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func isRepeatedBlock(rs []rune) bool {
	n := len(rs)
	for b := 1; b <= n/2; b++ {
		if n%b != 0 {
			continue
		}
		same := true
		for i := b; i < n; i++ {
			if rs[i] != rs[i-b] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// Rating is a password's strength for display.
type Rating struct {
	Level    int // 0 (very weak) to 4 (strong)
	Label    string
	Problems []string
}

var labels = [...]string{"very weak", "weak", "fair", "good", "strong"}

// Rate judges length and variety only. A password that fails Check never rates above "weak".
func Rate(pw string, c Context) Rating {
	problems := Check(pw, c)
	if problems == nil {
		problems = []string{}
	}
	level := 0
	switch bits := entropyBits(pw); {
	case bits >= 80:
		level = 4
	case bits >= 65:
		level = 3
	case bits >= 50:
		level = 2
	case bits >= 35:
		level = 1
	}
	if len(problems) > 0 && level > 1 {
		level = 1
	}
	return Rating{Level: level, Label: labels[level], Problems: problems}
}

func entropyBits(pw string) float64 {
	var lower, upper, digit, other bool
	distinct := map[rune]struct{}{}
	n := 0
	for _, r := range pw {
		n++
		distinct[r] = struct{}{}
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	pool := 0
	for _, in := range []struct {
		on   bool
		size int
	}{{lower, 26}, {upper, 26}, {digit, 10}, {other, 33}} {
		if in.on {
			pool += in.size
		}
	}
	if pool == 0 {
		return 0
	}
	effective := float64(len(distinct)) + 0.25*float64(n-len(distinct))
	return effective * math.Log2(float64(pool))
}

// TextBar renders the rating for a terminal, e.g. "[###--] fair".
func (r Rating) TextBar() string {
	return "[" + strings.Repeat("#", r.Level+1) + strings.Repeat("-", 4-r.Level) + "] " + r.Label
}

// ProblemText joins the unmet requirements for a message.
func (r Rating) ProblemText() string {
	return strings.Join(r.Problems, ", ")
}

// Join joins unmet requirements for a message.
func Join(problems []string) string {
	return strings.Join(problems, ", ")
}

const minTokenLength = 32

// CheckToken returns what a typed API token lacks. Tokens are secrets for programs, so only length,
// variety and obvious patterns matter, not character classes.
func CheckToken(token string) []string {
	var problems []string
	runes := []rune(token)
	if len(runes) < minTokenLength {
		problems = append(problems, fmt.Sprintf("needs at least %d characters", minTokenLength))
	}
	distinct := map[rune]struct{}{}
	for _, r := range runes {
		distinct[r] = struct{}{}
		if unicode.IsSpace(r) {
			problems = append(problems, "must not contain whitespace")
			break
		}
	}
	if len(distinct) < 10 {
		problems = append(problems, "needs at least 10 different characters")
	}
	if hasSequence(strings.ToLower(token)) {
		problems = append(problems, "contains a simple sequence such as abcd, 1234 or qwer")
	}
	if isRepeatedBlock(runes) {
		problems = append(problems, "is one block repeated")
	}
	return problems
}
