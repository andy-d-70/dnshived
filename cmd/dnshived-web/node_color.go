// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"regexp"
	"strconv"
	"strings"
)

var nodeColorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func validNodeColor(s string) bool { return nodeColorRe.MatchString(s) }

// defaultNodeColors are the picker's starting values (light theme).
var defaultNodeColors = map[string]string{"1": "#d6455d", "2": "#2f9fd8", "3": "#ffffff", "P": "#7c3aed"}

// DotLabel is the character inside a node's colour dot.
func (n NodeConfig) DotLabel() string {
	if i := strings.LastIndex(n.Name, "core-"); i == 0 && len(n.Name) == len("core-1") {
		return n.Name[len("core-"):]
	}
	return "P"
}

// DotClass picks the theme-tuned default colour of the dot.
func (n NodeConfig) DotClass() string {
	switch n.DotLabel() {
	case "1":
		return "d1"
	case "2":
		return "d2"
	case "3":
		return "d3"
	}
	return "dp"
}

// ColorValue is the colour the picker starts with.
func (n NodeConfig) ColorValue() string {
	if validNodeColor(n.Color) {
		return strings.ToLower(n.Color)
	}
	return defaultNodeColors[n.DotLabel()]
}

// HasColor reports whether a custom colour is set.
func (n NodeConfig) HasColor() bool { return validNodeColor(n.Color) }

// DotStyle carries a custom colour and a readable text colour for it.
func (n NodeConfig) DotStyle() template.CSS { return nodeDotStyle(n.Color) }

func nodeDotStyle(color string) template.CSS {
	if !validNodeColor(color) {
		return ""
	}
	return template.CSS(fmt.Sprintf("--nd:%s;--nd-fg:%s", strings.ToLower(color), dotTextColor(color)))
}

func dotTextColor(color string) string {
	r, _ := strconv.ParseUint(color[1:3], 16, 8)
	g, _ := strconv.ParseUint(color[3:5], 16, 8)
	b, _ := strconv.ParseUint(color[5:7], 16, 8)
	if (299*r+587*g+114*b)/1000 > 128 {
		return "#1b1f24"
	}
	return "#ffffff"
}
