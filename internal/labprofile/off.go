// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

//go:build !labprofile

// Package labprofile is a lab-only profiling tool; see lab.go. In every
// normal build this file is compiled instead and does nothing.
package labprofile

const (
	Enabled    = false
	Marker     = ""
	EnableFile = ""
)

func VersionSuffix() string { return "" }

func Start(dir func() string) {}
