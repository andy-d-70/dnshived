// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

//go:build !labprofile

// Lab-only profiling tool; see labprofile_on.go. In every normal build this file
// is compiled instead and does nothing.
package main

const (
	labEnabled    = false
	labMarker     = ""
	labEnableFile = ""
)

func labVersionSuffix() string { return "" }

func labStart(dir func() string) {}
