package main

import (
	"os"
	"testing"
)

// TestMain makes the real re-exec and every helper unit action
// unreachable for the whole test binary.
func TestMain(m *testing.M) {
	reExecFunc = func() {}
	bootstrapUnitFunc = func(string, string) error { return nil }
	stopUnitFunc = func(string) error { return nil }
	finishDecommissionFunc = func() error { return nil }
	resetHelperStateFunc = func() error { return nil }
	os.Exit(m.Run())
}
