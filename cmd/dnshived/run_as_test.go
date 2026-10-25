// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

func TestRefuseRootStart(t *testing.T) {
	found := func(string) (*user.User, error) { return &user.User{Username: serviceUser}, nil }
	missing := func(name string) (*user.User, error) { return nil, user.UnknownUserError(name) }

	if err := refuseRootStart(0, found); err == nil || !strings.Contains(err.Error(), serviceUser) {
		t.Errorf("root with service user: want refusal naming %q, got %v", serviceUser, err)
	}
	if err := refuseRootStart(0, missing); err != nil {
		t.Errorf("root without service user: want nil, got %v", err)
	}
	if err := refuseRootStart(1000, found); err != nil {
		t.Errorf("non-root: want nil, got %v", err)
	}
	if err := refuseRootStart(1000, func(string) (*user.User, error) { return nil, errors.New("unused") }); err != nil {
		t.Errorf("non-root must not depend on lookup: got %v", err)
	}
}
