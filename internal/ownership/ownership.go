// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package ownership gives files dnshived writes to the dnshived service account.
package ownership

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Dnshived makes the dnshived user and group the owner of path. A root writer would otherwise leave the file
// root-owned, and the daemon could not replace it later.
func Dnshived(path string) error {
	u, err := user.Lookup("dnshived")
	if err != nil {
		return fmt.Errorf("lookup dnshived user: %w", err)
	}
	g, err := user.LookupGroup("dnshived")
	if err != nil {
		return fmt.Errorf("lookup dnshived group: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse dnshived uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parse dnshived group gid %q: %w", g.Gid, err)
	}
	return os.Chown(path, uid, gid)
}
