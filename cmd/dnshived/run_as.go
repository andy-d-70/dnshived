// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os/user"
)

const serviceUser = "dnshived"

func refuseRootStart(euid int, lookup func(string) (*user.User, error)) error {
	if euid != 0 {
		return nil
	}
	if _, err := lookup(serviceUser); err != nil {
		return nil
	}
	return fmt.Errorf("refusing to run the daemon as root: it runs as the %q user (systemctl start dnshived); files written as root would be unreadable for dnsmasq", serviceUser)
}
