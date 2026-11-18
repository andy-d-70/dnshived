// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net"
	"strings"
)

var ouiKindIcons = map[string][2]string{
	"av":      {"\U0001F50A", "Audio or video device"},
	"apple":   {"\U0001F34F", "Apple device"},
	"phone":   {"\U0001F4F1", "Phone or tablet"},
	"printer": {"\U0001F5A8", "Printer"},
	"camera":  {"\U0001F4F7", "Camera"},
	"tv":      {"\U0001F4FA", "TV or streaming box"},
	"iot":     {"\U0001F50C", "Smart device"},
	"vm":      {"\U0001F5A5", "Virtual machine"},
	"network": {"\U0001F310", "Network device"},
}

// ouiIcon guesses a client type from the manufacturer prefix of mac. A private (randomized) MAC says nothing about the device.
func ouiIcon(mac string) (icon, title string, ok bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 || hw[0]&0x02 != 0 {
		return "", "", false
	}
	const hexd = "0123456789ABCDEF"
	key := []byte{hexd[hw[0]>>4], hexd[hw[0]&15], hexd[hw[1]>>4], hexd[hw[1]&15], hexd[hw[2]>>4], hexd[hw[2]&15]}
	e, found := ouiTable[string(key)]
	if !found {
		return "", "", false
	}
	ik := ouiKindIcons[ouiKinds[e[1]]]
	return ik[0], ik[1] + " (" + ouiVendors[e[0]] + ", guessed from the MAC address)", true
}
