// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"dnshived/internal/dnsfeed"
	"dnshived/internal/loglevel"
	"dnshived/internal/ownership"
)

const dnsFeedEnableFile = "/etc/dnshived/dns-feed.enable"

func dnsFeedEnabled() bool {
	_, err := os.Stat(dnsFeedEnableFile)
	return err == nil
}

// startDNSFeed serves the table feed on a unix socket until ctx ends. A stale socket file of an earlier run is replaced;
// anything else at the path is left alone and reported.
func startDNSFeed(ctx context.Context, path string, pub *dnsfeed.Publisher) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return err
	}
	if err := ownership.Dnshived(path); err != nil {
		loglevel.Warnf("[DNSFEED:ERROR] owner of %s: %v", path, err)
	}
	go func() {
		if err := pub.Serve(ctx, ln); err != nil {
			loglevel.Warnf("[DNSFEED:ERROR] %v", err)
		}
		_ = os.Remove(path)
	}()
	return nil
}
