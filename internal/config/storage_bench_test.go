// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"fmt"
	"path/filepath"
	"testing"
)

func bigCluster(domains, hosts int) *Cluster {
	c := splitFixture()
	c.LocalDomains = nil
	for d := 0; d < domains; d++ {
		ld := LocalDomain{Name: fmt.Sprintf("d%04d.lan", d)}
		for h := 0; h < hosts; h++ {
			ld.Records = append(ld.Records, LocalDomainHost{Host: fmt.Sprintf("h%04d", h), Type: "A", Value: fmt.Sprintf("10.%d.%d.%d", d%250, h/250, h%250)})
		}
		c.LocalDomains = append(c.LocalDomains, ld)
	}
	return c
}

func BenchmarkStorage(b *testing.B) {
	for _, size := range []struct{ d, h int }{{100, 100}, {500, 250}} {
		c := bigCluster(size.d, size.h)
		name := fmt.Sprintf("%dx%d", size.d, size.h)
		single := filepath.Join(b.TempDir(), "cluster.json")
		if err := saveSingle(single, c); err != nil {
			b.Fatal(err)
		}
		split := filepath.Join(b.TempDir(), "cluster.json")
		if err := saveSingle(split, c); err != nil {
			b.Fatal(err)
		}
		if _, err := MigrateToSplit(split); err != nil {
			b.Fatal(err)
		}
		b.Run("save-single/"+name, func(b *testing.B) {
			for b.Loop() {
				if err := saveSingle(single, c); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("save-split-one-domain-changed/"+name, func(b *testing.B) {
			i := 0
			for b.Loop() {
				i++
				c.LocalDomains[0].TTL = 60 + i%2
				if err := Save(split, c); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("save-split-nothing-changed/"+name, func(b *testing.B) {
			for b.Loop() {
				if err := Save(split, c); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("load-single/"+name, func(b *testing.B) {
			for b.Loop() {
				if _, err := Load(single); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("load-split/"+name, func(b *testing.B) {
			for b.Loop() {
				if _, err := Load(split); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
