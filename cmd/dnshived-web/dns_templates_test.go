// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestDNSTemplates_ParseAndPassRealClusterValidation(t *testing.T) {
	for _, tpl := range []struct {
		name string
		text string
	}{
		{"ddm", dnsTemplateDDM},
		{"nmos", dnsTemplateNMOS},
		{"ndi", dnsTemplateNDI},
	} {
		t.Run(tpl.name, func(t *testing.T) {
			records, err := parseDNSRecordLines(tpl.text)
			if err != nil {
				t.Fatalf("parseDNSRecordLines: %v", err)
			}
			if len(records) == 0 {
				t.Fatalf("template produced zero records")
			}
			c := config.Cluster{
				ClusterID:        "test",
				NodeID:           "core-1",
				Role:             "worker",
				SchemaVersion:    config.CurrentSchemaVersion,
				Platform:         &config.Platform{Workers: []string{"ens19"}},
				GlobalDNSRecords: records,
			}
			result := c.ValidateExtended()
			for _, e := range result.Errors {
				if strings.Contains(e, "dns_records") || strings.Contains(e, "global_dns_records") {
					t.Errorf("template %s failed real validation: %s", tpl.name, e)
				}
			}
		})
	}
}
