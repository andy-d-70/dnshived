// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

const dnsTemplateDDM = "A|ddm.fake.lan|203.0.113.10\n" +
	"SRV|default._dante-ddm-c._tcp.ddm.fake.lan|ddm.fake.lan|8443|0|0\n" +
	"TXT|default._dante-ddm-c._tcp.ddm.fake.lan|-\n" +
	"SRV|default._dante-ddm-d._udp.ddm.fake.lan|ddm.fake.lan|8000|0|0\n" +
	"TXT|default._dante-ddm-d._udp.ddm.fake.lan|-"

const dnsTemplateNMOS = "A|rds1.nmos.fake.lan|203.0.113.20\n" +
	"SRV|reg-api-1._nmos-register._tcp.nmos.fake.lan|rds1.nmos.fake.lan|80|0|0\n" +
	"TXT|reg-api-1._nmos-register._tcp.nmos.fake.lan|api_ver=v1.3\n" +
	"SRV|qry-api-1._nmos-query._tcp.nmos.fake.lan|rds1.nmos.fake.lan|80|0|0\n" +
	"TXT|qry-api-1._nmos-query._tcp.nmos.fake.lan|api_ver=v1.3"

const dnsTemplateNDI = "A|ndi-discovery.ndi.fake.lan|203.0.113.30\n" +
	"SRV|_ndi._tcp.ndi.fake.lan|ndi-discovery.ndi.fake.lan|5959|0|0"
