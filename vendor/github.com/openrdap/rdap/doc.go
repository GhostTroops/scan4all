// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

// Package rdap implements a client for the Registration Data Access Protocol (RDAP).
//
// RDAP is a modern replacement for the text-based WHOIS (port 43) protocol. It provides registration data for domain names/IP addresses/AS numbers, and more, in a structured format.
//
// This client executes RDAP queries and returns the responses as Go values.
//
// Quick usage:
//   client := &rdap.Client{}
//   domain, err := client.QueryDomain("example.cz")
//
//   if err == nil {
//     fmt.Printf("Handle=%s Domain=%s\n", domain.Handle, domain.LDHName)
//   }
// The QueryDomain(), QueryAutnum(), and QueryIP() methods all provide full contact information, and timeout after 30s.
//
// Normal usage:
//   // Query example.cz.
//   req := &rdap.Request{
//     Type: rdap.DomainRequest,
//     Query: "example.cz",
//   }
//
//   client := &rdap.Client{}
//   resp, err := client.Do(req)
//
//   if domain, ok := resp.Object.(*rdap.Domain); ok {
//     fmt.Printf("Handle=%s Domain=%s\n", domain.Handle, domain.LDHName)
//   }
//
// As of June 2017, all five number registries (AFRINIC, ARIN, APNIC, LANIC,
// RIPE) run RDAP servers. A small number of TLDs (top level domains) support
// RDAP so far, listed on https://data.iana.org/rdap/dns.json.
//
// The RDAP protocol uses HTTP, with responses in a JSON format. A bootstrapping mechanism (http://data.iana.org/rdap/) is used to determine the server to query.
package rdap
