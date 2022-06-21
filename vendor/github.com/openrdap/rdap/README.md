<img src="https://www.openrdap.org/public/img/logo.png">

OpenRDAP is an command line [RDAP](https://datatracker.ietf.org/wg/weirds/documents/) client implementation in Go.
[![Build Status](https://travis-ci.org/openrdap/rdap.svg?branch=master)](https://travis-ci.org/openrdap/rdap)

https://www.openrdap.org - homepage

https://www.openrdap.org/demo - live demo

## Features
* Command line RDAP client
* Query types supported:
    * ip
    * domain
    * autnum
    * nameserver
    * entity
    * help
    * url
    * domain-search
    * domain-search-by-nameserver
    * domain-search-by-nameserver-ip
    * nameserver-search
    * nameserver-search-by-ip
    * entity-search
    * entity-search-by-handle
* Query bootstrapping (automatic RDAP server URL detection for ip/domain/autnum/(experimental) entity queries)
* Bootstrap cache (optional, uses ~/.openrdap by default)
* X.509 client authentication
* Output formats: text, JSON, WHOIS style
* Experimental [object tagging](https://datatracker.ietf.org/doc/draft-ietf-regext-rdap-object-tag/) support

## Installation

This program uses Go. The Go compiler is available from https://golang.org/.

To install:

    go get -u github.com/openrdap/rdap/cmd/rdap

This will install the "rdap" binary in your $GOPATH/go/bin directory. Try running:

    ~/go/bin/rdap google.com

## Usage

| Query type                | Usage                                                                    |
| ---                       | ---                                                                      |
| Domain (.com)             | rdap -v example.com                                                      |
| Network                   | rdap -v 2001:db8::                                                       |
| Autnum                    | rdap -v AS15169                                                          |
| Nameserver                | rdap -v -t nameserver -s https://rdap.verisign.com/com/v1 ns1.google.com |
| Help                      | rdap -v -t help -s https://rdap.verisign.com/com/v1                      |
| Domain Search             | rdap -v -t domain-search -s $SERVER_URL example*.gtld                    |
| Domain Search (by NS)     | rdap -v -t domain-search-by-nameserver -s $SERVER_URL ns1.example.gtld   |
| Domain Search (by NS IP)  | rdap -v -t domain-search-by-nameserver-ip -s $SERVER_URL 192.0.2.0       |
| Nameserver Search         | rdap -v -t nameserver-search -s $SERVER_URL ns1.example.gtld             |
| Nameserver Search (by IP) | rdap -v -t nameserver-search-by-ip -s $SERVER_URL 192.0.2.0              |
| Entity Search             | rdap -v -t entity-search -s $SERVER_URL ENTITY-TAG                       |
| Entity Search (by handle) | rdap -v -t entity-search-by-handle -s $SERVER_URL ENTITY-TAG             |

See https://www.openrdap.org/docs.

## Go docs
[![godoc](https://godoc.org/github.com/openrdap/rdap?status.png)](https://godoc.org/github.com/openrdap/rdap)

## Requires
Go 1.7+

## Links
- Wikipedia - [Registration Data Access Protocol](https://en.wikipedia.org/wiki/Registration_Data_Access_Protocol)
- [ICANN RDAP pilot](https://www.icann.org/rdap)

- [OpenRDAP](https://www.openrdap.org)

- https://data.iana.org/rdap/ - Official IANA bootstrap information
- https://test.rdap.net/rdap/ - Test alternate bootstrap service with more experimental RDAP servers

- [RFC 7480 HTTP Usage in the Registration Data Access Protocol (RDAP)](https://tools.ietf.org/html/rfc7480)
- [RFC 7481 Security Services for the Registration Data Access Protocol (RDAP)](https://tools.ietf.org/html/rfc7481)
- [RFC 7482 Registration Data Access Protocol (RDAP) Query Format](https://tools.ietf.org/html/rfc7482)
- [RFC 7483 JSON Responses for the Registration Data Access Protocol (RDAP)](https://tools.ietf.org/html/rfc7483)
- [RFC 7484 Finding the Authoritative Registration Data (RDAP) Service](https://tools.ietf.org/html/rfc7484)

