asn1ber
=======

This is a forked version of the encoding/asn1 standard package from the Go
programming language. See http://golang.org for the original.

The purpose of the fork is to make changes (as and when required) in order to
remove DER-based restrictions from the code, to support SNMP and other uses of
ASN.1 that require BER encoding, but not the DER-specific restrictions.
