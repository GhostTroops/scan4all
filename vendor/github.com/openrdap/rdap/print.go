// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Printer formats RDAP response objects as human readable text, and writes them
// to an io.Writer.
//
// The format resembles a WHOIS response.
type Printer struct {
	// Output io.Writer.
	//
	// Defaults to os.Stdout.
	Writer io.Writer

	// RDAP responses typically consist of a nested set of objects,
	// these are represented using indentation.

	// Character to ident responses with.
	//
	// Defaults to ' ' (space character).
	IndentChar rune

	// Number of characters per indentation.
	//
	// Defaults to 2.
	IndentSize uint

	// OmitNotices prevents RDAP Notices from being printed.
	OmitNotices bool

	// OmitNotices prevents RDAP Remarks from being printed.
	OmitRemarks bool

	// BriefOutput shortens the output by omitting various objects. These are:
	//
	// Conformance, Notices, Remarks, Events, Port43, Variants, SecureDNS.
	BriefOutput bool

	// BriefLinks causes Link objects to be printed as a single line (the link),
	// rather than as a multi-line object.
	BriefLinks bool
}

func (p *Printer) Print(obj RDAPObject) {
	if p.Writer == nil {
		p.Writer = os.Stdout
	}

	if p.IndentSize == 0 {
		p.IndentSize = 2
	}

	if p.IndentChar == '\000' {
		p.IndentChar = ' '
	}

	p.printObject(obj, 0)
}

func (p *Printer) printObject(obj RDAPObject, indentLevel uint) {
	if obj == nil {
		return
	}

	switch v := obj.(type) {
	case *Domain:
		p.printDomain(v, indentLevel)
	case *Entity:
		p.printEntity(v, indentLevel)
	case *Nameserver:
		p.printNameserver(v, indentLevel)
	case *Autnum:
		p.printAutnum(v, indentLevel)
	case *IPNetwork:
		p.printIPNetwork(v, indentLevel)
	case *Help:
		p.printHelp(v, indentLevel)
	case *Error:
		p.printError(v, indentLevel)
	case *DomainSearchResults:
		p.printDomainSearchResults(v, indentLevel)
	case *EntitySearchResults:
		p.printEntitySearchResults(v, indentLevel)
	case *NameserverSearchResults:
		p.printNameserverSearchResults(v, indentLevel)
	}
}

func (p *Printer) printNameserverSearchResults(sr *NameserverSearchResults, indentLevel uint) {
	p.printHeading("Nameserver Search Results", indentLevel)
	indentLevel++

	if !p.BriefOutput {
		for _, c := range sr.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range sr.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	for _, n := range sr.Nameservers {
		p.printNameserver(&n, indentLevel)
	}

	p.printUnknowns(sr.DecodeData, indentLevel)
}

func (p *Printer) printEntitySearchResults(sr *EntitySearchResults, indentLevel uint) {
	p.printHeading("Entity Search Results", indentLevel)
	indentLevel++

	if !p.BriefOutput {
		for _, c := range sr.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range sr.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	for _, e := range sr.Entities {
		p.printEntity(&e, indentLevel)
	}

	p.printUnknowns(sr.DecodeData, indentLevel)
}

func (p *Printer) printDomainSearchResults(sr *DomainSearchResults, indentLevel uint) {
	p.printHeading("Domain Search Results", indentLevel)
	indentLevel++

	if !p.BriefOutput {
		for _, c := range sr.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range sr.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	for _, d := range sr.Domains {
		p.printDomain(&d, indentLevel)
	}

	p.printUnknowns(sr.DecodeData, indentLevel)
}

func (p *Printer) printError(e *Error, indentLevel uint) {
	p.printHeading("Error", indentLevel)
	indentLevel++

	if !p.BriefOutput {
		for _, c := range e.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range e.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	if e.ErrorCode != nil {
		p.printValue("Error Code",
			strconv.FormatUint(uint64(*e.ErrorCode), 10),
			indentLevel)
	}

	p.printValue("Title", e.Title, indentLevel)

	for _, d := range e.Description {
		p.printValue("Description", d, indentLevel)
	}

	p.printUnknowns(e.DecodeData, indentLevel)
}

func (p *Printer) printHelp(h *Help, indentLevel uint) {
	p.printHeading("Help", indentLevel)
	indentLevel++

	if !p.BriefOutput {
		for _, c := range h.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range h.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	p.printUnknowns(h.DecodeData, indentLevel)
}

func (p *Printer) printDomain(d *Domain, indentLevel uint) {
	p.printHeading("Domain", indentLevel)
	indentLevel++

	p.printValue("Domain Name", d.LDHName, indentLevel)
	p.printValue("Domain Name (Unicode)", d.UnicodeName, indentLevel)
	p.printValue("Handle", d.Handle, indentLevel)

	for _, s := range d.Status {
		p.printValue("Status", s, indentLevel)
	}

	if !p.BriefOutput {
		p.printValue("Port43", d.Port43, indentLevel)
	}

	for _, pid := range d.PublicIDs {
		p.printPublicID(pid, indentLevel)
	}

	if !p.BriefOutput {
		for _, c := range d.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range d.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitRemarks {
		for _, r := range d.Remarks {
			p.printRemark(r, indentLevel)
		}
	}

	for _, l := range d.Links {
		p.printLink(l, indentLevel)
	}

	if !p.BriefOutput {
		for _, e := range d.Events {
			p.printEvent(e, indentLevel, false)
		}

		for _, v := range d.Variants {
			p.printVariant(v, indentLevel)
		}

		if d.SecureDNS != nil {
			p.printSecureDNS(d.SecureDNS, indentLevel)
		}
	}

	for _, e := range d.Entities {
		p.printEntity(&e, indentLevel)
	}

	for _, n := range d.Nameservers {
		p.printNameserver(&n, indentLevel)
	}

	if d.Network != nil {
		p.printIPNetwork(d.Network, indentLevel)
	}

	p.printUnknowns(d.DecodeData, indentLevel)
}

func (p *Printer) printAutnum(a *Autnum, indentLevel uint) {
	p.printHeading("Autnum", indentLevel)

	indentLevel++

	p.printValue("Handle", a.Handle, indentLevel)
	p.printValue("Name", a.Name, indentLevel)
	p.printValue("Type", a.Type, indentLevel)

	for _, s := range a.Status {
		p.printValue("Status", s, indentLevel)
	}

	p.printValue("IP Version", a.IPVersion, indentLevel)
	p.printValue("Country", a.Country, indentLevel)

	if a.StartAutnum != nil {
		p.printValue("StartAutnum",
			strconv.FormatUint(uint64(*a.StartAutnum), 10),
			indentLevel)
	}

	if a.EndAutnum != nil {
		p.printValue("EndAutnum",
			strconv.FormatUint(uint64(*a.EndAutnum), 10),
			indentLevel)
	}

	if !p.BriefOutput {
		for _, c := range a.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput {
		p.printValue("Port43", a.Port43, indentLevel)
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range a.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitRemarks {
		for _, r := range a.Remarks {
			p.printRemark(r, indentLevel)
		}
	}

	for _, l := range a.Links {
		p.printLink(l, indentLevel)
	}

	if !p.BriefOutput {
		for _, e := range a.Events {
			p.printEvent(e, indentLevel, false)
		}
	}

	for _, e := range a.Entities {
		p.printEntity(&e, indentLevel)
	}

	p.printUnknowns(a.DecodeData, indentLevel)
}

func (p *Printer) printNameserver(n *Nameserver, indentLevel uint) {
	p.printHeading("Nameserver", indentLevel)

	indentLevel++

	p.printValue("Nameserver", n.LDHName, indentLevel)
	p.printValue("Nameserver (Unicode)", n.UnicodeName, indentLevel)
	p.printValue("Handle", n.Handle, indentLevel)

	for _, s := range n.Status {
		p.printValue("Status", s, indentLevel)
	}

	if !p.BriefOutput {
		p.printValue("Port43", n.Port43, indentLevel)
	}

	if !p.BriefOutput {
		for _, c := range n.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range n.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitRemarks {
		for _, r := range n.Remarks {
			p.printRemark(r, indentLevel)
		}
	}

	for _, l := range n.Links {
		p.printLink(l, indentLevel)
	}

	if !p.BriefOutput {
		for _, e := range n.Events {
			p.printEvent(e, indentLevel, false)
		}
	}

	if n.IPAddresses != nil {
		p.printIPAddressSet(n.IPAddresses, indentLevel)
	}

	for _, e := range n.Entities {
		p.printEntity(&e, indentLevel)
	}

	p.printUnknowns(n.DecodeData, indentLevel)
}

func (p *Printer) printIPAddressSet(s *IPAddressSet, indentLevel uint) {
	p.printHeading("IP Addresses", indentLevel)

	indentLevel++

	for _, ip := range s.V6 {
		p.printValue("IPv6", ip, indentLevel)
	}

	for _, ip := range s.V4 {
		p.printValue("IPv4", ip, indentLevel)
	}

	p.printUnknowns(s.DecodeData, indentLevel)
}

func (p *Printer) printEntity(e *Entity, indentLevel uint) {
	p.printHeading("Entity", indentLevel)

	indentLevel++

	p.printValue("Handle", e.Handle, indentLevel)

	for _, s := range e.Status {
		p.printValue("Status", s, indentLevel)
	}

	if !p.BriefOutput {
		p.printValue("Port43", e.Port43, indentLevel)
	}

	for _, pid := range e.PublicIDs {
		p.printPublicID(pid, indentLevel)
	}

	if !p.BriefOutput {
		for _, c := range e.Conformance {
			p.printValue("Conformance", c, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, n := range e.Notices {
			p.printNotice(n, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitRemarks {
		for _, r := range e.Remarks {
			p.printRemark(r, indentLevel)
		}
	}

	for _, l := range e.Links {
		p.printLink(l, indentLevel)
	}

	if !p.BriefOutput {
		for _, e := range e.Events {
			p.printEvent(e, indentLevel, false)
		}

		for _, e := range e.AsEventActor {
			p.printEvent(e, indentLevel, true)
		}
	}

	for _, r := range e.Roles {
		p.printValue("Role", r, indentLevel)
	}

	if e.VCard != nil {
		for _, property := range e.VCard.Properties {
			for _, str := range property.Values() {
				p.printValue("vCard "+property.Name, str, indentLevel)
			}
		}
	}

	if !p.BriefOutput {
		for _, ipn := range e.Networks {
			p.printIPNetwork(&ipn, indentLevel)
		}

		for _, asn := range e.Autnums {
			p.printAutnum(&asn, indentLevel)
		}

		for _, e := range e.Entities {
			p.printEntity(&e, indentLevel)
		}
	}

	p.printUnknowns(e.DecodeData, indentLevel)
}

func (p *Printer) printIPNetwork(n *IPNetwork, indentLevel uint) {
	p.printHeading("IP Network", indentLevel)

	indentLevel++

	p.printValue("Handle", n.Handle, indentLevel)
	p.printValue("Start Address", n.StartAddress, indentLevel)
	p.printValue("End Address", n.EndAddress, indentLevel)
	p.printValue("IP Version", n.IPVersion, indentLevel)
	p.printValue("Name", n.Name, indentLevel)
	p.printValue("Type", n.Type, indentLevel)
	p.printValue("Country", n.Country, indentLevel)
	p.printValue("ParentHandle", n.ParentHandle, indentLevel)

	for _, s := range n.Status {
		p.printValue("Status", s, indentLevel)
	}

	if !p.BriefOutput {
		p.printValue("Port43", n.Port43, indentLevel)
	}

	if !p.BriefOutput || p.OmitNotices {
		for _, no := range n.Notices {
			p.printNotice(no, indentLevel)
		}
	}

	if !p.BriefOutput || p.OmitRemarks {
		for _, r := range n.Remarks {
			p.printRemark(r, indentLevel)
		}
	}

	for _, e := range n.Entities {
		p.printEntity(&e, indentLevel)
	}

	for _, l := range n.Links {
		p.printLink(l, indentLevel)
	}

	if !p.BriefOutput {
		for _, e := range n.Events {
			p.printEvent(e, indentLevel, false)
		}
	}

	p.printUnknowns(n.DecodeData, indentLevel)
}

func (p *Printer) printPublicID(pid PublicID, indentLevel uint) {
	p.printHeading("Public ID", indentLevel)

	indentLevel++

	p.printValue("Type", pid.Type, indentLevel)
	p.printValue("Identifier", pid.Identifier, indentLevel)

	p.printUnknowns(pid.DecodeData, indentLevel)
}

func (p *Printer) printSecureDNS(s *SecureDNS, indentLevel uint) {
	p.printHeading("Secure DNS", indentLevel)

	indentLevel++

	if s.ZoneSigned != nil {
		p.printValue("Zone Signed",
			strconv.FormatBool(*s.ZoneSigned),
			indentLevel)
	}

	if s.DelegationSigned != nil {
		p.printValue("Delegation Signed",
			strconv.FormatBool(*s.DelegationSigned),
			indentLevel)
	}

	if s.MaxSigLife != nil {
		p.printValue("Max Signature Life",
			strconv.FormatUint(*s.MaxSigLife, 10),
			indentLevel)
	}

	for _, ds := range s.DS {
		p.printDSData(ds, indentLevel)
	}

	for _, key := range s.Keys {
		p.printKeyData(key, indentLevel)
	}

	p.printUnknowns(s.DecodeData, indentLevel)
}

func (p *Printer) printKeyData(k KeyData, indentLevel uint) {
	p.printHeading("Key", indentLevel)

	indentLevel++

	if k.Flags != nil {
		p.printValue("Flags",
			strconv.FormatUint(uint64(*k.Flags), 10),
			indentLevel)
	}

	if k.Protocol != nil {
		p.printValue("Protocol",
			strconv.FormatUint(uint64(*k.Protocol), 10),
			indentLevel)
	}

	if k.Algorithm != nil {
		p.printValue("Algorithm",
			strconv.FormatUint(uint64(*k.Algorithm), 10),
			indentLevel)
	}

	p.printValue("Public Key", k.PublicKey, indentLevel)

	if !p.BriefOutput {
		for _, e := range k.Events {
			p.printEvent(e, indentLevel, false)
		}
	}

	for _, l := range k.Links {
		p.printLink(l, indentLevel)
	}

	p.printUnknowns(k.DecodeData, indentLevel)
}

func (p *Printer) printDSData(d DSData, indentLevel uint) {
	p.printHeading("DSData", indentLevel)

	indentLevel++

	if d.KeyTag != nil {
		p.printValue("Key Tag",
			strconv.FormatUint(uint64(*d.KeyTag), 10),
			indentLevel)
	}

	if d.Algorithm != nil {
		p.printValue("Algorithm",
			strconv.FormatUint(uint64(*d.Algorithm), 10),
			indentLevel)
	}

	p.printValue("Digest", d.Digest, indentLevel)

	if d.DigestType != nil {
		p.printValue("DigestType",
			strconv.FormatUint(uint64(*d.DigestType), 10),
			indentLevel)
	}

	if !p.BriefOutput {
		for _, e := range d.Events {
			p.printEvent(e, indentLevel, false)
		}
	}

	for _, l := range d.Links {
		p.printLink(l, indentLevel)
	}

	p.printUnknowns(d.DecodeData, indentLevel)
}

func (p *Printer) printVariant(v Variant, indentLevel uint) {
	p.printHeading("Variant", indentLevel)

	indentLevel++
	for _, r := range v.Relation {
		p.printValue("Relation", r, indentLevel)
	}

	p.printValue("IDN Table", v.IDNTable, indentLevel)

	for _, vn := range v.VariantNames {
		p.printVariantName(vn, indentLevel)
	}

	p.printUnknowns(v.DecodeData, indentLevel)
}

func (p *Printer) printVariantName(vn VariantName, indentLevel uint) {
	p.printHeading("Variant Name", indentLevel)

	indentLevel++
	p.printValue("Domain Name", vn.LDHName, indentLevel)
	p.printValue("Domain Name (Unicode)", vn.UnicodeName, indentLevel)

	p.printUnknowns(vn.DecodeData, indentLevel)
}

func (p *Printer) printRemark(r Remark, indentLevel uint) {
	p.printHeading("Remark", indentLevel)

	indentLevel++
	p.printValue("Title", r.Title, indentLevel)
	p.printValue("Type", r.Type, indentLevel)
	for _, d := range r.Description {
		p.printValue("Description", d, indentLevel)
	}

	for _, l := range r.Links {
		p.printLink(l, indentLevel)
	}

	p.printUnknowns(r.DecodeData, indentLevel)
}

func (p *Printer) printNotice(n Notice, indentLevel uint) {
	p.printHeading("Notice", indentLevel)

	indentLevel++
	p.printValue("Title", n.Title, indentLevel)
	p.printValue("Type", n.Type, indentLevel)
	for _, d := range n.Description {
		p.printValue("Description", d, indentLevel)
	}

	for _, l := range n.Links {
		p.printLink(l, indentLevel)
	}

	p.printUnknowns(n.DecodeData, indentLevel)
}

func (p *Printer) printLink(l Link, indent uint) {
	if p.BriefLinks {
		p.printValue("Link", l.Href, indent)
		return
	}

	p.printHeading("Link", indent)

	indent++
	p.printValue("Title", l.Title, indent)
	p.printValue("Href", l.Href, indent)
	p.printValue("Value", l.Value, indent)
	p.printValue("Rel", l.Rel, indent)
	p.printValue("Media", l.Media, indent)
	p.printValue("Type", l.Type, indent)

	for _, h := range l.HrefLang {
		p.printValue("HrefLang", h, indent)
	}

	p.printUnknowns(l.DecodeData, indent)
}

func (p *Printer) printHeading(heading string, indentLevel uint) {
	fmt.Fprintf(p.Writer, "%s%s:\n",
		strings.Repeat(string(p.IndentChar), int(indentLevel*p.IndentSize)),
		p.cleanString(heading))
}

func (p *Printer) printValue(name string, value string, indentLevel uint) {
	if value == "" {
		return
	}

	fmt.Fprintf(p.Writer, "%s%s: %s\n",
		strings.Repeat(string(p.IndentChar), int(indentLevel*p.IndentSize)),
		p.cleanString(name),
		p.cleanString(value))
}

func (p *Printer) printEvent(e Event, indentLevel uint, asEventActor bool) {
	if p.BriefOutput {
		return
	}

	if asEventActor {
		p.printHeading("AsEventActor", indentLevel)
	} else {
		p.printHeading("Event", indentLevel)
	}

	indentLevel++

	p.printValue("Action", e.Action, indentLevel)
	p.printValue("Actor", e.Actor, indentLevel)
	p.printValue("Date", e.Date, indentLevel)

	for _, l := range e.Links {
		p.printLink(l, indentLevel)
	}

	p.printUnknowns(e.DecodeData, indentLevel)
}

func (p *Printer) printUnknowns(d *DecodeData, indentLevel uint) {
	if d == nil {
		return
	}

	for k, v := range d.values {
		isKnown, _ := d.isKnown[k]
		isOverrided, _ := d.overrideKnownValue[k]

		if !(isKnown && !isOverrided) {
			p.printUnknown(k, v, indentLevel)
		}
	}
}

func (p *Printer) printUnknown(key string, value interface{}, indentLevel uint) {
	switch value.(type) {
	case bool:
		p.printValue(key, strconv.FormatBool(value.(bool)), indentLevel)
	case float64:
		p.printValue(key, strconv.FormatFloat(value.(float64), 'f', -1, 64), indentLevel)
	case string:
		p.printValue(key, value.(string), indentLevel)
	case []interface{}:
		for _, value2 := range value.([]interface{}) {
			p.printUnknown(key, value2, indentLevel)
		}
	case map[string]interface{}:
		p.printHeading(key, indentLevel)
		indentLevel++

		for key2, value2 := range value.(map[string]interface{}) {
			p.printUnknown(key2, value2, indentLevel)
		}
	default:
		p.printValue(key, "[unprintable value]", indentLevel)
	}
}

func (p *Printer) cleanString(str string) string {
	return strings.Map(removeBadRunes, str)
}

func removeBadRunes(r rune) rune {
	switch r {
	case '\n', '\r', '\000':
		return -1
	default:
		return r
	}
}
