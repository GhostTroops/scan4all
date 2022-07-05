// OpenRDAP
// Copyright 2017 Tom Harwood
// MIT License, see the LICENSE file.

package rdap

import (
	"net/http"
	"time"

	"github.com/openrdap/rdap/bootstrap"
)

type Response struct {
	Object          RDAPObject
	BootstrapAnswer *bootstrap.Answer
	HTTP            []*HTTPResponse
}

type RDAPObject interface{}

type HTTPResponse struct {
	URL      string
	Response *http.Response
	Body     []byte
	Error    error
	Duration time.Duration
}

type WhoisStyleResponse struct {
	KeyDisplayOrder []string
	Data            map[string][]string
}

func (w *WhoisStyleResponse) add(key string, value string) {
	if value == "" {
		return
	}

	if _, exists := w.Data[key]; !exists {
		w.KeyDisplayOrder = append(w.KeyDisplayOrder, key)
		w.Data[key] = []string{value}
	} else {
		w.Data[key] = append(w.Data[key], value)
	}
}

func newWhoisStyleResponse() *WhoisStyleResponse {
	w := &WhoisStyleResponse{}
	w.Data = make(map[string][]string)

	return w
}

func (r *Response) ToWhoisStyleResponse() *WhoisStyleResponse {
	w := newWhoisStyleResponse()

	// Only support domain whois so far.
	d, ok := r.Object.(*Domain)
	if !ok {
		return w
	}

	// "Domain Name"
	w.add("Domain Name", d.LDHName)

	// Registry Domain ID
	w.add("Handle", d.Handle)

	// "Registrar WHOIS Server"
	w.add("Registrar WHOIS Server", d.Port43)

	// Events.
	for _, e := range d.Events {
		switch e.Action {
		case "last changed":
			w.add("Updated Date", e.Date)
		case "registration":
			w.add("Creation Date", e.Date)
		case "expiration":
			w.add("Expiration Date", e.Date)
		}
	}

	// Registrar fields.
	registrar := findFirstEntity("registrar", d.Entities)
	if registrar != nil {
		vcard := registrar.VCard
		if vcard != nil {
			// "Registrar"
			w.add("Registrar", vcard.Name())
		}

		// "Registrar IANA ID"
		for _, id := range registrar.PublicIDs {
			if id.Type == "IANA Registrar ID" {
				w.add("Registrar IANA ID", id.Identifier)
			}
		}

		// "Registrar Abuse Contact Email"
		// "Registrar Abuse Contact Phone"
	}

	// "Domain Status"
	for _, s := range d.Status {
		w.add("Domain Status", s)
	}

	addEntityFields(w, "Registrant", findFirstEntity("registrant", d.Entities))
	addEntityFields(w, "Admin", findFirstEntity("administrative", d.Entities))
	addEntityFields(w, "Tech", findFirstEntity("technical", d.Entities))
	addEntityFields(w, "Abuse", findFirstEntity("abuse", d.Entities))

	// "Name Server"
	for _, n := range d.Nameservers {
		w.add("Name Server", n.LDHName)
	}

	return w
}

func addEntityFields(w *WhoisStyleResponse, t string, e *Entity) {
	if e == nil {
		return
	}

	v := e.VCard
	if v == nil {
		return
	}

	w.add(t+" Name", v.Name())
	w.add(t+" PO Box", v.POBox())
	w.add(t+" Extended Address", v.ExtendedAddress())
	w.add(t+" Street", v.StreetAddress())
	w.add(t+" Locality", v.Locality())
	w.add(t+" Post Code", v.PostalCode())
	w.add(t+" Country", v.Country())
	w.add(t+" Tel", v.Tel())
	w.add(t+" Fax", v.Fax())
	w.add(t+" Email", v.Email())
}

func findFirstEntity(role string, entities []Entity) *Entity {
	for _, e := range entities {
		for _, r := range e.Roles {
			if r == role {
				return &e
			}
		}
	}

	return nil
}
