package ldapserver

import (
	"strings"

	ldap "github.com/lor00x/goldap/message"
)

// Constant to LDAP Request protocol Type names
const (
	SEARCH   = "SearchRequest"
	BIND     = "BindRequest"
	COMPARE  = "CompareRequest"
	ADD      = "AddRequest"
	MODIFY   = "ModifyRequest"
	DELETE   = "DelRequest"
	EXTENDED = "ExtendedRequest"
	ABANDON  = "AbandonRequest"
)

// HandlerFunc type is an adapter to allow the use of
// ordinary functions as LDAP handlers.  If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler object that calls f.
type HandlerFunc func(ResponseWriter, *Message)

// RouteMux manages all routes
type RouteMux struct {
	routes        []*route
	notFoundRoute *route
}

type route struct {
	label       string
	operation   string
	handler     HandlerFunc
	exoName     string
	sBasedn     string
	uBasedn     bool
	sFilter     string
	uFilter     bool
	sScope      int
	uScope      bool
	sAuthChoice string
	uAuthChoice bool
}

// Match return true when the *Message matches the route
// conditions
func (r *route) Match(m *Message) bool {
	if m.ProtocolOpName() != r.operation {
		return false
	}

	switch v := m.ProtocolOp().(type) {
	case ldap.BindRequest:
		if r.uAuthChoice {
			if strings.ToLower(v.AuthenticationChoice()) != r.sAuthChoice {
				return false
			}
		}
		return true

	case ldap.ExtendedRequest:
		if string(v.RequestName()) != r.exoName {
			return false
		}
		return true

	case ldap.SearchRequest:
		if r.uBasedn {
			if strings.ToLower(string(v.BaseObject())) != r.sBasedn {
				return false
			}
		}

		if r.uFilter {
			if strings.ToLower(v.FilterString()) != r.sFilter {
				return false
			}
		}

		if r.uScope {
			if int(v.Scope()) != r.sScope {
				return false
			}
		}
		return true
	}
	return true
}

func (r *route) Label(label string) *route {
	r.label = label
	return r
}

func (r *route) BaseDn(dn string) *route {
	r.sBasedn = strings.ToLower(dn)
	r.uBasedn = true
	return r
}

func (r *route) AuthenticationChoice(choice string) *route {
	r.sAuthChoice = strings.ToLower(choice)
	r.uAuthChoice = true
	return r
}

func (r *route) Filter(pattern string) *route {
	r.sFilter = strings.ToLower(pattern)
	r.uFilter = true
	return r
}

func (r *route) Scope(scope int) *route {
	r.sScope = scope
	r.uScope = true
	return r
}

func (r *route) RequestName(name ldap.LDAPOID) *route {
	r.exoName = string(name)
	return r
}

// NewRouteMux returns a new *RouteMux
// RouteMux implements ldapserver.Handler
func NewRouteMux() *RouteMux {
	return &RouteMux{}
}

// Handler interface used to serve a LDAP Request message
type Handler interface {
	ServeLDAP(w ResponseWriter, r *Message)
}

// ServeLDAP dispatches the request to the handler whose
// pattern most closely matches the request request Message.
func (h *RouteMux) ServeLDAP(w ResponseWriter, r *Message) {

	//find a matching Route
	for _, route := range h.routes {

		//if the route don't match, skip it
		if !route.Match(r) {
			continue
		}

		route.handler(w, r)
		return
	}

	// Catch a AbandonRequest not handled by user
	switch v := r.ProtocolOp().(type) {
	case ldap.AbandonRequest:
		// retreive the request to abandon, and send a abort signal to it
		if requestToAbandon, ok := r.Client.GetMessageByID(int(v)); ok {
			requestToAbandon.Abandon()
		}
	}

	if h.notFoundRoute != nil {
		h.notFoundRoute.handler(w, r)
	} else {
		res := NewResponse(LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}

// Adds a new Route to the Handler
func (h *RouteMux) addRoute(r *route) {
	//and finally append to the list of Routes
	//create the Route
	h.routes = append(h.routes, r)
}

func (h *RouteMux) NotFound(handler HandlerFunc) *route {
	route := &route{}
	route.handler = handler
	h.notFoundRoute = route
	return route
}

func (h *RouteMux) Bind(handler HandlerFunc) *route {
	route := &route{}
	route.operation = BIND
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Search(handler HandlerFunc) *route {
	route := &route{}
	route.operation = SEARCH
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Add(handler HandlerFunc) *route {
	route := &route{}
	route.operation = ADD
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Delete(handler HandlerFunc) *route {
	route := &route{}
	route.operation = DELETE
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Modify(handler HandlerFunc) *route {
	route := &route{}
	route.operation = MODIFY
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Compare(handler HandlerFunc) *route {
	route := &route{}
	route.operation = COMPARE
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Extended(handler HandlerFunc) *route {
	route := &route{}
	route.operation = EXTENDED
	route.handler = handler
	h.addRoute(route)
	return route
}

func (h *RouteMux) Abandon(handler HandlerFunc) *route {
	route := &route{}
	route.operation = ABANDON
	route.handler = handler
	h.addRoute(route)
	return route
}
