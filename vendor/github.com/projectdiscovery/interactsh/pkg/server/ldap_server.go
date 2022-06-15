package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	ldap "github.com/Mzack9999/ldapserver"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/stringsutil"
)

// Most routes handlers are taken from the example at https://github.com/vjeantet/ldapserver/blob/master/examples/complex/main.go

func init() {
	ldap.Logger = ldap.DiscardingLogger
}

// LDAPServer is a ldap server instance
type LDAPServer struct {
	WithLogger bool
	options    *Options
	server     *ldap.Server
	tlsConfig  *tls.Config
}

// NewLDAPServer returns a new LDAP server.
func NewLDAPServer(options *Options, withLogger bool) (*LDAPServer, error) {
	ldapserver := &LDAPServer{options: options, WithLogger: withLogger}

	if withLogger {
		ldap.Logger = ldapserver
	}

	routes := ldap.NewRouteMux()
	routes.Bind(ldapserver.handleBind)
	routes.NotFound(ldapserver.handleNotFound)
	routes.Abandon(ldapserver.handleAbandon)
	routes.Compare(ldapserver.handleCompare)
	routes.Add(ldapserver.handleAdd)
	routes.Delete(ldapserver.handleDelete)
	routes.Modify(ldapserver.handleModify)
	routes.Extended(ldapserver.handleStartTLS).RequestName(ldap.NoticeOfStartTLS).Label("StartTLS")
	routes.Extended(ldapserver.handleWhoAmI).RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")
	routes.Extended(ldapserver.handleExtended).Label("Ext - Generic")
	routes.Search(ldapserver.handleSearch)

	server := ldap.NewServer()
	err := server.Handle(routes)
	if err != nil {
		return nil, err
	}
	ldapserver.server = server

	return ldapserver, nil
}

// ListenAndServe listens on ldap ports for the server.
func (ldapServer *LDAPServer) ListenAndServe(tlsConfig *tls.Config, ldapAlive chan bool) {
	ldapAlive <- true
	ldapServer.tlsConfig = tlsConfig
	if err := ldapServer.server.ListenAndServe(fmt.Sprintf("%s:%d", ldapServer.options.ListenIP, ldapServer.options.LdapPort)); err != nil {
		gologger.Error().Msgf("Could not serve ldap on port 10389: %s\n", err)
		ldapAlive <- false
	}
}

// handleBind is a handler for bind requests
func (ldapServer *LDAPServer) handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	var message strings.Builder
	message.WriteString("Type=Bind\n")
	message.WriteString(fmt.Sprintf("AuthenticationChoice=%s\n", r.AuthenticationChoice()))
	message.WriteString(fmt.Sprintf("User=%s\n", r.Name()))
	message.WriteString(fmt.Sprintf("Pass=%s\n", r.Authentication()))
	w.Write(res)

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleSearch is a handler for search requests
func (ldapServer *LDAPServer) handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	var uniqueID, fullID string

	host := m.Client.Addr().String()

	r := m.GetSearchRequest()

	var message strings.Builder
	message.WriteString("Type=Search\n")
	baseObject := r.BaseObject()
	message.WriteString(fmt.Sprintf("BaseDn=%s\n", baseObject))
	message.WriteString(fmt.Sprintf("Filter=%s\n", r.Filter()))
	message.WriteString(fmt.Sprintf("FilterString=%s\n", r.FilterString()))
	message.WriteString(fmt.Sprintf("Attributes=%s\n", r.Attributes()))
	message.WriteString(fmt.Sprintf("TimeLimit=%d\n", r.TimeLimit().Int()))

	e := ldap.NewSearchResultEntry("cn=interactsh, " + string(baseObject))
	e.AddAttribute("mail", "interact@s.h", "interact@s.h")
	e.AddAttribute("company", "aaa")
	e.AddAttribute("department", "bbbb")
	e.AddAttribute("l", "cccc")
	e.AddAttribute("mobile", "123456789")
	e.AddAttribute("telephoneNumber", "123456789")
	e.AddAttribute("cn", "interact")
	w.Write(e)
	res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	for _, part := range stringsutil.SplitAny(string(baseObject), "=,") {
		partChunks := strings.Split(part, ".")
		for i, partChunk := range partChunks {
			for scanChunk := range stringsutil.SlideWithLength(partChunk, ldapServer.options.GetIdLength()) {
				if ldapServer.options.isCorrelationID(scanChunk) {
					uniqueID = scanChunk
					fullID = partChunk
					if i+1 <= len(partChunks) {
						fullID = strings.Join(partChunks[:i+1], ".")
					}
					ldapServer.handleInteraction(uniqueID, fullID, message.String(), host)
				}
			}
		}
	}
}

func (ldapServer *LDAPServer) handleInteraction(uniqueID, fullID, reqString, host string) {
	if uniqueID != "" {
		correlationID := uniqueID[:ldapServer.options.CorrelationIdLength]
		interaction := &Interaction{
			Protocol:      "ldap",
			UniqueID:      uniqueID,
			FullId:        fullID,
			RawRequest:    reqString,
			RemoteAddress: host,
			Timestamp:     time.Now(),
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			gologger.Warning().Msgf("Could not encode ldap interaction: %s\n", err)
		} else {
			gologger.Debug().Msgf("LDAP Interaction: \n%s\n", buffer.String())
			if err := ldapServer.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
				gologger.Warning().Msgf("Could not store ldap interaction: %s\n", err)
			}
		}

	}

	// still not the full interaction without correlation if requested
	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: host,
			RawRequest:    reqString,
		})
	}
}

// handleAbandon is a handler for abandon requests
func (ldapServer *LDAPServer) handleAbandon(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAbandonRequest()
	var message strings.Builder
	message.WriteString("Type=Abandon\n")

	if requestToAbandon, ok := m.Client.GetMessageByID(int(r)); ok {
		requestToAbandon.Abandon()
	}

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleNotFound is a handler for not matched routes requests
func (ldapServer *LDAPServer) handleNotFound(w ldap.ResponseWriter, m *ldap.Message) {
	var message strings.Builder
	message.WriteString(fmt.Sprintf("Type=%s\n", m.String()))

	switch m.ProtocolOpType() {
	case ldap.ApplicationBindRequest:
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")
		w.Write(res)
	default:
		res := ldap.NewResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleCompare is a handler for compare requests
func (ldapServer *LDAPServer) handleCompare(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetCompareRequest()
	var message strings.Builder
	message.WriteString("Type=Compare\n")
	message.WriteString(fmt.Sprintf("Attribute name to compare=%s\n", r.Ava().AttributeDesc()))
	message.WriteString(fmt.Sprintf("Attribute value expected=%s\n", r.Ava().AssertionValue()))

	res := ldap.NewCompareResponse(ldap.LDAPResultCompareTrue)
	w.Write(res)

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleCompare is a handler for compare requests
func (ldapServer *LDAPServer) handleAdd(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetAddRequest()
	var message strings.Builder
	message.WriteString("Type=Add\n")
	message.WriteString(fmt.Sprintf("Entity=%s\n", r.Entry()))
	for _, attribute := range r.Attributes() {
		for _, attributeValue := range attribute.Vals() {
			message.WriteString(fmt.Sprintf("Attribute Name=%s Attribute Value=%s\n", attribute.Type_(), attributeValue))
		}
	}

	res := ldap.NewAddResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleDelete is a handler for delete requests
func (ldapServer *LDAPServer) handleDelete(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetCompareRequest()
	var message strings.Builder
	message.WriteString("Type=Delete\n")
	message.WriteString(fmt.Sprintf("Entity=%s\n", r.Entry()))

	res := ldap.NewDeleteResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleModify is a handler for delete requests
func (ldapServer *LDAPServer) handleModify(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetModifyRequest()
	var message strings.Builder
	message.WriteString("Type=Modify\n")
	message.WriteString(fmt.Sprintf("Entity=%s\n", r.Object()))

	for _, change := range r.Changes() {
		modification := change.Modification()
		var operationString string
		switch change.Operation() {
		case ldap.ModifyRequestChangeOperationAdd:
			operationString = "Add"
		case ldap.ModifyRequestChangeOperationDelete:
			operationString = "Delete"
		case ldap.ModifyRequestChangeOperationReplace:
			operationString = "Replace"
		}

		var vals []string
		for _, attributeValue := range modification.Vals() {
			vals = append(vals, fmt.Sprint(attributeValue))
		}
		message.WriteString(fmt.Sprintf("Operation=%s Attribute=%s Values=[%s]\n", operationString, modification.Type_(), strings.Join(vals, " - ")))
	}

	res := ldap.NewModifyResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleStartTLS is a handler for startTLS requests
func (ldapServer *LDAPServer) handleStartTLS(w ldap.ResponseWriter, m *ldap.Message) {
	var message strings.Builder
	message.WriteString("Type=StartTLS\n")

	tlsconfig, _ := ldapServer.getTLSconfig()
	tlsConn := tls.Server(m.Client.GetConn(), tlsconfig)
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	res.SetResponseName(ldap.NoticeOfStartTLS)
	w.Write(res)

	if err := tlsConn.Handshake(); err != nil {
		message.WriteString(fmt.Sprintf("Result=StartTLS Handshake error %s\n", err.Error()))
		res.SetDiagnosticMessage(fmt.Sprintf("StartTLS Handshake error : \"%s\"", err.Error()))
		res.SetResultCode(ldap.LDAPResultOperationsError)
		w.Write(res)
		return
	}
	m.Client.SetConn(tlsConn)
	message.WriteString("Result=StartTLS OK\n")

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleWhoAmI is a handler for whoami requests
func (ldapServer *LDAPServer) handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message) {
	var message strings.Builder
	message.WriteString("Type=WhoAmI\n")

	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

// handleExtended is a handler for generic extended requests
func (ldapServer *LDAPServer) handleExtended(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetExtendedRequest()

	var message strings.Builder
	message.WriteString("Type=Extended\n")
	message.WriteString(fmt.Sprintf("Name=%s\n", r.RequestName()))
	message.WriteString(fmt.Sprintf("Value=%s\n", r.RequestValue()))

	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)

	if ldapServer.WithLogger {
		ldapServer.logInteraction(Interaction{
			RemoteAddress: m.Client.Addr().String(),
			RawRequest:    message.String(),
		})
	}
}

func (ldapServer *LDAPServer) Fatal(v ...interface{}) {
	//nolint
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Fatalf(format string, v ...interface{}) {
	ldapServer.handleLog(format, v...)
}
func (ldapServer *LDAPServer) Fatalln(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Panic(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Panicf(format string, v ...interface{}) {
	ldapServer.handleLog(format, v...)
}
func (ldapServer *LDAPServer) Panicln(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Print(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}
func (ldapServer *LDAPServer) Printf(format string, v ...interface{}) {
	ldapServer.handleLog(format, v...)
}
func (ldapServer *LDAPServer) Println(v ...interface{}) {
	ldapServer.handleLog("%v", v...) //nolint
}

func (ldapServer *LDAPServer) handleLog(f string, v ...interface{}) {
	// just discard logs if logger is disabled
	if !ldapServer.WithLogger {
		return
	}

	var data strings.Builder
	if f != "" {
		data.WriteString(fmt.Sprintf(f, v...))
	} else {
		for _, vv := range v {
			data.WriteString(fmt.Sprint(vv))
		}
	}

	// Correlation id doesn't apply here, we skip encryption
	ldapServer.logInteraction(Interaction{RawRequest: data.String()})
}

func (ldapServer *LDAPServer) logInteraction(interaction Interaction) {
	// Correlation id doesn't apply here, we skip encryption
	interaction.Protocol = "ldap"
	interaction.Timestamp = time.Now()
	buffer := &bytes.Buffer{}
	if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
		gologger.Warning().Msgf("Could not encode ldap interaction: %s\n", err)
	} else {
		gologger.Debug().Msgf("LDAP Interaction: \n%s\n", buffer.String())
		if err := ldapServer.options.Storage.AddInteractionWithId(ldapServer.options.Token, buffer.Bytes()); err != nil {
			gologger.Warning().Msgf("Could not store ldap interaction: %s\n", err)
		}
	}
}

func (ldapServer *LDAPServer) Close() error {
	return ldapServer.server.Listener.Close()
}

// localhostCert is a PEM-encoded TLS cert with SAN DNS names
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBOTCB5qADAgECAgEAMAsGCSqGSIb3DQEBBTAAMB4XDTcwMDEwMTAwMDAwMFoX
DTQ5MTIzMTIzNTk1OVowADBaMAsGCSqGSIb3DQEBAQNLADBIAkEAsuA5mAFMj6Q7
qoBzcvKzIq4kzuT5epSp2AkcQfyBHm7K13Ws7u+0b5Vb9gqTf5cAiIKcrtrXVqkL
8i1UQF6AzwIDAQABo08wTTAOBgNVHQ8BAf8EBAMCACQwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDAbBgNVHREEFDASggkxMjcuMC4wLjGCBVs6OjFdMAsG
CSqGSIb3DQEBBQNBAJH30zjLWRztrWpOCgJL8RQWLaKzhK79pVhAx6q/3NrF16C7
+l1BRZstTwIGdoGId8BRpErK1TXkniFb95ZMynM=
-----END CERTIFICATE-----
`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPQIBAAJBALLgOZgBTI+kO6qAc3LysyKuJM7k+XqUqdgJHEH8gR5uytd1rO7v
tG+VW/YKk3+XAIiCnK7a11apC/ItVEBegM8CAwEAAQJBAI5sxq7naeR9ahyqRkJi
SIv2iMxLuPEHaezf5CYOPWjSjBPyVhyRevkhtqEjF/WkgL7C2nWpYHsUcBDBQVF0
3KECIQDtEGB2ulnkZAahl3WuJziXGLB+p8Wgx7wzSM6bHu1c6QIhAMEp++CaS+SJ
/TrU0zwY/fW4SvQeb49BPZUF3oqR8Xz3AiEA1rAJHBzBgdOQKdE3ksMUPcnvNJSN
poCcELmz2clVXtkCIQCLytuLV38XHToTipR4yMl6O+6arzAjZ56uq7m7ZRV0TwIh
AM65XAOw8Dsg9Kq78aYXiOEDc5DL0sbFUu/SlmRcCg93
-----END RSA PRIVATE KEY-----
`)

// getTLSconfig returns a tls configuration used to build a TLSlistener for TLS or StartTLS
func (ldapServer *LDAPServer) getTLSconfig() (*tls.Config, error) {
	if ldapServer.tlsConfig == nil {
		cert, err := tls.X509KeyPair(localhostCert, localhostKey)
		if err != nil {
			return &tls.Config{InsecureSkipVerify: true}, err
		}
		// SSL3.0 support is fine as we might be interacting with jurassic java
		return &tls.Config{
			MinVersion:   tls.VersionSSL30, //nolint
			MaxVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			ServerName:   "127.0.0.1",
		}, nil
	}

	return ldapServer.tlsConfig, nil
}
