// Package smtpd implements a basic SMTP server.
package smtpd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Debug `true` enables verbose logging.
	Debug      = false
	rcptToRE   = regexp.MustCompile(`[Tt][Oo]:\s?<(.+)>`)
	mailFromRE = regexp.MustCompile(`[Ff][Rr][Oo][Mm]:\s?<(.*)>(\s(.*))?`) // Delivery Status Notifications are sent with "MAIL FROM:<>"
	mailSizeRE = regexp.MustCompile(`[Ss][Ii][Zz][Ee]=(\d+)`)
)

// Handler function called upon successful receipt of an email.
type Handler func(remoteAddr net.Addr, from string, to []string, data []byte) error

// HandlerRcpt function called on RCPT. Return accept status.
type HandlerRcpt func(remoteAddr net.Addr, from string, to string) bool

// AuthHandler function called when a login attempt is performed. Returns true if credentials are correct.
type AuthHandler func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error)

// ListenAndServe listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections.
func ListenAndServe(addr string, handler Handler, appname string, hostname string) error {
	srv := &Server{Addr: addr, Handler: handler, Appname: appname, Hostname: hostname}
	return srv.ListenAndServe()
}

// ListenAndServeTLS listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections. Connections may be upgraded to TLS if the client requests it.
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler Handler, appname string, hostname string) error {
	srv := &Server{Addr: addr, Handler: handler, Appname: appname, Hostname: hostname}
	err := srv.ConfigureTLS(certFile, keyFile)
	if err != nil {
		return err
	}
	return srv.ListenAndServe()
}

type maxSizeExceededError struct {
	limit int
}

func maxSizeExceeded(limit int) maxSizeExceededError {
	return maxSizeExceededError{limit}
}

// Error uses the RFC 5321 response message in preference to RFC 1870.
// RFC 3463 defines enhanced status code x.3.4 as "Message too big for system".
func (err maxSizeExceededError) Error() string {
	return fmt.Sprintf("552 5.3.4 Requested mail action aborted: exceeded storage allocation (%d)", err.limit)
}

// LogFunc is a function capable of logging the client-server communication.
type LogFunc func(remoteIP, verb, line string)

// Server is an SMTP server.
type Server struct {
	Addr         string // TCP address to listen on, defaults to ":25" (all addresses, port 25) if empty
	Appname      string
	AuthHandler  AuthHandler
	AuthMechs    map[string]bool // Override list of allowed authentication mechanisms. Currently supported: LOGIN, PLAIN, CRAM-MD5. Enabling LOGIN and PLAIN will reduce RFC 4954 compliance.
	AuthRequired bool            // Require authentication for every command except AUTH, EHLO, HELO, NOOP, RSET or QUIT as per RFC 4954. Ignored if AuthHandler is not configured.
	Handler      Handler
	HandlerRcpt  HandlerRcpt
	Hostname     string
	LogRead      LogFunc
	LogWrite     LogFunc
	MaxSize      int // Maximum message size allowed, in bytes
	Timeout      time.Duration
	TLSConfig    *tls.Config
	TLSListener  bool // Listen for incoming TLS connections only (not recommended as it may reduce compatibility). Ignored if TLS is not configured.
	TLSRequired  bool // Require TLS for every command except NOOP, EHLO, STARTTLS, or QUIT as per RFC 3207. Ignored if TLS is not configured.
}

// ConfigureTLS creates a TLS configuration from certificate and key files.
func (srv *Server) ConfigureTLS(certFile string, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	return nil
}

// ConfigureTLSWithPassphrase creates a TLS configuration from a certificate,
// an encrypted key file and the associated passphrase:
func (srv *Server) ConfigureTLSWithPassphrase(
	certFile string,
	keyFile string,
	passphrase string,
) error {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	keyPEMDecrypted, err := x509.DecryptPEMBlock(keyDERBlock, []byte(passphrase))
	if err != nil {
		return err
	}
	var pemBlock pem.Block
	pemBlock.Type = keyDERBlock.Type
	pemBlock.Bytes = keyPEMDecrypted
	keyPEMBlock = pem.EncodeToMemory(&pemBlock)
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	return nil
}

// ListenAndServe listens on the TCP network address srv.Addr and then
// calls Serve to handle requests on incoming connections.  If
// srv.Addr is blank, ":25" is used.
func (srv *Server) ListenAndServe() error {
	if srv.Addr == "" {
		srv.Addr = ":25"
	}
	if srv.Appname == "" {
		srv.Appname = "smtpd"
	}
	if srv.Hostname == "" {
		srv.Hostname, _ = os.Hostname()
	}
	if srv.Timeout == 0 {
		srv.Timeout = 5 * time.Minute
	}

	var ln net.Listener
	var err error

	// If TLSListener is enabled, listen for TLS connections only.
	if srv.TLSConfig != nil && srv.TLSListener {
		ln, err = tls.Listen("tcp", srv.Addr, srv.TLSConfig)
	} else {
		ln, err = net.Listen("tcp", srv.Addr)
	}
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// Serve creates a new SMTP session after a network connection is established.
func (srv *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			return err
		}
		session := srv.newSession(conn)
		go session.serve()
	}
}

type session struct {
	srv           *Server
	conn          net.Conn
	br            *bufio.Reader
	bw            *bufio.Writer
	remoteIP      string // Remote IP address
	remoteHost    string // Remote hostname according to reverse DNS lookup
	remoteName    string // Remote hostname as supplied with EHLO
	tls           bool
	authenticated bool
}

// Create new session from connection.
func (srv *Server) newSession(conn net.Conn) (s *session) {
	s = &session{
		srv:  srv,
		conn: conn,
		br:   bufio.NewReader(conn),
		bw:   bufio.NewWriter(conn),
	}

	// Get remote end info for the Received header.
	s.remoteIP, _, _ = net.SplitHostPort(s.conn.RemoteAddr().String())
	names, err := net.LookupAddr(s.remoteIP)
	if err == nil && len(names) > 0 {
		s.remoteHost = names[0]
	} else {
		s.remoteHost = "unknown"
	}

	// Set tls = true if TLS is already in use.
	_, s.tls = s.conn.(*tls.Conn)

	return
}

// Function called to handle connection requests.
func (s *session) serve() {
	defer s.conn.Close()
	var from string
	var gotFrom bool
	var to []string
	var buffer bytes.Buffer

	// Send banner.
	s.writef("220 %s %s ESMTP Service ready", s.srv.Hostname, s.srv.Appname)

loop:
	for {
		// Attempt to read a line from the socket.
		// On timeout, send a timeout message and return from serve().
		// On error, assume the client has gone away i.e. return from serve().
		line, err := s.readLine()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", s.srv.Hostname, s.srv.Appname)
			}
			break
		}
		verb, args := s.parseLine(line)

		switch verb {
		case "HELO":
			s.remoteName = args
			s.writef("250 %s greets %s", s.srv.Hostname, s.remoteName)

			// RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET, so reset for HELO too.
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "EHLO":
			s.remoteName = args
			s.writef(s.makeEHLOResponse())

			// RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET.
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "MAIL":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if s.srv.AuthHandler != nil && s.srv.AuthRequired && !s.authenticated {
				s.writef("530 5.7.0 Authentication required")
				break
			}

			match := mailFromRE.FindStringSubmatch(args)
			if match == nil {
				s.writef("501 5.5.4 Syntax error in parameters or arguments (invalid FROM parameter)")
			} else {
				// Validate the SIZE parameter if one was sent.
				if len(match[2]) > 0 { // A parameter is present
					sizeMatch := mailSizeRE.FindStringSubmatch(match[3])
					if sizeMatch == nil {
						s.writef("501 5.5.4 Syntax error in parameters or arguments (invalid SIZE parameter)")
					} else {
						// Enforce the maximum message size if one is set.
						size, err := strconv.Atoi(sizeMatch[1])
						if err != nil { // Bad SIZE parameter
							s.writef("501 5.5.4 Syntax error in parameters or arguments (invalid SIZE parameter)")
						} else if s.srv.MaxSize > 0 && size > s.srv.MaxSize { // SIZE above maximum size, if set
							err = maxSizeExceeded(s.srv.MaxSize)
							s.writef(err.Error())
						} else { // SIZE ok
							from = match[1]
							gotFrom = true
							s.writef("250 2.1.0 Ok")
						}
					}
				} else { // No parameters after FROM
					from = match[1]
					gotFrom = true
					s.writef("250 2.1.0 Ok")
				}
			}
			to = nil
			buffer.Reset()
		case "RCPT":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if s.srv.AuthHandler != nil && s.srv.AuthRequired && !s.authenticated {
				s.writef("530 5.7.0 Authentication required")
				break
			}
			if !gotFrom {
				s.writef("503 5.5.1 Bad sequence of commands (MAIL required before RCPT)")
				break
			}

			match := rcptToRE.FindStringSubmatch(args)
			if match == nil {
				s.writef("501 5.5.4 Syntax error in parameters or arguments (invalid TO parameter)")
			} else {
				// RFC 5321 specifies 100 minimum recipients
				if len(to) == 100 {
					s.writef("452 4.5.3 Too many recipients")
				} else {
					accept := true
					if s.srv.HandlerRcpt != nil {
						accept = s.srv.HandlerRcpt(s.conn.RemoteAddr(), from, match[1])
					}
					if accept {
						to = append(to, match[1])
						s.writef("250 2.1.5 Ok")
					} else {
						s.writef("550 5.1.0 Requested action not taken: mailbox unavailable")
					}
				}
			}
		case "DATA":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			if s.srv.AuthHandler != nil && s.srv.AuthRequired && !s.authenticated {
				s.writef("530 5.7.0 Authentication required")
				break
			}
			if !gotFrom || len(to) == 0 {
				s.writef("503 5.5.1 Bad sequence of commands (MAIL & RCPT required before DATA)")
				break
			}

			s.writef("354 Start mail input; end with <CR><LF>.<CR><LF>")

			// Attempt to read message body from the socket.
			// On timeout, send a timeout message and return from serve().
			// On net.Error, assume the client has gone away i.e. return from serve().
			// On other errors, allow the client to try again.
			data, err := s.readData()
			if err != nil {
				switch err.(type) {
				case net.Error:
					if err.(net.Error).Timeout() {
						s.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", s.srv.Hostname, s.srv.Appname)
					}
					break loop
				case maxSizeExceededError:
					s.writef(err.Error())
					continue
				default:
					s.writef("451 4.3.0 Requested action aborted: local error in processing")
					continue
				}
			}

			// Create Received header & write message body into buffer.
			buffer.Reset()
			buffer.Write(s.makeHeaders(to))
			buffer.Write(data)

			// Pass mail on to handler.
			if s.srv.Handler != nil {
				err := s.srv.Handler(s.conn.RemoteAddr(), from, to, buffer.Bytes())
				if err != nil {
					s.writef("451 4.3.5 Unable to process mail")
					break
				}
			}
			s.writef("250 2.0.0 Ok: queued")

			// Reset for next mail.
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "QUIT":
			s.writef("221 2.0.0 %s %s ESMTP Service closing transmission channel", s.srv.Hostname, s.srv.Appname)
			break loop
		case "RSET":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			s.writef("250 2.0.0 Ok")
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "NOOP":
			s.writef("250 2.0.0 Ok")
		case "HELP", "VRFY", "EXPN":
			// See RFC 5321 section 4.2.4 for usage of 500 & 502 response codes.
			s.writef("502 5.5.1 Command not implemented")
		case "STARTTLS":
			// Parameters are not allowed (RFC 3207 section 4).
			if args != "" {
				s.writef("501 5.5.2 Syntax error (no parameters allowed)")
				break
			}

			// Handle case where TLS is requested but not configured (and therefore not listed as a service extension).
			if s.srv.TLSConfig == nil {
				s.writef("502 5.5.1 Command not implemented")
				break
			}

			// Handle case where STARTTLS is received when TLS is already in use.
			if s.tls {
				s.writef("503 5.5.1 Bad sequence of commands (TLS already in use)")
				break
			}

			s.writef("220 2.0.0 Ready to start TLS")

			// Establish a TLS connection with the client.
			tlsConn := tls.Server(s.conn, s.srv.TLSConfig)
			err := tlsConn.Handshake()
			if err != nil {
				s.writef("403 4.7.0 TLS handshake failed")
				break
			}

			// TLS handshake succeeded, switch to using the TLS connection.
			s.conn = tlsConn
			s.br = bufio.NewReader(s.conn)
			s.bw = bufio.NewWriter(s.conn)
			s.tls = true

			// RFC 3207 specifies that the server must discard any prior knowledge obtained from the client.
			s.remoteName = ""
			from = ""
			gotFrom = false
			to = nil
			buffer.Reset()
		case "AUTH":
			if s.srv.TLSConfig != nil && s.srv.TLSRequired && !s.tls {
				s.writef("530 5.7.0 Must issue a STARTTLS command first")
				break
			}
			// Handle case where AUTH is requested but not configured (and therefore not listed as a service extension).
			if s.srv.AuthHandler == nil {
				s.writef("502 5.5.1 Command not implemented")
				break
			}

			// Handle case where AUTH is received when already authenticated.
			if s.authenticated {
				s.writef("503 5.5.1 Bad sequence of commands (already authenticated for this session)")
				break
			}

			// RFC 4954 specifies that AUTH is not permitted during mail transactions.
			if gotFrom || len(to) > 0 {
				s.writef("503 5.5.1 Bad sequence of commands (AUTH not permitted during mail transaction)")
				break
			}

			// RFC 4954 requires a mechanism parameter.
			authType, authArgs := s.parseLine(args)
			if authType == "" {
				s.writef("501 5.5.4 Malformed AUTH input (argument required)")
				break
			}

			// RFC 4954 requires rejecting unsupported authentication mechanisms with a 504 response.
			allowedAuth := s.authMechs()
			if allowed, found := allowedAuth[authType]; !found || !allowed {
				s.writef("504 5.5.4 Unrecognized authentication type")
				break
			}

			// RFC 4954 also specifies that ESMTP code 5.5.4 ("Invalid command arguments") should be returned
			// when attempting to use an unsupported authentication type.
			// Many servers return 5.7.4 ("Security features not supported") instead.
			switch authType {
			case "PLAIN":
				s.authenticated, err = s.handleAuthPlain(authArgs)
			case "LOGIN":
				s.authenticated, err = s.handleAuthLogin(authArgs)
			case "CRAM-MD5":
				s.authenticated, err = s.handleAuthCramMD5()
			}

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					s.writef("421 4.4.2 %s %s ESMTP Service closing transmission channel after timeout exceeded", s.srv.Hostname, s.srv.Appname)
					break loop
				}

				s.writef(err.Error())
				break
			}

			if s.authenticated {
				s.writef("235 2.7.0 Authentication successful")
			} else {
				s.writef("535 5.7.8 Authentication credentials invalid")
			}
		default:
			// See RFC 5321 section 4.2.4 for usage of 500 & 502 response codes.
			s.writef("500 5.5.2 Syntax error, command unrecognized")
		}
	}
}

// Wrapper function for writing a complete line to the socket.
func (s *session) writef(format string, args ...interface{}) error {
	if s.srv.Timeout > 0 {
		s.conn.SetWriteDeadline(time.Now().Add(s.srv.Timeout))
	}

	line := fmt.Sprintf(format, args...)
	fmt.Fprintf(s.bw, line+"\r\n")
	err := s.bw.Flush()

	if Debug {
		verb := "WROTE"
		if s.srv.LogWrite != nil {
			s.srv.LogWrite(s.remoteIP, verb, line)
		} else {
			log.Println(s.remoteIP, verb, line)
		}
	}

	return err
}

// Read a complete line from the socket.
func (s *session) readLine() (string, error) {
	if s.srv.Timeout > 0 {
		s.conn.SetReadDeadline(time.Now().Add(s.srv.Timeout))
	}

	line, err := s.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line) // Strip trailing \r\n

	if Debug {
		verb := "READ"
		if s.srv.LogRead != nil {
			s.srv.LogRead(s.remoteIP, verb, line)
		} else {
			log.Println(s.remoteIP, verb, line)
		}
	}

	return line, err
}

// Parse a line read from the socket.
func (s *session) parseLine(line string) (verb string, args string) {
	if idx := strings.Index(line, " "); idx != -1 {
		verb = strings.ToUpper(line[:idx])
		args = strings.TrimSpace(line[idx+1:])
	} else {
		verb = strings.ToUpper(line)
		args = ""
	}
	return verb, args
}

// Read the message data following a DATA command.
func (s *session) readData() ([]byte, error) {
	var data []byte
	for {
		if s.srv.Timeout > 0 {
			s.conn.SetReadDeadline(time.Now().Add(s.srv.Timeout))
		}

		line, err := s.br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		// Handle end of data denoted by lone period (\r\n.\r\n)
		if bytes.Equal(line, []byte(".\r\n")) {
			break
		}
		// Remove leading period (RFC 5321 section 4.5.2)
		if line[0] == '.' {
			line = line[1:]
		}

		// Enforce the maximum message size limit.
		if s.srv.MaxSize > 0 {
			if len(data)+len(line) > s.srv.MaxSize {
				_, _ = s.br.Discard(s.br.Buffered()) // Discard the buffer remnants.
				return nil, maxSizeExceeded(s.srv.MaxSize)
			}
		}

		data = append(data, line...)
	}
	return data, nil
}

// Create the Received header to comply with RFC 2821 section 3.8.2.
// TODO: Work out what to do with multiple to addresses.
func (s *session) makeHeaders(to []string) []byte {
	var buffer bytes.Buffer
	now := time.Now().Format("Mon, _2 Jan 2006 15:04:05 -0700 (MST)")
	buffer.WriteString(fmt.Sprintf("Received: from %s (%s [%s])\r\n", s.remoteName, s.remoteHost, s.remoteIP))
	buffer.WriteString(fmt.Sprintf("        by %s (%s) with SMTP\r\n", s.srv.Hostname, s.srv.Appname))
	buffer.WriteString(fmt.Sprintf("        for <%s>; %s\r\n", to[0], now))
	return buffer.Bytes()
}

// Determine allowed authentication mechanisms.
// RFC 4954 specifies that plaintext authentication mechanisms such as LOGIN and PLAIN require a TLS connection.
// This can be explicitly overridden e.g. setting s.srv.AuthMechs["LOGIN"] = true.
func (s *session) authMechs() (mechs map[string]bool) {
	mechs = map[string]bool{"LOGIN": s.tls, "PLAIN": s.tls, "CRAM-MD5": true}

	for mech := range mechs {
		allowed, found := s.srv.AuthMechs[mech]
		if found {
			mechs[mech] = allowed
		}
	}

	return
}

// Create the greeting string sent in response to an EHLO command.
func (s *session) makeEHLOResponse() (response string) {
	response = fmt.Sprintf("250-%s greets %s\r\n", s.srv.Hostname, s.remoteName)

	// RFC 1870 specifies that "SIZE 0" indicates no maximum size is in force.
	response += fmt.Sprintf("250-SIZE %d\r\n", s.srv.MaxSize)

	// Only list STARTTLS if TLS is configured, but not currently in use.
	if s.srv.TLSConfig != nil && !s.tls {
		response += "250-STARTTLS\r\n"
	}

	// Only list AUTH if an AuthHandler is configured and at least one mechanism is allowed.
	if s.srv.AuthHandler != nil {
		var mechs []string
		for mech, allowed := range s.authMechs() {
			if allowed {
				mechs = append(mechs, mech)
			}
		}
		if len(mechs) > 0 {
			response += "250-AUTH " + strings.Join(mechs, " ") + "\r\n"
		}
	}

	response += "250 ENHANCEDSTATUSCODES"
	return
}

func (s *session) handleAuthLogin(arg string) (bool, error) {
	var err error

	if arg == "" {
		s.writef("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
		arg, err = s.readLine()
		if err != nil {
			return false, err
		}
	}

	username, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	s.writef("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
	line, err := s.readLine()
	if err != nil {
		return false, err
	}

	password, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	// Validate credentials.
	authenticated, err := s.srv.AuthHandler(s.conn.RemoteAddr(), "LOGIN", username, password, nil)

	return authenticated, err
}

func (s *session) handleAuthPlain(arg string) (bool, error) {
	var err error

	// If fast mode (AUTH PLAIN [arg]) is not used, prompt for credentials.
	if arg == "" {
		s.writef("334 ")
		arg, err = s.readLine()
		if err != nil {
			return false, err
		}
	}

	data, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	parts := bytes.Split(data, []byte{0})
	if len(parts) != 3 {
		return false, errors.New("501 5.5.2 Syntax error (unable to parse)")
	}

	// Validate credentials.
	authenticated, err := s.srv.AuthHandler(s.conn.RemoteAddr(), "PLAIN", parts[1], parts[2], nil)

	return authenticated, err
}

func (s *session) handleAuthCramMD5() (bool, error) {
	shared := "<" + strconv.Itoa(os.Getpid()) + "." + strconv.Itoa(time.Now().Nanosecond()) + "@" + s.srv.Hostname + ">"

	s.writef("334 " + base64.StdEncoding.EncodeToString([]byte(shared)))

	data, err := s.readLine()
	if err != nil {
		return false, err
	}

	if data == "*" {
		return false, errors.New("501 5.7.0 Authentication cancelled")
	}

	buf, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return false, errors.New("501 5.5.2 Syntax error (unable to decode)")
	}

	fields := strings.Split(string(buf), " ")
	if len(fields) < 2 {
		return false, errors.New("501 5.5.2 Syntax error (unable to parse)")
	}

	// Validate credentials.
	authenticated, err := s.srv.AuthHandler(s.conn.RemoteAddr(), "CRAM-MD5", []byte(fields[0]), []byte(fields[1]), []byte(shared))

	return authenticated, err
}
