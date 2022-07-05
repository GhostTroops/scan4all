package smb

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"

	"github.com/stacktitan/smb/gss"
	"github.com/stacktitan/smb/ntlmssp"
	"github.com/stacktitan/smb/smb/encoder"
)

type Session struct {
	IsSigningRequired bool
	IsAuthenticated   bool
	debug             bool
	securityMode      uint16
	messageID         uint64
	sessionID         uint64
	conn              net.Conn
	dialect           uint16
	options           Options
	trees             map[string]uint32
}

type Options struct {
	Host        string
	Port        int
	Workstation string
	Domain      string
	User        string
	Password    string
	Hash        string
}

func validateOptions(opt Options) error {
	if opt.Host == "" {
		return errors.New("Missing required option: Host")
	}
	if opt.Port < 1 || opt.Port > 65535 {
		return errors.New("Invalid or missing value: Port")
	}
	return nil
}

func NewSession(opt Options, debug bool) (s *Session, err error) {

	if err := validateOptions(opt); err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
	if err != nil {
		return
	}

	s = &Session{
		IsSigningRequired: false,
		IsAuthenticated:   false,
		debug:             debug,
		securityMode:      0,
		messageID:         0,
		sessionID:         0,
		dialect:           0,
		conn:              conn,
		options:           opt,
		trees:             make(map[string]uint32),
	}

	s.Debug("Negotiating protocol", nil)
	err = s.NegotiateProtocol()
	if err != nil {
		return
	}

	return s, nil
}

func (s *Session) Debug(msg string, err error) {
	if s.debug {
		log.Println("[ DEBUG ] ", msg)
		if err != nil {
			debug.PrintStack()
		}
	}
}

func (s *Session) NegotiateProtocol() error {
	negReq := s.NewNegotiateReq()
	s.Debug("Sending NegotiateProtocol request", nil)
	buf, err := s.send(negReq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	negRes := NewNegotiateRes()
	s.Debug("Unmarshalling NegotiateProtocol response", nil)
	if err := encoder.Unmarshal(buf, &negRes); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if negRes.Header.Status != StatusOk {
		return errors.New(fmt.Sprintf("NT Status Error: %d\n", negRes.Header.Status))
	}

	// Check SPNEGO security blob
	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return err
	}
	oid := negRes.SecurityBlob.OID
	if !oid.Equal(asn1.ObjectIdentifier(spnegoOID)) {
		return errors.New(fmt.Sprintf(
			"Unknown security type OID [expecting %s]: %s\n",
			gss.SpnegoOid,
			negRes.SecurityBlob.OID))
	}

	// Check for NTLMSSP support
	ntlmsspOID, err := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	if err != nil {
		s.Debug("", err)
		return err
	}

	hasNTLMSSP := false
	for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
		if mechType.Equal(asn1.ObjectIdentifier(ntlmsspOID)) {
			hasNTLMSSP = true
			break
		}
	}
	if !hasNTLMSSP {
		return errors.New("Server does not support NTLMSSP")
	}

	s.securityMode = negRes.SecurityMode
	s.dialect = negRes.DialectRevision

	// Determine whether signing is required
	mode := uint16(s.securityMode)
	if mode&SecurityModeSigningEnabled > 0 {
		if mode&SecurityModeSigningRequired > 0 {
			s.IsSigningRequired = true
		} else {
			s.IsSigningRequired = false
		}
	} else {
		s.IsSigningRequired = false
	}

	s.Debug("Sending SessionSetup1 request", nil)
	ssreq, err := s.NewSessionSetup1Req()
	if err != nil {
		s.Debug("", err)
		return err
	}
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err = encoder.Marshal(ssreq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	buf, err = s.send(ssreq)
	if err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	s.Debug("Unmarshalling SessionSetup1 response", nil)
	if err := encoder.Unmarshal(buf, &ssres); err != nil {
		s.Debug("", err)
		return err
	}

	challenge := ntlmssp.NewChallenge()
	resp := ssres.SecurityBlob
	if err := encoder.Unmarshal(resp.ResponseToken, &challenge); err != nil {
		s.Debug("", err)
		return err
	}

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status, _ := StatusMap[negRes.Header.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	s.sessionID = ssres.Header.SessionID

	s.Debug("Sending SessionSetup2 request", nil)
	ss2req, err := s.NewSessionSetup2Req()
	if err != nil {
		s.Debug("", err)
		return err
	}

	var auth ntlmssp.Authenticate
	if s.options.Hash != "" {
		// Hash present, use it for auth
		s.Debug("Performing hash-based authentication", nil)
		auth = ntlmssp.NewAuthenticateHash(s.options.Domain, s.options.User, s.options.Workstation, s.options.Hash, challenge)
	} else {
		// No hash, use password
		s.Debug("Performing password-based authentication", nil)
		auth = ntlmssp.NewAuthenticatePass(s.options.Domain, s.options.User, s.options.Workstation, s.options.Password, challenge)
	}

	responseToken, err := encoder.Marshal(auth)
	if err != nil {
		s.Debug("", err)
		return err
	}
	resp2 := ss2req.SecurityBlob
	resp2.ResponseToken = responseToken
	ss2req.SecurityBlob = resp2
	ss2req.Header.Credits = 127
	buf, err = encoder.Marshal(ss2req)
	if err != nil {
		s.Debug("", err)
		return err
	}

	buf, err = s.send(ss2req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	s.Debug("Unmarshalling SessionSetup2 response", nil)
	var authResp Header
	if err := encoder.Unmarshal(buf, &authResp); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	if authResp.Status != StatusOk {
		status, _ := StatusMap[authResp.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	s.IsAuthenticated = true

	s.Debug("Completed NegotiateProtocol and SessionSetup", nil)
	return nil
}

func (s *Session) TreeConnect(name string) error {
	s.Debug("Sending TreeConnect request ["+name+"]", nil)
	req, err := s.NewTreeConnectReq(name)
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err := s.send(req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	var res TreeConnectRes
	s.Debug("Unmarshalling TreeConnect response ["+name+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if res.Header.Status != StatusOk {
		return errors.New("Failed to connect to tree: " + StatusMap[res.Header.Status])
	}
	s.trees[name] = res.Header.TreeID

	s.Debug("Completed TreeConnect ["+name+"]", nil)
	return nil
}

func (s *Session) TreeDisconnect(name string) error {

	var (
		treeid    uint32
		pathFound bool
	)
	for k, v := range s.trees {
		if k == name {
			treeid = v
			pathFound = true
			break
		}
	}

	if !pathFound {
		err := errors.New("Unable to find tree path for disconnect")
		s.Debug("", err)
		return err
	}

	s.Debug("Sending TreeDisconnect request ["+name+"]", nil)
	req, err := s.NewTreeDisconnectReq(treeid)
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err := s.send(req)
	if err != nil {
		s.Debug("", err)
		return err
	}
	s.Debug("Unmarshalling TreeDisconnect response for ["+name+"]", nil)
	var res TreeDisconnectRes
	if err := encoder.Unmarshal(buf, &res); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	if res.Header.Status != StatusOk {
		return errors.New("Failed to disconnect from tree: " + StatusMap[res.Header.Status])
	}
	delete(s.trees, name)

	s.Debug("TreeDisconnect completed ["+name+"]", nil)
	return nil
}

func (s *Session) Close() {
	s.Debug("Closing session", nil)
	for k, _ := range s.trees {
		s.TreeDisconnect(k)
	}
	s.Debug("Closing TCP connection", nil)
	s.conn.Close()
	s.Debug("Session close completed", nil)
}

func (s *Session) send(req interface{}) (res []byte, err error) {
	buf, err := encoder.Marshal(req)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		s.Debug("", err)
		return
	}

	rw := bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		s.Debug("", err)
		return
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		s.Debug("", err)
		return
	}
	if size > 0x00FFFFFF {
		return nil, errors.New("Invalid NetBIOS Session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}
	if uint32(l) != size {
		return nil, errors.New("Message size invalid")
	}

	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, errors.New("Protocol Not Implemented")
	case ProtocolSmb2:
	}

	s.messageID++
	return data, nil
}
