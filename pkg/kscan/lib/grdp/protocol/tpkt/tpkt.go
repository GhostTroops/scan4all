package tpkt

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/core"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/emission"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/glog"
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/protocol/nla"
)

// take idea from https://github.com/Madnikulin50/gordp

/**
 * Type of tpkt packet
 * Fastpath is use to shortcut RDP stack
 * @see http://msdn.microsoft.com/en-us/library/cc240621.aspx
 * @see http://msdn.microsoft.com/en-us/library/cc240589.aspx
 */
const (
	FASTPATH_ACTION_FASTPATH = 0x0
	FASTPATH_ACTION_X224     = 0x3
)

/**
 * TPKT layer of rdp stack
 */
type TPKT struct {
	emission.Emitter
	Conn             *core.SocketLayer
	ntlm             *nla.NTLMv2
	secFlag          byte
	lastShortLength  int
	fastPathListener core.FastPathListener
	ntlmSec          *nla.NTLMv2Security
}

func New(s *core.SocketLayer, ntlm *nla.NTLMv2) *TPKT {
	t := &TPKT{
		Emitter: *emission.NewEmitter(),
		Conn:    s,
		secFlag: 0,
		ntlm:    ntlm}
	core.StartReadBytes(2, s, t.recvHeader)
	return t
}

func (t *TPKT) StartTLS() error {
	return t.Conn.StartTLS()
}

func (t *TPKT) StartNLA() error {
	err := t.StartTLS()
	if err != nil {
		glog.Info("start tls failed", err)
		return err
	}
	req := nla.EncodeDERTRequest([]nla.Message{t.ntlm.GetNegotiateMessage()}, nil, nil)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send NegotiateMessage", err)
		return err
	}

	resp := make([]byte, 1024)
	n, err := t.Conn.Read(resp)
	if err != nil {
		return fmt.Errorf("read %s", err)
	} else {
		glog.Debug("StartNLA Read success")
	}
	return t.recvChallenge(resp[:n])
}

func (t *TPKT) recvChallenge(data []byte) error {
	glog.Debug("recvChallenge", hex.EncodeToString(data))
	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return err
	}
	glog.Debugf("tsreq:%+v", tsreq)
	// get pubkey
	pubkey, err := t.Conn.TlsPubKey()
	glog.Debugf("pubkey=%+v", pubkey)

	authMsg, ntlmSec := t.ntlm.GetAuthenticateMessage(tsreq.NegoTokens[0].Data)
	t.ntlmSec = ntlmSec

	encryptPubkey := ntlmSec.GssEncrypt(pubkey)
	req := nla.EncodeDERTRequest([]nla.Message{authMsg}, nil, encryptPubkey)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return err
	}
	resp := make([]byte, 1024)
	n, err := t.Conn.Read(resp)
	if err != nil {
		glog.Error("Read:", err)
		return fmt.Errorf("read %s", err)
	} else {
		glog.Debug("recvChallenge Read success")
	}
	return t.recvPubKeyInc(resp[:n])
}

func (t *TPKT) recvPubKeyInc(data []byte) error {
	glog.Debug("recvPubKeyInc", hex.EncodeToString(data))
	tsreq, err := nla.DecodeDERTRequest(data)
	if err != nil {
		glog.Info("DecodeDERTRequest", err)
		return err
	}
	glog.Debug("PubKeyAuth:", tsreq.PubKeyAuth)
	//ignore
	//pubkey := t.ntlmSec.GssDecrypt([]byte(tsreq.PubKeyAuth))
	domain, username, password := t.ntlm.GetEncodedCredentials()
	credentials := nla.EncodeDERTCredentials(domain, username, password)
	authInfo := t.ntlmSec.GssEncrypt(credentials)
	req := nla.EncodeDERTRequest(nil, authInfo, nil)
	_, err = t.Conn.Write(req)
	if err != nil {
		glog.Info("send AuthenticateMessage", err)
		return err
	}

	return nil
}

func (t *TPKT) Read(b []byte) (n int, err error) {
	return t.Conn.Read(b)
}

func (t *TPKT) Write(data []byte) (n int, err error) {
	buff := &bytes.Buffer{}
	core.WriteUInt8(FASTPATH_ACTION_X224, buff)
	core.WriteUInt8(0, buff)
	core.WriteUInt16BE(uint16(len(data)+4), buff)
	buff.Write(data)
	glog.Debug("tpkt Write", hex.EncodeToString(buff.Bytes()))
	return t.Conn.Write(buff.Bytes())
}

func (t *TPKT) Close() error {
	return t.Conn.Close()
}

func (t *TPKT) SetFastPathListener(f core.FastPathListener) {
	t.fastPathListener = f
}

func (t *TPKT) SendFastPath(secFlag byte, data []byte) (n int, err error) {
	buff := &bytes.Buffer{}
	core.WriteUInt8(FASTPATH_ACTION_FASTPATH|((secFlag&0x3)<<6), buff)
	core.WriteUInt16BE(uint16(len(data)+3)|0x8000, buff)
	buff.Write(data)
	glog.Debug("TPTK SendFastPath", hex.EncodeToString(buff.Bytes()))
	return t.Conn.Write(buff.Bytes())
}

func (t *TPKT) recvHeader(s []byte, err error) {
	glog.Debug("tpkt recvHeader", hex.EncodeToString(s), err)
	if err != nil {
		t.Emit("error", err)
		return
	}
	r := bytes.NewReader(s)
	version, _ := core.ReadUInt8(r)
	if version == FASTPATH_ACTION_X224 {
		glog.Debug("tptk recvHeader FASTPATH_ACTION_X224, wait for recvExtendedHeader")
		core.StartReadBytes(2, t.Conn, t.recvExtendedHeader)
	} else {
		t.secFlag = (version >> 6) & 0x3
		length, _ := core.ReadUInt8(r)
		t.lastShortLength = int(length)
		if t.lastShortLength&0x80 != 0 {
			core.StartReadBytes(1, t.Conn, t.recvExtendedFastPathHeader)
		} else {
			core.StartReadBytes(t.lastShortLength-2, t.Conn, t.recvFastPath)
		}
	}
}

func (t *TPKT) recvExtendedHeader(s []byte, err error) {
	glog.Debug("tpkt recvExtendedHeader", hex.EncodeToString(s), err)
	if err != nil {
		return
	}
	r := bytes.NewReader(s)
	size, _ := core.ReadUint16BE(r)
	glog.Debug("tpkt wait recvData:", size)
	core.StartReadBytes(int(size-4), t.Conn, t.recvData)
}

func (t *TPKT) recvData(s []byte, err error) {
	glog.Debug("tpkt recvData", hex.EncodeToString(s), err)
	if err != nil {
		return
	}
	t.Emit("data", s)
	core.StartReadBytes(2, t.Conn, t.recvHeader)
}

func (t *TPKT) recvExtendedFastPathHeader(s []byte, err error) {
	glog.Debug("tpkt recvExtendedFastPathHeader", hex.EncodeToString(s))
	r := bytes.NewReader(s)
	rightPart, err := core.ReadUInt8(r)
	if err != nil {
		glog.Error("TPTK recvExtendedFastPathHeader", err)
		return
	}

	leftPart := t.lastShortLength & ^0x80
	packetSize := (leftPart << 8) + int(rightPart)
	core.StartReadBytes(packetSize-3, t.Conn, t.recvFastPath)
}

func (t *TPKT) recvFastPath(s []byte, err error) {
	glog.Debug("tpkt recvFastPath")
	if err != nil {
		return
	}

	t.fastPathListener.RecvFastPath(t.secFlag, s)
	core.StartReadBytes(2, t.Conn, t.recvHeader)
}
