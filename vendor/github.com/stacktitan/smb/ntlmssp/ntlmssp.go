package ntlmssp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"encoding/hex"

	"github.com/stacktitan/smb/smb/encoder"
)

const Signature = "NTLMSSP\x00"

const (
	_ uint32 = iota
	TypeNtLmNegotiate
	TypeNtLmChallenge
	TypeNtLmAuthenticate
)

const (
	FlgNegUnicode uint32 = 1 << iota
	FlgNegOEM
	FlgNegRequestTarget
	FlgNegReserved10
	FlgNegSign
	FlgNegSeal
	FlgNegDatagram
	FlgNegLmKey
	FlgNegReserved9
	FlgNegNtLm
	FlgNegReserved8
	FlgNegAnonymous
	FlgNegOEMDomainSupplied
	FlgNegOEMWorkstationSupplied
	FlgNegReserved7
	FlgNegAlwaysSign
	FlgNegTargetTypeDomain
	FlgNegTargetTypeServer
	FlgNegReserved6
	FlgNegExtendedSessionSecurity
	FlgNegIdentify
	FlgNegReserved5
	FlgNegRequestNonNtSessionKey
	FlgNegTargetInfo
	FlgNegReserved4
	FlgNegVersion
	FlgNegReserved3
	FlgNegReserved2
	FlgNegReserved1
	FlgNeg128
	FlgNegKeyExch
	FlgNeg56
)

const (
	MsvAvEOL uint16 = iota
	MsvAvNbComputerName
	MsvAvNbDomainName
	MsvAvDnsComputerName
	MsvAvDnsDomainName
	MsvAvDnsTreeName
	MsvAvFlags
	MsvAvTimestamp
	MsvAvSingleHost
	MsvAvTargetName
	MsvChannelBindings
)

type Header struct {
	Signature   []byte `smb:"fixed:8"`
	MessageType uint32
}

type Negotiate struct {
	Header
	NegotiateFlags          uint32
	DomainNameLen           uint16 `smb:"len:DomainName"`
	DomainNameMaxLen        uint16 `smb:"len:DomainName"`
	DomainNameBufferOffset  uint32 `smb:"offset:DomainName"`
	WorkstationLen          uint16 `smb:"len:Workstation"`
	WorkstationMaxLen       uint16 `smb:"len:Workstation"`
	WorkstationBufferOffset uint32 `smb:"offset:Workstation"`
	DomainName              []byte
	Workstation             []byte
}

type Challenge struct {
	Header
	TargetNameLen          uint16 `smb:"len:TargetName"`
	TargetNameMaxLen       uint16 `smb:"len:TargetName"`
	TargetNameBufferOffset uint32 `smb:"offset:TargetName"`
	NegotiateFlags         uint32
	ServerChallenge        uint64
	Reserved               uint64
	TargetInfoLen          uint16 `smb:"len:TargetInfo"`
	TargetInfoMaxLen       uint16 `smb:"len:TargetInfo"`
	TargetInfoBufferOffset uint32 `smb:"offset:TargetInfo"`
	Version                uint64
	TargetName             []byte
	TargetInfo             *AvPairSlice
}

type Authenticate struct {
	Header
	LmChallengeResponseLen                uint16 `smb:"len:LmChallengeResponse"`
	LmChallengeResponseMaxLen             uint16 `smb:"len:LmChallengeResponse"`
	LmChallengeResponseBufferOffset       uint32 `smb:"offset:LmChallengeResponse"`
	NtChallengeResponseLen                uint16 `smb:"len:NtChallengeResponse"`
	NtChallengeResponseMaxLen             uint16 `smb:"len:NtChallengeResponse"`
	NtChallengResponseBufferOffset        uint32 `smb:"offset:NtChallengeResponse"`
	DomainNameLen                         uint16 `smb:"len:DomainName"`
	DomainNameMaxLen                      uint16 `smb:"len:DomainName"`
	DomainNameBufferOffset                uint32 `smb:"offset:DomainName"`
	UserNameLen                           uint16 `smb:"len:UserName"`
	UserNameMaxLen                        uint16 `smb:"len:UserName"`
	UserNameBufferOffset                  uint32 `smb:"offset:UserName"`
	WorkstationLen                        uint16 `smb:"len:Workstation"`
	WorkstationMaxLen                     uint16 `smb:"len:Workstation"`
	WorkstationBufferOffset               uint32 `smb:"offset:Workstation"`
	EncryptedRandomSessionKeyLen          uint16 `smb:"len:EncryptedRandomSessionKey"`
	EncryptedRandomSessionKeyMaxLen       uint16 `smb:"len:EncryptedRandomSessionKey"`
	EncryptedRandomSessionKeyBufferOffset uint32 `smb:"offset:EncryptedRandomSessionKey"`
	NegotiateFlags                        uint32
	DomainName                            []byte `smb:"unicode"`
	UserName                              []byte `smb:"unicode"`
	Workstation                           []byte `smb:"unicode"`
	EncryptedRandomSessionKey             []byte
	LmChallengeResponse                   []byte
	NtChallengeResponse                   []byte
}

type AvPair struct {
	AvID  uint16
	AvLen uint16 `smb:"len:Value"`
	Value []byte
}
type AvPairSlice []AvPair

func (p AvPair) Size() uint64 {
	return uint64(binary.Size(p.AvID) + binary.Size(p.AvLen) + int(p.AvLen))
}

func (s *AvPairSlice) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	for _, pair := range *s {
		buf, err := encoder.Marshal(pair)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (s *AvPairSlice) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	slice := []AvPair{}
	l, ok := meta.Lens[meta.CurrField]
	if !ok {
		return errors.New(fmt.Sprintf("Cannot unmarshal field '%s'. Missing length\n", meta.CurrField))
	}
	o, ok := meta.Offsets[meta.CurrField]
	if !ok {
		return errors.New(fmt.Sprintf("Cannot unmarshal field '%s'. Missing offset\n", meta.CurrField))
	}
	for i := l; i > 0; {
		var avPair AvPair
		err := encoder.Unmarshal(meta.ParentBuf[o:o+i], &avPair)
		if err != nil {
			return err
		}
		slice = append(slice, avPair)
		size := avPair.Size()
		o += size
		i -= size
	}
	*s = slice
	return nil
}

func NewNegotiate(domainName, workstation string) Negotiate {
	return Negotiate{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmNegotiate,
		},
		NegotiateFlags: FlgNeg56 |
			FlgNeg128 |
			FlgNegTargetInfo |
			FlgNegExtendedSessionSecurity |
			FlgNegOEMDomainSupplied |
			FlgNegNtLm |
			FlgNegRequestTarget |
			FlgNegUnicode,
		DomainNameLen:           0,
		DomainNameMaxLen:        0,
		DomainNameBufferOffset:  0,
		WorkstationLen:          0,
		WorkstationMaxLen:       0,
		WorkstationBufferOffset: 0,
		DomainName:              []byte(domainName),
		Workstation:             []byte(workstation),
	}
}

func NewChallenge() Challenge {
	return Challenge{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmChallenge,
		},
		TargetNameLen:          0,
		TargetNameMaxLen:       0,
		TargetNameBufferOffset: 0,
		NegotiateFlags: FlgNeg56 |
			FlgNeg128 |
			FlgNegVersion |
			FlgNegTargetInfo |
			FlgNegExtendedSessionSecurity |
			FlgNegTargetTypeServer |
			FlgNegNtLm |
			FlgNegRequestTarget |
			FlgNegUnicode,
		ServerChallenge:        0,
		Reserved:               0,
		TargetInfoLen:          0,
		TargetInfoMaxLen:       0,
		TargetInfoBufferOffset: 0,
		Version:                0,
		TargetName:             []byte{},
		TargetInfo:             new(AvPairSlice),
	}
}

func NewAuthenticatePass(domain, user, workstation, password string, c Challenge) Authenticate {
	// Assumes domain, user, and workstation are not unicode
	nthash := Ntowfv2(password, user, domain)
	lmhash := Lmowfv2(password, user, domain)
	return newAuthenticate(domain, user, workstation, nthash, lmhash, c)
}

func NewAuthenticateHash(domain, user, workstation, hash string, c Challenge) Authenticate {
	// Assumes domain, user, and workstation are not unicode
	buf := make([]byte, len(hash)/2)
	hex.Decode(buf, []byte(hash))
	return newAuthenticate(domain, user, workstation, buf, buf, c)
}

func newAuthenticate(domain, user, workstation string, nthash, lmhash []byte, c Challenge) Authenticate {
	// Assumes domain, user, and workstation are not unicode
	var timestamp []byte
	for k, av := range *c.TargetInfo {
		if av.AvID == MsvAvTimestamp {
			timestamp = (*c.TargetInfo)[k].Value
		}
	}
	if timestamp == nil {
		// Credit to https://github.com/Azure/go-ntlmssp/blob/master/unicode.go for logic
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}

	clientChallenge := make([]byte, 8)
	rand.Reader.Read(clientChallenge)
	serverChallenge := make([]byte, 8)
	w := bytes.NewBuffer(make([]byte, 0))
	binary.Write(w, binary.LittleEndian, c.ServerChallenge)
	serverChallenge = w.Bytes()
	w = bytes.NewBuffer(make([]byte, 0))
	for _, av := range *c.TargetInfo {
		binary.Write(w, binary.LittleEndian, av.AvID)
		binary.Write(w, binary.LittleEndian, av.AvLen)
		binary.Write(w, binary.LittleEndian, av.Value)
	}
	response := ComputeResponseNTLMv2(nthash, lmhash, clientChallenge, serverChallenge, timestamp, w.Bytes())

	h := hmac.New(md5.New, lmhash)
	h.Write(append(serverChallenge, clientChallenge...))
	lmChallengeResponse := h.Sum(nil)
	lmChallengeResponse = append(lmChallengeResponse, clientChallenge...)

	return Authenticate{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmAuthenticate,
		},
		DomainName:  encoder.ToUnicode(domain),
		UserName:    encoder.ToUnicode(user),
		Workstation: encoder.ToUnicode(workstation),
		NegotiateFlags: FlgNeg56 |
			FlgNeg128 |
			FlgNegTargetInfo |
			FlgNegExtendedSessionSecurity |
			FlgNegOEMDomainSupplied |
			FlgNegNtLm |
			FlgNegRequestTarget |
			FlgNegUnicode,
		NtChallengeResponse: response,
		LmChallengeResponse: lmChallengeResponse,
	}
}
