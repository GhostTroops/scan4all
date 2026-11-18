package giop

import (
	"bytes"
	"encoding/binary"
)

type LocateRequest struct {
	Header            *Header
	RequestId         []byte // 4
	TargetAddress     []byte // 2
	_reserved         []byte // 2
	_keyAddressLength []byte // 4
	KeyAddress        []byte // _keyAddressLength
}

func (l *LocateRequest) getMessageSize() int {
	total := 0
	// RequestID
	total += 4
	// TargetAddress
	total += 2
	// _reserved
	total += 2
	// _keyAddressLength
	total += 4
	// KeyAddress
	total += len(l.KeyAddress)
	return total
}

func (l *LocateRequest) Bytes() []byte {
	buf := &bytes.Buffer{}

	l._reserved = []byte{0x00, 0x00}

	buf.Write(l.Header.Magic)
	buf.Write(l.Header.MajorVersion)
	buf.Write(l.Header.MinorVersion)
	buf.Write(l.Header.MessageFlags)
	buf.Write(l.Header.MessageType)
	sizeByte := make([]byte, 4)
	size := l.getMessageSize()
	binary.BigEndian.PutUint32(sizeByte, uint32(size))
	buf.Write(sizeByte)

	buf.Write(l.RequestId)
	buf.Write(l.TargetAddress)
	buf.Write(l._reserved)
	keyLen := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLen, uint32(len(l.KeyAddress)))
	buf.Write(keyLen)
	buf.Write(l.KeyAddress)

	return buf.Bytes()
}
