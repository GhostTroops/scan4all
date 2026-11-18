package giop

import (
	"bytes"
	"encoding/binary"
)

type RebindRequest struct {
	Header             *Header
	RequestId          []byte // 4
	ResponseFlags      []byte // 1
	_reserved1         []byte // 3
	TargetAddress      []byte // 2
	_reserved2         []byte // 2
	_keyAddressLength  []byte // 4
	KeyAddress         []byte // _keyAddressLength
	_operationLength   []byte // 4
	RequestOperation   []byte // _operationLength
	_reserved3         []byte // 2
	ServiceContextList *ServiceContextList
	StubData           []byte // no limit
}

// GetMessageSize
// get size from a GIOP struct
func (r *RebindRequest) GetMessageSize() int {
	total := 0
	// RequestID
	total += 4
	// ResponseFlags
	total += 1
	// _reserved1
	total += 3
	// TargetAddress
	total += 2
	// _reserved2
	total += 2
	// _keyAddressLength
	total += 4
	// KeyAddress
	total += len(r.KeyAddress)
	// _operationLength
	total += 4
	// RequestOperation
	total += len(r.RequestOperation)
	// _reserved3
	total += 2
	// ServiceContext length
	total += 4
	slu := binary.BigEndian.Uint32(r.ServiceContextList.SequenceLength)
	sl := int(slu)
	// ServiceContext
	for i := 0; i < sl; i++ {
		sc := r.ServiceContextList.ServiceContext[i]
		total += sc.encodedSize()
	}
	// StubData
	total += len(r.StubData)
	return total
}

// Bytes
// get bytes data from a GIOP struct
func (r *RebindRequest) Bytes() []byte {
	buf := &bytes.Buffer{}

	r._reserved1 = []byte{0x00, 0x00, 0x00}
	r._reserved2 = []byte{0x00, 0x00}
	r._reserved3 = []byte{0x00, 0x00}

	buf.Write(r.Header.Magic)
	buf.Write(r.Header.MajorVersion)
	buf.Write(r.Header.MinorVersion)
	buf.Write(r.Header.MessageFlags)
	buf.Write(r.Header.MessageType)
	sizeByte := make([]byte, 4)
	size := r.GetMessageSize()
	binary.BigEndian.PutUint32(sizeByte, uint32(size))
	buf.Write(sizeByte)

	buf.Write(r.RequestId)
	buf.Write(r.ResponseFlags)
	buf.Write(r._reserved1)
	buf.Write(r.TargetAddress)
	buf.Write(r._reserved2)
	keyLen := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLen, uint32(len(r.KeyAddress)))
	buf.Write(keyLen)
	buf.Write(r.KeyAddress)
	opLen := make([]byte, 4)
	binary.BigEndian.PutUint32(opLen, uint32(len(r.RequestOperation)+1))
	buf.Write(opLen)
	buf.Write(r.RequestOperation)
	buf.Write(r._reserved3)

	slu := binary.BigEndian.Uint32(r.ServiceContextList.SequenceLength)
	sl := int(slu)
	buf.Write(r.ServiceContextList.SequenceLength)
	for i := 0; i < sl; i++ {
		sc := r.ServiceContextList.ServiceContext[i]
		buf.Write(sc.VSCID)
		buf.Write(sc.SCID)
		cdLen := make([]byte, 4)
		binary.BigEndian.PutUint32(cdLen, uint32(sc.contextDataLength()))
		buf.Write(cdLen)
		buf.Write(sc.Endianness)
		buf.Write(sc.Data)
	}
	buf.Write(r.StubData)

	return buf.Bytes()
}
