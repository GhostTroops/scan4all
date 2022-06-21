package network

import "encoding/binary"

type PacketType uint8

type PacketInterface interface {
	bytes() []byte
	getPacketType() PacketType
}

const (
	CONNECT  PacketType = 1
	ACCEPT   PacketType = 2
	ACK      PacketType = 3
	REFUSE   PacketType = 4
	REDIRECT PacketType = 5
	DATA     PacketType = 6
	NULL     PacketType = 7
	ABORT    PacketType = 9
	RESEND   PacketType = 11
	MARKER   PacketType = 12
	ATTN     PacketType = 13
	CTRL     PacketType = 14
	HIGHEST  PacketType = 19
)

type Packet struct {
	//sessionCtx SessionContext
	dataOffset uint16
	length     uint32
	packetType PacketType
	flag       uint8
	//NSPFSID    int
	//buffer     []byte
	//SID        []byte
}

//const (
//	NSPFSID   = 1
//	NSPFRDS   = 2
//	NSPFRDR   = 4
//	NSPFSRN   = 8
//	NSPFPRB   = 0x10
//	NSPSID_SZ = 0x10
//)

func newPacket(packetData []byte) *Packet {
	return &Packet{
		length:     uint32(binary.BigEndian.Uint16(packetData)),
		packetType: PacketType(packetData[4]),
		flag:       packetData[5],
	}
}

func (pck *Packet) bytes() []byte {
	output := make([]byte, 8)
	if pck.dataOffset > 8 {
		output = append(output, make([]byte, pck.dataOffset-8)...)
	}
	binary.BigEndian.PutUint16(output, uint16(pck.length))
	output[4] = uint8(pck.packetType)
	output[5] = pck.flag
	return output
}
func (pck *Packet) getPacketType() PacketType {
	return pck.packetType
}
