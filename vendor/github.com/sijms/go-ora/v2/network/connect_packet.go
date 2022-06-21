package network

import "encoding/binary"

//type ConnectPacket Packet
type ConnectPacket struct {
	packet     Packet
	sessionCtx SessionContext
	buffer     []byte
}

func (pck *ConnectPacket) bytes() []byte {
	output := pck.packet.bytes()
	//binary.BigEndian.PutUint16(output, pck.length)
	//output[4] = uint8(pck.packetType)
	//output[5] = pck.flag
	binary.BigEndian.PutUint16(output[8:], pck.sessionCtx.Version)
	binary.BigEndian.PutUint16(output[10:], pck.sessionCtx.LoVersion)
	binary.BigEndian.PutUint16(output[12:], pck.sessionCtx.Options)
	num := uint16(pck.sessionCtx.SessionDataUnit)
	if pck.sessionCtx.SessionDataUnit > 0xFFFF {
		num = 0xFFFF
	}
	binary.BigEndian.PutUint16(output[14:], num)
	binary.BigEndian.PutUint32(output[58:], pck.sessionCtx.SessionDataUnit)
	num = uint16(pck.sessionCtx.TransportDataUnit)
	if pck.sessionCtx.TransportDataUnit > 0xFFFF {
		num = 0xFFFF
	}
	binary.BigEndian.PutUint16(output[16:], num)
	binary.BigEndian.PutUint32(output[62:], pck.sessionCtx.TransportDataUnit)
	binary.BigEndian.PutUint32(output[66:], 0)
	output[18] = 79
	output[19] = 152
	binary.BigEndian.PutUint16(output[22:], pck.sessionCtx.OurOne)
	binary.BigEndian.PutUint16(output[24:], uint16(len(pck.buffer)))
	binary.BigEndian.PutUint16(output[26:], pck.packet.dataOffset)
	output[32] = pck.sessionCtx.ACFL0
	output[33] = pck.sessionCtx.ACFL1
	if len(pck.buffer) <= 230 {
		output = append(output, pck.buffer...)
	}
	return output

}
func (pck *ConnectPacket) getPacketType() PacketType {
	return pck.packet.packetType
}
func newConnectPacket(sessionCtx SessionContext) *ConnectPacket {
	connectData := sessionCtx.ConnOption.ConnectionData()
	length := uint32(len(connectData))
	if length > 230 {
		length = 0
	}
	length += 70

	sessionCtx.Histone = 1
	sessionCtx.ACFL0 = 1
	sessionCtx.ACFL1 = 1
	//sessionCtx.ACFL0 = 4
	//sessionCtx.ACFL1 = 4

	return &ConnectPacket{
		sessionCtx: sessionCtx,
		packet: Packet{
			dataOffset: 70,
			length:     length,
			packetType: CONNECT,
			flag:       0,
		},
		buffer: []byte(connectData),
	}
}
