package network

import (
	"encoding/binary"
	"regexp"
	"strconv"
	"strings"
)

type RefusePacket struct {
	packet Packet
	//dataOffset uint16
	//Len uint16
	//packetType PacketType
	//Flag uint8
	Err          OracleError
	SystemReason uint8
	UserReason   uint8
	message      string
}

func (pck *RefusePacket) bytes() []byte {
	output := pck.packet.bytes()
	output[8] = pck.SystemReason
	output[9] = pck.UserReason
	data := []byte(pck.message)
	binary.BigEndian.PutUint16(output[10:], uint16(len(data)))
	output = append(output, data...)
	return output
}

func (pck *RefusePacket) getPacketType() PacketType {
	return pck.packet.packetType
}
func newRefusePacketFromData(packetData []byte) *RefusePacket {
	if len(packetData) < 12 {
		return nil
	}
	dataLen := binary.BigEndian.Uint16(packetData[10:])
	var message string
	if uint16(len(packetData)) >= 12+dataLen {
		message = string(packetData[12 : 12+dataLen])
	}

	return &RefusePacket{
		packet: Packet{
			dataOffset: 12,
			length:     uint32(binary.BigEndian.Uint16(packetData)),
			packetType: PacketType(packetData[4]),
			flag:       0,
		},
		SystemReason: packetData[9],
		UserReason:   packetData[8],
		message:      message,
	}
}

func (rf *RefusePacket) extractErrCode() {
	rf.Err.ErrCode = 12564
	rf.Err.ErrMsg = "ORA-12564: TNS connection refused"
	if len(rf.message) == 0 {
		return
	}
	r, err := regexp.Compile(`\(\s*ERR\s*=\s*([0-9]+)\s*\)`)
	if err != nil {
		return
	}
	msg := strings.ToUpper(rf.message)
	matches := r.FindStringSubmatch(msg)
	if len(matches) != 2 {
		return
	}
	strErrCode := matches[1]
	errCode, err := strconv.ParseInt(strErrCode, 10, 32)
	if err == nil {
		rf.Err.ErrCode = int(errCode)
		rf.Err.translate()
		return
	}
	r, err = regexp.Compile(`\(\s*ERROR\s*=([A-Z0-9=\(\)]+)`)
	if err != nil {
		return
	}
	matches = r.FindStringSubmatch(msg)
	if len(matches) != 2 {
		return
	}
	codeStr := matches[1]
	r, err = regexp.Compile(`CODE\s*=\s*([0-9]+)`)
	if err != nil {
		return
	}
	matches = r.FindStringSubmatch(codeStr)
	if len(matches) != 2 {
		return
	}
	strErrCode = matches[1]
	errCode, err = strconv.ParseInt(strErrCode, 10, 32)
	if err == nil {
		rf.Err.ErrCode = int(errCode)
		rf.Err.translate()
	}
	//str := "(DESCRIPTION=(TMP=)(VSNNUM=186647552)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))"
}
