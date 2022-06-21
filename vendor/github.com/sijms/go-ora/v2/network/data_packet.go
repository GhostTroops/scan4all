package network

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type DataPacket struct {
	Packet
	sessionCtx *SessionContext
	dataFlag   uint16
	buffer     []byte
}

func (pck *DataPacket) bytes() []byte {
	output := bytes.Buffer{}
	temp := make([]byte, 0xA)
	if pck.sessionCtx.handshakeComplete && pck.sessionCtx.Version >= 315 {
		binary.BigEndian.PutUint32(temp, pck.length)
	} else {
		binary.BigEndian.PutUint16(temp, uint16(pck.length))
	}
	temp[4] = uint8(pck.packetType)
	temp[5] = pck.flag
	binary.BigEndian.PutUint16(temp[8:], pck.dataFlag)
	output.Write(temp)
	if len(pck.buffer) > 0 {
		output.Write(pck.buffer)
	}
	return output.Bytes()
}

func newDataPacket(initialData []byte, sessionCtx *SessionContext) (*DataPacket, error) {
	var outputData []byte = initialData
	var err error
	if sessionCtx.AdvancedService.HashAlgo != nil {
		hashData := sessionCtx.AdvancedService.HashAlgo.Compute(outputData)
		outputData = append(outputData, hashData...)
	}
	if sessionCtx.AdvancedService.CryptAlgo != nil {
		//outputData = make([]byte, len(outputData))
		//copy(outputData, outputData)
		outputData, err = sessionCtx.AdvancedService.CryptAlgo.Encrypt(outputData)
		if err != nil {
			return nil, err
		}
	}
	if sessionCtx.AdvancedService.HashAlgo != nil || sessionCtx.AdvancedService.CryptAlgo != nil {
		foldingKey := uint8(0)
		outputData = append(outputData, foldingKey)
	}

	return &DataPacket{
		Packet: Packet{
			dataOffset: 0xA,
			length:     uint32(len(outputData)) + 0xA,
			packetType: DATA,
			flag:       0,
		},
		sessionCtx: sessionCtx,
		dataFlag:   0,
		buffer:     outputData,
	}, nil
}

func newDataPacketFromData(packetData []byte, sessionCtx *SessionContext) (*DataPacket, error) {
	if len(packetData) <= 0xA || PacketType(packetData[4]) != DATA {
		return nil, errors.New("Not data packet")
	}
	pck := &DataPacket{
		Packet: Packet{
			dataOffset: 0xA,
			//length:     binary.BigEndian.Uint16(packetData),
			packetType: PacketType(packetData[4]),
			flag:       packetData[5],
		},
		sessionCtx: sessionCtx,
		dataFlag:   binary.BigEndian.Uint16(packetData[8:]),
		buffer:     packetData[10:],
	}
	if sessionCtx.handshakeComplete && sessionCtx.Version >= 315 {
		pck.length = binary.BigEndian.Uint32(packetData)
	} else {
		pck.length = uint32(binary.BigEndian.Uint16(packetData))
	}
	var err error
	if sessionCtx.AdvancedService.CryptAlgo != nil || sessionCtx.AdvancedService.HashAlgo != nil {
		pck.buffer = pck.buffer[:len(pck.buffer)-1]
	}
	if sessionCtx.AdvancedService.CryptAlgo != nil {
		pck.buffer, err = sessionCtx.AdvancedService.CryptAlgo.Decrypt(pck.buffer)
		if err != nil {
			return nil, err
		}
	}
	if sessionCtx.AdvancedService.HashAlgo != nil {
		pck.buffer, err = sessionCtx.AdvancedService.HashAlgo.Validate(pck.buffer)
		if err != nil {
			return nil, err
		}
	}
	return pck, nil
}

//func (pck *DataPacket) Data() []byte {
//	return pck.buffer
//}
