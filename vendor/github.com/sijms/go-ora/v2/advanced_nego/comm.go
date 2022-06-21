package advanced_nego

import (
	"errors"
	"github.com/sijms/go-ora/v2/network"
)

type AdvancedNegoComm struct {
	session *network.Session
}

func newComm(session *network.Session) *AdvancedNegoComm {
	return &AdvancedNegoComm{session: session}
}

func (comm *AdvancedNegoComm) writePacketHeader(length, _type int) {
	comm.session.PutInt(length, 2, true, false)
	comm.session.PutInt(_type, 2, true, false)
}

func (comm *AdvancedNegoComm) readPacketHeader(_type int) (length int, err error) {
	length, err = comm.session.GetInt(2, false, true)
	if err != nil {
		return
	}
	receivedType, err := comm.session.GetInt(2, false, true)
	if err != nil {
		return 0, err
	}
	if receivedType != _type {
		err = errors.New("advanced negotiation error: received type is not as stored type")
		return
	}
	err = comm.validatePacketHeader(length, receivedType)
	return
}

func (comm *AdvancedNegoComm) validatePacketHeader(length, _type int) error {
	if _type < 0 || _type > 7 {
		return errors.New("advanced negotiation error: cannot validate packet header")
	}
	switch _type {
	case 0, 1:
		break
	case 2:
		if length > 1 {
			return errors.New("advanced negotiation error: cannot validate packet header")
		}
	case 3:
		fallthrough
	case 6:
		if length > 2 {
			return errors.New("advanced negotiation error: cannot validate packet header")
		}
	case 4:
		fallthrough
	case 5:
		if length > 4 {
			return errors.New("advanced negotiation error: cannot validate packet header")
		}
	case 7:
		if length < 10 {
			return errors.New("advanced negotiation error: cannot validate packet header")
		}
	default:
		return errors.New("advanced negotiation error: cannot validate packet header")
	}
	return nil
}

func (comm *AdvancedNegoComm) readUB1() (number uint8, err error) {
	_, err = comm.readPacketHeader(2)
	number, err = comm.session.GetByte()
	return
}
func (comm *AdvancedNegoComm) writeUB1(number uint8) {
	comm.writePacketHeader(1, 2)
	comm.session.PutBytes(number)
}

func (comm *AdvancedNegoComm) readUB2() (number int, err error) {
	_, err = comm.readPacketHeader(3)
	number, err = comm.session.GetInt(2, false, true)
	return
}

func (comm *AdvancedNegoComm) writeUB2(number int) {
	comm.writePacketHeader(2, 3)
	comm.session.PutInt(number, 2, true, false)
}

func (comm *AdvancedNegoComm) readUB4() (number int, err error) {
	_, err = comm.readPacketHeader(4)
	number, err = comm.session.GetInt(4, false, true)
	return
}

func (comm *AdvancedNegoComm) writeUB4(number int) {
	comm.writePacketHeader(4, 4)
	comm.session.PutInt(number, 4, true, false)
}

func (comm *AdvancedNegoComm) readString() (string, error) {
	stringLen, err := comm.readPacketHeader(0)
	if err != nil {
		return "", err
	}
	resultBytes, err := comm.session.GetBytes(stringLen)
	if err != nil {
		return "", err
	}
	return string(resultBytes), nil
}

func (comm *AdvancedNegoComm) writeString(input string) {
	comm.writePacketHeader(len(input), 0)
	comm.session.PutBytes([]byte(input)...)
}

func (comm *AdvancedNegoComm) writeStatus(status int) {
	comm.writePacketHeader(2, 6)
	comm.session.PutInt(status, 2, true, false)
}

func (comm *AdvancedNegoComm) readStatus() (status int, err error) {
	_, err = comm.readPacketHeader(6)
	if err != nil {
		return
	}
	status, err = comm.session.GetInt(2, false, true)
	return
}
func (comm *AdvancedNegoComm) readVersion() (uint32, error) {
	_, err := comm.readPacketHeader(5)
	if err != nil {
		return 0, err
	}
	version, err := comm.session.GetInt(4, false, true)
	return uint32(version), err
}

func (comm *AdvancedNegoComm) writeVersion(version uint32) {
	comm.writePacketHeader(4, 5)
	comm.session.PutInt(version, 4, true, false)
}

func (comm *AdvancedNegoComm) readBytes() ([]byte, error) {
	length, err := comm.readPacketHeader(1)
	if err != nil {
		return nil, err
	}
	return comm.session.GetBytes(length)
}

func (comm *AdvancedNegoComm) writeBytes(input []byte) {
	comm.writePacketHeader(len(input), 1)
	comm.session.PutBytes(input...)
}

func (comm *AdvancedNegoComm) readUB2Array() ([]int, error) {
	_, err := comm.readPacketHeader(1)
	if err != nil {
		return nil, err
	}
	num1, err := comm.session.GetInt64(4, false, true)
	if err != nil {
		return nil, err
	}
	num2, err := comm.session.GetInt(2, false, true)
	if err != nil {
		return nil, err
	}
	size, err := comm.session.GetInt(4, false, true)
	if err != nil {
		return nil, err
	}
	if num1 != 0xDEADBEEF || num2 != 3 {
		return nil, errors.New("advanced negotiation error: reading supervisor service")
	}
	output := make([]int, size)
	for i := 0; i < size; i++ {
		output[i], err = comm.session.GetInt(2, false, true)
		if err != nil {
			return nil, err
		}
	}
	return output, nil
}

func (comm *AdvancedNegoComm) writeUB2Array(input []int) {
	comm.writePacketHeader(10+len(input)*2, 1)
	comm.session.PutInt(uint64(0xDEADBEEF), 4, true, false)
	comm.session.PutInt(3, 2, true, false)
	comm.session.PutInt(len(input), 4, true, false)
	for i := 0; i < len(input); i++ {
		comm.session.PutInt(input[i], 2, true, false)
	}
}
