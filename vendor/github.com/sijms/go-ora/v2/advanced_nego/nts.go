package advanced_nego

import (
	"encoding/binary"
	"errors"
	"github.com/sijms/go-ora/v2/advanced_nego/ntlmssp"
)

type NTSAuthInterface interface {
	NewNegotiateMessage(domain, machine string) ([]byte, error)
	ProcessChallenge(chaMsgData []byte, user, password string) ([]byte, error)
}

var NTSAuth NTSAuthInterface = &NTSAuthDefault{}

type NTSAuthDefault struct{}

type NTSAuthHash struct {
	NTSAuthDefault
}

func (nts *NTSAuthDefault) NewNegotiateMessage(domain, machine string) ([]byte, error) {
	return ntlmssp.NewNegotiateMessage(domain, machine)
}
func (nts *NTSAuthDefault) ProcessChallenge(chaMsgData []byte, user, password string) ([]byte, error) {
	return ntlmssp.ProcessChallenge(chaMsgData, user, password)
}
func (nts *NTSAuthHash) ProcessChallenge(chaMsgData []byte, user, password string) ([]byte, error) {
	return ntlmssp.ProcessChallengeWithHash(chaMsgData, user, password)
}
func createNTSNegoPacket(domain, machine string) ([]byte, error) {
	var packetData = []byte{
		0, 1, 0, 7, 0, 0, 0, 0, 0, 4, 0, 5, 2, 0, 0, 0,
		0, 4, 0, 4, 0, 0, 0, 9, 0, 4, 0, 4, 0, 0, 0, 2,
		0, 20, 0, 1, 2, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 0,
		0, 4, 0, 1, 55, 0, 0, 0, 0, 55, 0, 1,
	}
	var ret = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x99, 0x0B, 0x20, 0x02, 0x00, 0x00, 0x01, 0x00}
	ret = append(ret, packetData...)
	sspiOffset := len(ret)
	if NTSAuth == nil {
		return nil, errors.New("NTS authentication manager cannot be nil")
	}
	negoData, err := NTSAuth.NewNegotiateMessage(domain, machine)
	if err != nil {
		return nil, err
	}
	ret = append(ret, negoData...)
	temp := make([]byte, 2)
	binary.BigEndian.PutUint16(temp, uint16(len(ret)))
	for x := 0; x < 2; x++ {
		ret[x+4] = temp[x]
	}
	temp2 := make([]byte, 4)
	ntsDataLen := len(ret) - sspiOffset
	binary.LittleEndian.PutUint32(temp2, uint32(ntsDataLen))
	binary.BigEndian.PutUint16(temp, uint16(ntsDataLen))
	for x := 0; x < 4; x++ {
		ret[sspiOffset-8+x] = temp2[x]
	}
	for x := 0; x < 2; x++ {
		ret[sspiOffset-4+x] = temp[x]
	}
	return ret, nil
}
func createNTSAuthPacket(chaMsgData []byte, user, password string) ([]byte, error) {
	var packetData = []byte{
		0, 1, 0, 2, 0, 0, 0, 0, 0, 4,
		0, 1, 55, 0, 0, 0, 0, 55, 0, 1,
	}
	var ret = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x90, 0x0, 0x0, 0x0, 0x0, 0x0, 0x01, 0x0}
	ret = append(ret, packetData...)
	sspiOffset := len(ret)
	if NTSAuth == nil {
		return nil, errors.New("NTS authentication manager cannot be nil")
	}
	authData, err := NTSAuth.ProcessChallenge(chaMsgData, user, password)
	if err != nil {
		return nil, err
	}
	ret = append(ret, authData...)
	temp := make([]byte, 2)
	binary.BigEndian.PutUint16(temp, uint16(len(ret)))
	for x := 0; x < 2; x++ {
		ret[x+4] = temp[x]
	}
	temp2 := make([]byte, 4)
	ntsDataLen := len(ret) - sspiOffset
	binary.LittleEndian.PutUint32(temp2, uint32(ntsDataLen))
	binary.BigEndian.PutUint16(temp, uint16(ntsDataLen))
	for x := 0; x < 4; x++ {
		ret[sspiOffset-8+x] = temp2[x]
	}
	for x := 0; x < 2; x++ {
		ret[sspiOffset-4+x] = temp[x]
	}
	return ret, nil
}
