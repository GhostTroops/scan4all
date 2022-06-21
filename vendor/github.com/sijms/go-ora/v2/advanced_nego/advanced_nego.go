package advanced_nego

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
)

var version int = 0xB200200

type AdvNego struct {
	comm        *AdvancedNegoComm
	serviceList []AdvNegoService
}

func NewAdvNego(session *network.Session) (*AdvNego, error) {
	output := &AdvNego{
		comm:        &AdvancedNegoComm{session: session},
		serviceList: make([]AdvNegoService, 5),
	}
	var err error
	output.serviceList[1], err = NewAuthService(output.comm)
	if err != nil {
		return nil, err
	}
	output.serviceList[2], err = NewEncryptService(output.comm)
	if err != nil {
		return nil, err
	}
	output.serviceList[3], err = NewDataIntegrityService(output.comm)
	if err != nil {
		return nil, err
	}
	output.serviceList[4], err = NewSupervisorService(output.comm)
	if err != nil {
		return nil, err
	}
	return output, nil
}
func (nego *AdvNego) readHeader() ([]int, error) {
	num, err := nego.comm.session.GetInt64(4, false, true)
	if err != nil {
		return nil, err
	}
	if num != 0xDEADBEEF {
		return nil, errors.New("advanced negotiation error: during receive header")
	}
	output := make([]int, 4)
	output[0], err = nego.comm.session.GetInt(2, false, true)
	if err != nil {
		return nil, err
	}
	output[1], err = nego.comm.session.GetInt(4, false, true)
	if err != nil {
		return nil, err
	}
	output[2], err = nego.comm.session.GetInt(2, false, true)
	if err != nil {
		return nil, err
	}
	output[3], err = nego.comm.session.GetInt(1, false, true)
	return output, err
}
func (nego *AdvNego) writeHeader(length, servCount int, errFlags uint8) {
	nego.comm.session.PutInt(uint64(0xDEADBEEF), 4, true, false)
	nego.comm.session.PutInt(length, 2, true, false)
	nego.comm.session.PutInt(version, 4, true, false)
	nego.comm.session.PutInt(servCount, 2, true, false)
	nego.comm.session.PutBytes(errFlags)
}
func (nego *AdvNego) readServiceHeader() ([]int, error) {
	output := make([]int, 3)
	var err error
	output[0], err = nego.comm.session.GetInt(2, false, true)
	if err != nil {
		return nil, err
	}
	output[1], err = nego.comm.session.GetInt(2, false, true)
	if err != nil {
		return nil, err
	}
	output[2], err = nego.comm.session.GetInt(4, false, true)
	return output, err
}
func (nego *AdvNego) Read() error {
	header, err := nego.readHeader()
	if err != nil {
		return err
	}
	for i := 0; i < header[2]; i++ {
		serviceHeader, err := nego.readServiceHeader()
		if err != nil {
			return err
		}
		if serviceHeader[2] != 0 {
			return fmt.Errorf("advanced negotiation error: during receive service header: network excpetion: ora-%d", serviceHeader[2])
		}
		err = nego.serviceList[serviceHeader[0]].readServiceData(serviceHeader[1])
		if err != nil {
			return err
		}
		err = nego.serviceList[serviceHeader[0]].validateResponse()
		if err != nil {
			return err
		}
	}
	var authKerberos bool = false
	var authNTS bool = false
	if authServ, ok := nego.serviceList[1].(*authService); ok {
		if authServ.active {
			if authServ.serviceName == "KERBEROS5" {
				return errors.New("advanced negotiation: KERBEROS5 authentication still not supported")
				authKerberos = true
			} else if authServ.serviceName == "NTS" {
				authNTS = true
			}
		}
	}
	size := 0
	numService := 0
	if dataServ, ok := nego.serviceList[3].(*dataIntegrityService); ok {
		if len(dataServ.publicKey) > 0 {
			size = size + 12 + len(dataServ.publicKey)
			numService++
		}
	}
	if authKerberos {
		size += 37
		numService++
	}
	if authNTS {
		size += 130
		numService++
	}
	if numService == 0 {
		return nil
	}
	nego.comm.session.ResetBuffer()
	nego.writeHeader(size+13, numService, 0)
	if dataServ, ok := nego.serviceList[3].(*dataIntegrityService); ok {
		if len(dataServ.publicKey) > 0 {
			nego.comm.session.Context.ConnOption.Tracer.Print("Send Client Public Key:")
			dataServ.writeHeader(1)
			nego.comm.writeBytes(dataServ.publicKey)
		}
	}
	if authKerberos {
		if authServ, ok := nego.serviceList[1].(*authService); ok {
			authServ.writeHeader(4)
			nego.comm.writeVersion(authServ.getVersion())
			nego.comm.writeUB4(9)
			nego.comm.writeUB4(2)
			nego.comm.writeUB1(1)
		}
	}
	if authNTS {
		connOption := nego.comm.session.Context.ConnOption
		ntsPacket, err := createNTSNegoPacket(connOption.ClientInfo.DomainName, connOption.ClientInfo.HostName)
		if err != nil {
			return err
		}
		nego.comm.session.ResetBuffer()
		nego.comm.session.PutBytes(ntsPacket...)
		err = nego.comm.session.Write()
		if err != nil {
			return err
		}
		ntsHeader, err := nego.comm.session.GetBytes(33)
		if err != nil {
			return err
		}
		sizeOffset := len(ntsHeader) - 8
		chaSize := binary.LittleEndian.Uint32(ntsHeader[sizeOffset : sizeOffset+4])
		chaData, err := nego.comm.session.GetBytes(int(chaSize))
		if err != nil {
			return err
		}
		ntsPacket, err = createNTSAuthPacket(chaData, connOption.ClientInfo.UserName,
			connOption.ClientInfo.Password)
		if err != nil {
			return err
		}
		nego.comm.session.ResetBuffer()
		nego.comm.session.PutBytes(ntsPacket...)
		err = nego.comm.session.Write()
		if err != nil {
			return err
		}
		//fmt.Println(nego.comm.session.GetBytes(10))
		//return errors.New("interrupt")
		return nil
	}
	return nego.comm.session.Write()
}
func (nego *AdvNego) Write() error {
	nego.comm.session.ResetBuffer()
	size := 0
	for i := 1; i < 5; i++ {
		size = size + 8 + nego.serviceList[i].getServiceDataLength()
	}
	//size += 13
	nego.writeHeader(13+size, 4, 0)
	err := nego.serviceList[4].writeServiceData()
	if err != nil {
		return err
	}
	err = nego.serviceList[1].writeServiceData()
	if err != nil {
		return err
	}
	err = nego.serviceList[2].writeServiceData()
	if err != nil {
		return err
	}
	err = nego.serviceList[3].writeServiceData()
	if err != nil {
		return err
	}
	return nego.comm.session.Write()
}

func (nego *AdvNego) StartServices() error {
	err := nego.serviceList[3].activateAlgorithm()
	if err != nil {
		return err
	}
	err = nego.serviceList[2].activateAlgorithm()
	if err != nil {
		return err
	}
	err = nego.serviceList[1].activateAlgorithm()
	if err != nil {
		return err
	}
	err = nego.serviceList[4].activateAlgorithm()
	if err != nil {
		return err
	}
	return nil
}
