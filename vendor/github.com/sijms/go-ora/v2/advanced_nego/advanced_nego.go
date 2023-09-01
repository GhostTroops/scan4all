package advanced_nego

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
	"net"
)

var version int = 0xB200200

type KerberosAuthInterface interface {
	Authenticate(server, service string) ([]byte, error)
}

var kerberosAuth KerberosAuthInterface = nil

// Set Kerberos5 Authentication inferface used for kerberos authentication
func SetKerberosAuth(input KerberosAuthInterface) {
	kerberosAuth = input
}

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
				//return errors.New("advanced negotiation: KERBEROS5 authentication still not supported")
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
		if kerberosAuth == nil {
			return errors.New("advanced negotiation error: you need to call SetKerberosAuth with valid interface before use kerberos5 authentication")
		}
		if authServ, ok := nego.serviceList[1].(*authService); ok {
			authServ.writeHeader(4)
			nego.comm.writeVersion(authServ.getVersion())
			nego.comm.writeUB4(9)
			nego.comm.writeUB4(2)
			nego.comm.writeUB1(1)
			err = nego.comm.session.Write()
			if err != nil {
				return err
			}
			return nego.kerbosHandshake(authServ)
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

func (nego *AdvNego) kerbosHandshake(authServ *authService) error {
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
	}
	serviceName, err := nego.comm.readString()
	if err != nil {
		return err
	}
	serverHostName, err := nego.comm.readString()
	if err != nil {
		return err
	}
	if len(serviceName) == 0 {
		return errors.New("kerberos negotiation error: Service Name not received")
	}
	if len(serverHostName) == 0 {
		return errors.New("kerberos negotiation error: Server hostname not received")
	}
	ticketData, err := kerberosAuth.Authenticate(serverHostName, serviceName)
	if err != nil {
		return err
	}
	// get host ip address
	localAddress, err := getHostIPAddress()
	if err != nil {
		return err
	}
	// if address is ipv6 then num1 = 24 otherwise = 2
	num1 := 2
	localAddress = net.IP{172, 17, 0, 2}
	if len(localAddress) > 4 {
		num1 = 24
	}
	nego.comm.session.ResetBuffer()
	// sendanoheader(length of ticket + 43 + length of address, 1 , 0)
	nego.writeHeader(len(ticketData)+43+len(localAddress), 1, 0)
	// sendheader(4)
	authServ.writeHeader(4)
	// send ub2 = num1
	nego.comm.writeUB2(num1)
	// send ub4 = length of address
	nego.comm.writeUB4(len(localAddress))
	// send bytes address bytes
	nego.comm.writeBytes(localAddress)
	// send bytes ticket
	nego.comm.writeBytes(ticketData)
	// write
	err = nego.comm.session.Write()
	if err != nil {
		return err
	}
	// read ano header
	header, err = nego.readHeader()
	if err != nil {
		return err
	}
	for index := 0; index < header[2]; index++ {
		serviceHeader, err := nego.readServiceHeader()
		if err != nil {
			return err
		}
		if serviceHeader[2] != 0 {
			return &network.OracleError{ErrCode: serviceHeader[2]}
			//return fmt.Errorf("advanced negotiation error: during receive service header: network excpetion: ora-%d", serviceHeader[2])
		}
	}
	// get packet header (2)
	_, err = nego.comm.readPacketHeader(2)
	if err != nil {
		return err
	}
	// num2 = get ub1
	_, err = nego.comm.session.GetByte()
	if err != nil {
		return err
	}
	// receive byte array
	_, err = nego.comm.readBytes()
	if err != nil {
		return err
	}
	// send ano header (25,1, 0)
	nego.comm.session.ResetBuffer()
	nego.writeHeader(25, 1, 0)
	// as.sendheader(1)
	authServ.writeHeader(1)
	// send packet header(0, 1)
	nego.comm.writePacketHeader(0, 1)
	// write
	return nego.comm.session.Write()
}
func getHostIPAddress() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.To4(), nil
			}
			if ipnet.IP.To16() != nil {
				return ipnet.IP.To16(), nil
			}
		}
	}
	return nil, errors.New("advanced negotiation error: during get local ip address")
}
