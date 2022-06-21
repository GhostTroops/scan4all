package advanced_nego

import (
	"errors"
)

type authService struct {
	defaultService
	status      int
	serviceName string
	active      bool
}

func NewAuthService(comm *AdvancedNegoComm) (*authService, error) {
	output := &authService{
		defaultService: defaultService{
			comm:        comm,
			serviceType: 1,
			level:       -1,
			version:     0xB200200,
		},
		status: 0xFCFF,
	}
	//var avaAuth []string
	output.availableServiceNames = []string{"", "NTS", "KERBEROS5", "TCPS"}
	output.availableServiceIDs = []int{0, 1, 1, 2}
	//if runtime.GOOS == "windows" {
	//
	//} else {
	//	output.availableServiceNames = []string{"NTS", "TCPS"}
	//	output.availableServiceIDs = []int{1, 2}
	//}
	//str :=  ""
	connOption := comm.session.Context.ConnOption
	//for
	//if connOption != nil {
	//	snConfig := connOption.SNOConfig
	//	if snConfig != nil {
	//		var exists bool
	//		str, exists = snConfig["sqlnet.authentication_services"]
	//		if !exists {
	//			str = ""
	//		}
	//	}
	//}
	//level := conops.Encryption != null ? conops.Encryption : snoConfig[];
	err := output.buildServiceList(connOption.AuthService, false, false)
	//output.selectedServ, err = output.validate(strings.Split(str,","), true)
	if err != nil {
		return nil, err
	}
	return output, nil
	/* user list is found in the dictionary
	sessCtx.m_conops.SNOConfig["sqlnet.authentication_services"]
	*/
	/* you need to confirm that every item in user list found in avaAuth list
	then for each item in userList you need to get index of it in the avaAuth
	return output*/
}

func (serv *authService) writeServiceData() error {
	serv.writeHeader(3 + (len(serv.selectedIndices) * 2))
	comm := serv.comm
	comm.writeVersion(serv.getVersion())
	comm.writeUB2(0xE0E1)
	comm.writeStatus(serv.status)
	for i := 0; i < len(serv.selectedIndices); i++ {
		index := serv.selectedIndices[i]
		comm.writeUB1(uint8(serv.availableServiceIDs[index]))
		comm.writeString(serv.availableServiceNames[index])
	}
	return nil
}

func (serv *authService) readServiceData(subPacketNum int) error {
	// read version
	var err error
	comm := serv.comm
	serv.version, err = comm.readVersion()
	if err != nil {
		return err
	}
	// read status
	status, err := comm.readStatus()
	if err != nil {
		return err
	}
	if status == 0xFAFF && subPacketNum > 2 {
		// get 1 byte with header
		_, err = comm.readUB1()
		serv.serviceName, err = comm.readString()
		if err != nil {
			return err
		}
		if subPacketNum > 4 {
			_, err = comm.readVersion()
			if err != nil {
				return err
			}
			_, err = comm.readUB4()
			if err != nil {
				return err
			}
			_, err = comm.readUB4()
			if err != nil {
				return err
			}
		}
		serv.active = true
	} else {
		if status != 0xFBFF {
			return errors.New("advanced negotiation error: reading authentication service")
		}
		serv.active = false
	}
	return nil
}

func (serv *authService) getServiceDataLength() int {
	size := 20
	for i := 0; i < len(serv.selectedIndices); i++ {
		index := serv.selectedIndices[i]
		size = size + 5 + (4 + len(serv.availableServiceNames[index]))
	}
	return size
}
