package advanced_nego

import (
	"errors"
)

type supervisorService struct {
	defaultService
	cid       []byte
	servArray []int
}

func NewSupervisorService(comm *AdvancedNegoComm) (*supervisorService, error) {
	output := &supervisorService{
		defaultService: defaultService{
			comm:        comm,
			serviceType: 4,
			version:     0xB200200,
		},
		cid:       []byte{0, 0, 16, 28, 102, 236, 40, 234},
		servArray: []int{4, 1, 2, 3},
	}
	return output, nil
}

func (serv *supervisorService) readServiceData(subPacketNum int) error {
	var err error
	comm := serv.comm
	_, err = comm.readVersion()
	if err != nil {
		return err
	}
	status, err := comm.readStatus()
	if err != nil {
		return err
	}
	if status != 31 {
		return errors.New("advanced negotiation error: reading supervisor service")
	}
	serv.servArray, err = comm.readUB2Array()
	if err != nil {
		return err
	}
	return nil
}

func (serv *supervisorService) writeServiceData() error {
	serv.writeHeader(3)
	comm := serv.comm
	comm.writeVersion(serv.getVersion())
	// send cid
	comm.writeBytes(serv.cid)
	// send the serv-array
	comm.writeUB2Array(serv.servArray)
	return nil
}

func (serv *supervisorService) getServiceDataLength() int {
	return 12 + len(serv.cid) + 4 + 10 + (len(serv.servArray) * 2)
}
