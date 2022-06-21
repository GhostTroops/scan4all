package advanced_nego

import (
	"errors"
	"fmt"
	"strings"
)

type AdvNegoService interface {
	getServiceDataLength() int
	writeServiceData() error
	readServiceData(subPacketNum int) error
	validateResponse() error
	getVersion() uint32
	activateAlgorithm() error
}

type defaultService struct {
	comm                  *AdvancedNegoComm
	serviceType           int
	level                 int
	availableServiceNames []string
	availableServiceIDs   []int
	selectedIndices       []int
	version               uint32
	//selectedServ map[string]int
	//avaServs     map[string]int
}

func (serv *defaultService) getVersion() uint32 {
	return serv.version
}
func (serv *defaultService) activateAlgorithm() error {
	return nil
}

//func (serv *defaultService) writePacketHeader(session *network.Session, length, _type int) {
//	// the driver call Anocommunication.ValidateType(length, type);
//	session.PutInt(length, 2, true, false)
//	session.PutInt(_type, 2, true, false)
//}
//func (serv *defaultService) readPacketHeader(session *network.Session, _type int) (length int, err error) {
//	length, err = session.GetInt(2, false, true)
//	if err != nil {
//		return
//	}
//	receivedType, err := session.GetInt(2, false, true)
//	if err != nil {
//		return 0, err
//	}
//	if receivedType != _type {
//		err = errors.New("advanced negotiation error: received type is not as stored type")
//		return
//	}
//	err = serv.validatePacketHeader(length, receivedType)
//	return
//}
//func (serv *defaultService) validatePacketHeader(length, _type int) error {
//	if _type < 0 || _type > 7 {
//		return errors.New("advanced negotiation error: cannot validate packet header")
//	}
//	switch _type {
//	case 0, 1:
//		break
//	case 2:
//		if length > 1 {
//			return errors.New("advanced negotiation error: cannot validate packet header")
//		}
//	case 3:
//		fallthrough
//	case 6:
//		if length > 2 {
//			return errors.New("advanced negotiation error: cannot validate packet header")
//		}
//	case 4:
//		fallthrough
//	case 5:
//		if length > 4 {
//			return errors.New("advanced negotiation error: cannot validate packet header")
//		}
//	case 7:
//		if length < 10 {
//			return errors.New("advanced negotiation error: cannot validate packet header")
//		}
//	default:
//		return errors.New("advanced negotiation error: cannot validate packet header")
//	}
//	return nil
//}
//func (serv *defaultService) readUB2(session *network.Session) (number int, err error) {
//	_, err = serv.readPacketHeader(session, 3)
//	number, err = session.GetInt(2, false, true)
//	return
//}
func (serv *defaultService) writeHeader(serviceSubPackets int) {
	serv.comm.session.PutInt(serv.serviceType, 2, true, false)
	serv.comm.session.PutInt(serviceSubPackets, 2, true, false)
	serv.comm.session.PutInt(0, 4, true, false)
}

//func (serv *defaultService) readVersion(session *network.Session) (uint32, error) {
//	_, err := serv.readPacketHeader(session, 5)
//	if err != nil {
//		return 0, err
//	}
//	version, err := session.GetInt(4, false, true)
//	return uint32(version), err
//
//}
//func (serv *defaultService) readBytes(session *network.Session) ([]byte, error) {
//	length, err := serv.readPacketHeader(session, 1)
//	if err != nil {
//		return nil, err
//	}
//	return session.GetBytes(length)
//}
//func (serv *defaultService) writeVersion(session *network.Session) {
//	serv.writePacketHeader(session, 4, 5)
//	session.PutInt(serv.getVersion(), 4, true, false)
//}

func (serv *defaultService) readAdvNegoLevel(level string) {
	level = strings.ToUpper(level)
	if level == "" || level == "ACCEPTED" {
		serv.level = 0
	} else if level == "REJECTED" {
		serv.level = 1
	} else if level == "REQUESTED" {
		serv.level = 2
	} else if level == "REQUIRED" {
		serv.level = 3
	} else {
		serv.level = -1
	}
}

func (serv *defaultService) buildServiceList(userList []string, useLevel, useDefault bool) error {
	serv.selectedIndices = make([]int, 0, 10)
	//serv.selectedServ = make(map[string]int)
	if useLevel {
		if serv.level == 1 {
			serv.selectedIndices = append(serv.selectedIndices, 0)
			//serv.selectedServ[""] = 0
			return nil
		}
		if serv.level != 0 && serv.level != 2 && serv.level != 3 {
			return errors.New(fmt.Sprintf("unsupported service level value: %d", serv.level))
		}
	}
	userListLength := len(userList)
	for i := 0; i < userListLength; i++ {
		userList[i] = strings.TrimSpace(userList[i])
	}
	if userListLength > 0 && userList[userListLength-1] == "" {
		userList = userList[:userListLength-1]
	}
	if len(userList) == 0 {
		if useDefault {
			for i := 0; i < len(serv.availableServiceNames); i++ {
				if serv.availableServiceNames[i] == "" {
					if !(useLevel && serv.level == 0) {
						continue
					}
				}
				serv.selectedIndices = append(serv.selectedIndices, i)
			}
			if useLevel && serv.level == 2 {
				serv.selectedIndices = append(serv.selectedIndices, 0)
				//serv.selectedServ[""] = 0
			}
		}
		return nil
	} else if len(userList) == 1 {
		if strings.ToUpper(userList[0]) == "ALL" {
			for i := 0; i < len(serv.availableServiceNames); i++ {
				if serv.availableServiceNames[i] == "" {
					if !(useLevel && serv.level == 0) {
						continue
					}
				}
				serv.selectedIndices = append(serv.selectedIndices, i)
			}
			if useLevel && serv.level == 2 {
				serv.selectedIndices = append(serv.selectedIndices, 0)
				//serv.selectedServ[""] = 0
			}
			return nil
		} else if strings.ToUpper(userList[0]) == "NONE" {
			return nil
		}
	}
	if useLevel && serv.level == 0 {
		serv.selectedIndices = append(serv.selectedIndices, 0)
		//serv.selectedServ[""] = 0
	}
	for _, userItem := range userList {
		if userItem == "" {
			return errors.New("empty authentication service")
		}
		found := false
		for i := 0; i < len(serv.availableServiceNames); i++ {
			if strings.ToUpper(userItem) == serv.availableServiceNames[i] {
				serv.selectedIndices = append(serv.selectedIndices, i)
				found = true
				break
			}
		}
		//for key, value := range serv.avaServs {
		//	if strings.ToUpper(userItem) == key {
		//		serv.selectedServ[key] = value
		//		//output = append(output, userItem)
		//		found = true
		//		break
		//	}
		//}
		if !found {
			return errors.New("unsupported authentication service")
		}
	}
	if useLevel && serv.level == 2 {
		serv.selectedIndices = append(serv.selectedIndices, 0)
	}
	return nil
}
func (serv *defaultService) validateResponse() error {
	return nil
}
