package go_ora

import (
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
)

type simpleObject struct {
	connection *Connection
	//session     *network.Session
	operationID uint8
	data        []byte
	err         error
}

func (obj *simpleObject) write() *simpleObject {
	//obj.session.ResetBuffer()
	session := obj.connection.session
	session.PutBytes(3, obj.operationID, 0)
	if obj.data != nil {
		session.PutBytes(obj.data...)
	}
	obj.err = session.Write()
	return obj
}

func (obj *simpleObject) read() error {
	session := obj.connection.session
	if obj.err != nil {
		return obj.err
	}
	loop := true
	for loop {
		msg, err := session.GetByte()
		if err != nil {
			return err
		}
		switch msg {
		case 4:
			session.Summary, err = network.NewSummary(session)
			if err != nil {
				return err
			}
			loop = false
		case 9:
			if session.HasEOSCapability {
				if session.Summary == nil {
					session.Summary = new(network.SummaryObject)
				}
				session.Summary.EndOfCallStatus, err = session.GetInt(4, true, true)
				if err != nil {
					return err
				}
			}
			if session.HasFSAPCapability {
				if session.Summary == nil {
					session.Summary = new(network.SummaryObject)
				}
				session.Summary.EndToEndECIDSequence, err = session.GetInt(2, true, true)
				if err != nil {
					return err
				}
			}
			loop = false
		case 15:
			warning, err := network.NewWarningObject(session)
			if err != nil {
				return err
			}
			if warning != nil {
				fmt.Println(warning)
			}
		case 23:
			opCode, err := session.GetByte()
			if err != nil {
				return err
			}
			err = obj.connection.getServerNetworkInformation(opCode)
			if err != nil {
				return err
			}
		default:
			return errors.New(fmt.Sprintf("TTC error: received code %d during simple object read", msg))
		}
	}
	if session.HasError() {
		return session.GetError()
	}
	return nil
}
