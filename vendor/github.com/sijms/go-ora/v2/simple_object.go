package go_ora

import (
	"database/sql/driver"
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
		err = obj.connection.readResponse(msg)
		if err != nil {
			return err
		}
		if msg == 4 || msg == 9 {
			loop = false
		}
	}
	if session.HasError() {
		return session.GetError()
	}
	return nil
}

func (obj *simpleObject) exec() error {
	tracer := obj.connection.connOption.Tracer
	failOver := obj.connection.connOption.Failover
	if failOver == 0 {
		failOver = 1
	}
	var err = obj.write().read()
	if err != nil {
		if isBadConn(err) {
			tracer.Print("Error: ", err)
			return driver.ErrBadConn
		}
		return err
	}
	return nil
	//var reconnect bool
	//for writeTrials := 0; writeTrials < failOver; writeTrials++ {
	//	reconnect, err = obj.connection.reConnect(err, writeTrials)
	//	if err != nil {
	//		tracer.Print("Error: ", err)
	//		if !reconnect {
	//			return err
	//		}
	//		continue
	//	}
	//	break
	//}
	//if reconnect {
	//	return &network.OracleError{ErrCode: 3135}
	//}
	//return err
}
