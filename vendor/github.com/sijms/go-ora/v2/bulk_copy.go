package go_ora

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
)

var (
	bulkCopySuccess   = 1
	bulkCopyAllowRead = 2
	bulkCopyUserAbort = 4
	bulkCopyTimeout   = 8
)

type BulkCopy struct {
	conn          *Connection
	TableName     string
	SchemaName    string
	PartitionName string
	ColumnNames   []string
	data          bytes.Buffer
	//BatchSize     int
	columns     []ParameterInfo
	tableCursor int64
	sdbaBits    int64
	dbaBits     int64
}

func NewBulkCopy(conn *Connection, tableName string) *BulkCopy {
	ret := &BulkCopy{
		conn:      conn,
		TableName: tableName,
		data:      bytes.Buffer{},
	}
	return ret
}
func (bulk *BulkCopy) AddRow(values ...interface{}) error {
	data := bytes.Buffer{}
	for _, val := range values {
		if val == nil {
			data.WriteByte(0xFF)
			continue
		}
		par := &ParameterInfo{
			Direction:   Input,
			Flag:        3,
			CharsetID:   bulk.conn.tcpNego.ServerCharset,
			CharsetForm: 1,
		}
		err := par.encodeValue(val, 0, bulk.conn)
		if err != nil {
			return err
		}
		dataLen := len(par.BValue)
		if dataLen > 0xFA {
			data.WriteByte(0xFE)
			err = binary.Write(&data, binary.BigEndian, uint16(dataLen))
			if err != nil {
				return err
			}
		} else {
			data.WriteByte(uint8(dataLen))
		}
		data.Write(par.BValue)
	}
	var flag uint8 = 0x3C
	length := data.Len() + 4
	session := bulk.conn.session
	//session.WriteBytes(&bulk.data, flag)
	bulk.data.WriteByte(flag)
	session.WriteInt(&bulk.data, length, 2, true, false)
	bulk.data.WriteByte(uint8(len(bulk.columns)))
	_, err := data.WriteTo(&bulk.data)
	if err != nil {
		return err
	}
	if bulk.data.Len() > 0x20000 {
		err = bulk.EndStream()
		if err != nil {
			return err
		}
	}
	return nil
	//session.PutBytes(flag)
	//session.PutInt(length, 2, true, false)
	//session.PutBytes(uint8(len(bulk.columns)))
	//session.PutBytes(data.Bytes()...)
	//return nil
}

func (bulk *BulkCopy) StartStream() error {
	err := bulk.prepareDirectPath()
	if err != nil {
		return err
	}
	return nil
}
func (bulk *BulkCopy) EndStream() error {
	defer bulk.data.Reset()
	err := bulk.writeStreamMessage()
	if err != nil {
		return err
	}
	return bulk.readStreamResponse()
}

func (bulk *BulkCopy) writeStreamMessage() error {
	session := bulk.conn.session
	session.ResetBuffer()
	session.PutBytes(0x3, 0x81, 0)
	session.PutInt(bulk.tableCursor, 2, true, true)
	if bulk.data.Len() > 0 {
		session.PutBytes(1)
		session.PutInt(bulk.data.Len(), 4, true, true)
	} else {
		session.PutBytes(0, 0)
	}
	session.PutInt(400, 4, true, true)
	session.PutBytes(0, 0, 1, 1)
	session.PutBytes(bulk.data.Bytes()...)
	return session.Write()
}

func (bulk *BulkCopy) readStreamResponse() error {
	loop := true
	session := bulk.conn.session
	for loop {
		msg, err := session.GetByte()
		if err != nil {
			return err
		}
		switch msg {
		case 8:
			length, err := session.GetInt(2, true, true)
			if err != nil {
				return err
			}
			//tempArray := make([]int64, length)
			for x := 0; x < length; x++ {
				//tempArray[x], err = session.GetInt64(4, true, true)
				_, err = session.GetInt(4, true, true)
				if err != nil {
					return err
				}
			}
		default:
			err = bulk.conn.readResponse(msg)
			if err != nil {
				return err
			}
			if msg == 4 || msg == 9 {
				loop = false
			}
		}
	}
	if session.HasError() {
		if session.Summary.RetCode == 1403 {
			session.Summary = nil
		} else {
			return session.GetError()
		}
	}
	return nil
}

func (bulk *BulkCopy) prepareDirectPath() error {
	if bulk.conn.State != Opened {
		return &network.OracleError{ErrCode: 6413, ErrMsg: "ORA-06413: Connection not open"}
	}
	if len(bulk.SchemaName) == 0 {
		bulk.SchemaName = bulk.conn.connOption.UserID
	}
	err := bulk.writePrepareMessage()
	if err != nil {
		return err
	}
	// read
	return bulk.readPrepareResponse()
	//return nil
}

func (bulk *BulkCopy) writePrepareMessage() error {
	dppi4 := make([]int, 15, 37)
	dppi4[0] = 400
	dppi4[1] = 400
	dppi4[11] = 0xFFFF
	//if in transaction:
	//	this.m_dppi4[16] = 0xFFFF;
	//	this.m_dppi4[17] = 0xFFFF;
	//	this.m_dppi4[36] = 1

	length := 0
	if len(bulk.SchemaName) > 0 {
		length++
	}
	if len(bulk.TableName) > 0 {
		length++
	}
	if len(bulk.PartitionName) > 0 {
		length++
	}
	length += len(bulk.ColumnNames)

	// send direct path prepare request
	session := bulk.conn.session
	session.ResetBuffer()
	session.PutBytes(0x3, 0x80, 0, 0x1, 0x1, 0x1)
	session.PutInt(length, 2, true, true)
	session.PutBytes(0x1)
	session.PutInt(len(dppi4), 2, true, true)
	session.PutBytes(0x1, 0x1, 0x1, 0x1, 0x1, 0x1)
	if len(bulk.SchemaName) > 0 {
		temp := bulk.conn.sStrConv.Encode(bulk.SchemaName)
		session.PutKeyVal(nil, temp, 3)
	}
	if len(bulk.TableName) > 0 {
		temp := bulk.conn.sStrConv.Encode(bulk.TableName)
		session.PutKeyVal(nil, temp, 1)
	}
	if len(bulk.PartitionName) > 0 {
		temp := bulk.conn.sStrConv.Encode(bulk.PartitionName)
		session.PutKeyVal(nil, temp, 2)
	}
	for _, col := range bulk.ColumnNames {
		temp := bulk.conn.sStrConv.Encode(col)
		session.PutKeyVal(nil, temp, 4)
	}
	for _, x := range dppi4 {
		session.PutInt(x, 4, true, true)
	}
	return session.Write()
}

func (bulk *BulkCopy) readPrepareResponse() error {
	loop := true
	session := bulk.conn.session
	for loop {
		msg, err := session.GetByte()
		if err != nil {
			return err
		}
		switch msg {
		case 8:
			length, err := session.GetInt(2, true, true)
			if err != nil {
				return err
			}
			if length > 0 {
				bulk.columns = make([]ParameterInfo, length)
				for x := 0; x < length; x++ {
					err = bulk.columns[x].load(bulk.conn)
				}
			}

			//this.m_dppoparm = new TTCKeywordValuePair[length];
			//for (int index = 0; index < length2; ++index)
			//	this.m_dppoparm[index] = TTCKeywordValuePair.Unmarshal(this.m_marshallingEngine);
			length, err = session.GetInt(2, true, true)
			if err != nil {
				return err
			}
			for x := 0; x < length; x++ {
				key, val, num, err := session.GetKeyVal()
				if err != nil {
					return err
				}
				fmt.Println(key, "\t", val, "\t", num)
			}
			length, err = session.GetInt(2, true, true)
			if err != nil {
				return err
			}

			//this.m_dppo4 = new long[length];
			//for (int index = 0; index < length3; ++index)
			//	this.m_dppo4[index] = this.m_marshallingEngine.UnmarshalUB4();
			tempArray := make([]int64, length)
			for x := 0; x < length; x++ {
				tempArray[x], err = session.GetInt64(4, true, true)
				if err != nil {
					return err
				}
			}
			if length > 3 {
				bulk.tableCursor = tempArray[3]
			} else {
				bulk.tableCursor = 0
			}
			if length > 5 {
				bulk.sdbaBits = tempArray[5]
			} else {
				bulk.sdbaBits = 0
			}
			if length > 8 {
				bulk.dbaBits = tempArray[8]
			} else {
				bulk.dbaBits = 0
			}
		default:
			err = bulk.conn.readResponse(msg)
			if err != nil {
				return err
			}
			if msg == 4 || msg == 9 {
				loop = false
			}
		}
	}
	if session.HasError() {
		if session.Summary.RetCode == 1403 {
			session.Summary = nil
		} else {
			return session.GetError()
		}
	}
	return nil
}

func (bulk *BulkCopy) Commit() error {
	err := bulk.writeFinalMessage(2)
	if err != nil {
		return err
	}
	return bulk.readFinalResponse()
}

func (bulk *BulkCopy) Abort() error {
	err := bulk.writeFinalMessage(1)
	if err != nil {
		return err
	}
	return bulk.readFinalResponse()
}

func (bulk *BulkCopy) writeFinalMessage(code int) error {
	session := bulk.conn.session
	session.ResetBuffer()
	session.PutBytes(0x3, 0x82, 0)
	session.PutInt(code, 4, true, true)
	session.PutInt(bulk.tableCursor, 2, true, true)
	session.PutBytes(0, 0, 1, 1)
	return session.Write()
}

func (bulk *BulkCopy) readFinalResponse() error {
	loop := true
	session := bulk.conn.session
	for loop {
		msg, err := session.GetByte()
		if err != nil {
			return err
		}
		switch msg {
		case 8:
			length, err := session.GetInt(2, true, true)
			if err != nil {
				return err
			}
			for x := 0; x < length; x++ {
				_, err = session.GetInt(4, true, true)
				if err != nil {
					return err
				}
			}
		default:
			err = bulk.conn.readResponse(msg)
			if err != nil {
				return err
			}
			if msg == 4 || msg == 9 {
				loop = false
			}
		}
	}
	if session.HasError() {
		if session.Summary.RetCode == 1403 {
			session.Summary = nil
		} else {
			return session.GetError()
		}
	}
	return nil
}
