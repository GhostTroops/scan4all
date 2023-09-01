package go_ora

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"errors"
	"github.com/sijms/go-ora/v2/converters"
	"github.com/sijms/go-ora/v2/network"
	"time"
)

func (par *ParameterInfo) encodeArrayFloat(session *network.Session, value []float64) error {
	//par.setForNumber()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			temp, err := converters.EncodeDouble(tempVal)
			if err != nil {
				return err
			}
			session.WriteClr(&arrayBuffer, temp)
		}
		par.BValue = arrayBuffer.Bytes()
	}
	return nil
}

func (par *ParameterInfo) encodeArrayNullFloat64(session *network.Session, value []sql.NullFloat64) error {
	//par.setForNumber()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			if tempVal.Valid {
				temp, err := converters.EncodeDouble(tempVal.Float64)
				if err != nil {
					return err
				}
				session.WriteClr(&arrayBuffer, temp)
			} else {
				session.WriteClr(&arrayBuffer, nil)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	}
	return nil
}

func (par *ParameterInfo) encodeArrayNullBool(session *network.Session, value []sql.NullBool) {
	//par.setForNumber()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, val := range value {
			if val.Valid {
				var tempNum int64 = 0
				if val.Bool {
					tempNum = 1
				}
				session.WriteClr(&arrayBuffer, converters.EncodeInt64(tempNum))
			} else {
				session.WriteClr(&arrayBuffer, nil)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayNullByte(session *network.Session, value []sql.NullByte) {
	//par.setForNumber()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, val := range value {
			if val.Valid {
				session.WriteClr(&arrayBuffer, converters.EncodeInt64(int64(val.Byte)))
			} else {
				session.WriteClr(&arrayBuffer, nil)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayNullInt16(session *network.Session, value []sql.NullInt16) {
	//par.setForNumber()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, val := range value {
			if val.Valid {
				session.WriteClr(&arrayBuffer, converters.EncodeInt64(int64(val.Int16)))
			} else {
				session.WriteClr(&arrayBuffer, nil)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayNullInt32(session *network.Session, value []sql.NullInt32) {
	//par.setForNumber()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, val := range value {
			if val.Valid {
				session.WriteClr(&arrayBuffer, converters.EncodeInt64(int64(val.Int32)))
			} else {
				session.WriteClr(&arrayBuffer, nil)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayNullInt64(session *network.Session, value []sql.NullInt64) {
	//par.setForNumber()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, val := range value {
			if val.Valid {
				session.WriteClr(&arrayBuffer, converters.EncodeInt64(val.Int64))
			} else {
				session.WriteClr(&arrayBuffer, nil)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayInt(session *network.Session, value []int64) {
	//par.setForNumber()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, val := range value {
			session.WriteClr(&arrayBuffer, converters.EncodeInt64(val))
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayNullTimeStamp(session *network.Session, value []NullTimeStamp) {
	//par.setForTime()
	par.DataType = TIMESTAMP
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			if tempVal.Valid {
				session.WriteClr(&arrayBuffer, converters.EncodeDate(time.Time(tempVal.TimeStamp)))
			} else {
				session.WriteClr(&arrayBuffer, nil)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayNullTime(session *network.Session, value []sql.NullTime) {
	//par.setForTime()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			if tempVal.Valid {
				session.WriteClr(&arrayBuffer, converters.EncodeDate(tempVal.Time))
			} else {
				session.WriteClr(&arrayBuffer, nil)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayTimeStamp(session *network.Session, value []TimeStamp) {
	//par.setForTime()
	par.DataType = TIMESTAMP
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			session.WriteClr(&arrayBuffer, converters.EncodeTimeStamp(time.Time(tempVal), false))
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayTime(session *network.Session, value []time.Time) {
	//par.setForTime()
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			session.WriteClr(&arrayBuffer, converters.EncodeDate(tempVal))
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayNullNVarchar(conn *Connection, value []NullNVarChar) {
	par.DataType = NCHAR
	par.ContFlag = 16
	session := conn.session
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			if !tempVal.Valid {
				session.WriteClr(&arrayBuffer, nil)
				continue
			}
			tempLen := len([]rune(tempVal.NVarChar))
			if par.MaxCharLen < tempLen {
				par.MaxCharLen = tempLen
			}
			strConv, _ := conn.getStrConv(par.CharsetID)
			tempBytes := strConv.Encode(string(tempVal.NVarChar))
			session.WriteClr(&arrayBuffer, tempBytes)
			if par.MaxLen < len(tempBytes) {
				par.MaxLen = len(tempBytes)
			}
		}
		par.MaxCharLen = par.MaxLen
		par.BValue = arrayBuffer.Bytes()
		if par.MaxLen == 0 {
			par.MaxLen = 1
			par.MaxCharLen = 0
		}
	} else {
		par.MaxLen = conn.maxLen.nvarchar
		par.MaxCharLen = par.MaxLen / converters.MaxBytePerChar(par.CharsetID)
	}
}

func (par *ParameterInfo) encodeArrayNullString(conn *Connection, value []sql.NullString) {
	par.DataType = NCHAR
	par.ContFlag = 16
	session := conn.session
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			if !tempVal.Valid {
				session.WriteClr(&arrayBuffer, nil)
				continue
			}
			//tempLen := len([]rune(tempVal.String))
			//if par.MaxCharLen < tempLen {
			//	par.MaxCharLen = tempLen
			//}
			strConv, _ := conn.getStrConv(par.CharsetID)
			tempBytes := strConv.Encode(tempVal.String)
			session.WriteClr(&arrayBuffer, tempBytes)
			if par.MaxLen < len(tempBytes) {
				par.MaxLen = len(tempBytes)
			}
		}
		par.MaxCharLen = par.MaxLen
		par.BValue = arrayBuffer.Bytes()
		if par.MaxLen == 0 {
			par.MaxLen = 1
			par.MaxCharLen = 0
		}
	} else {
		par.MaxLen = conn.maxLen.varchar
		par.MaxCharLen = par.MaxLen / converters.MaxBytePerChar(par.CharsetID)
	}
}

func (par *ParameterInfo) encodeArrayString(conn *Connection, value []string) {
	par.DataType = NCHAR
	par.ContFlag = 16
	session := conn.session
	arrayBuffer := bytes.Buffer{}
	session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
	if len(value) > 0 {
		for _, tempVal := range value {
			strConv, _ := conn.getStrConv(par.CharsetID)
			tempBytes := strConv.Encode(tempVal)
			session.WriteClr(&arrayBuffer, tempBytes)
			if par.MaxLen < len(tempBytes) {
				par.MaxLen = len(tempBytes)
			}
		}
		par.MaxCharLen = par.MaxLen
		par.BValue = arrayBuffer.Bytes()
		if par.MaxLen == 0 {
			par.MaxLen = 1
			par.MaxCharLen = 0
		}

	} else {
		par.MaxLen = conn.maxLen.varchar
		par.MaxCharLen = par.MaxLen / converters.MaxBytePerChar(par.CharsetID)
	}
}

func (par *ParameterInfo) encodeArrayValue(val driver.Value, size int, connection *Connection) error {
	var err error
	switch value := val.(type) {
	case *[]time.Time:
		par.encodeArrayTime(connection.session, *value)
	case []*time.Time:
		temp := make([]time.Time, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayTime(connection.session, temp)
	case []time.Time:
		par.encodeArrayTime(connection.session, value)
	case *[]sql.NullTime:
		par.encodeArrayNullTime(connection.session, *value)
	case []*sql.NullTime:
		temp := make([]sql.NullTime, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullTime(connection.session, temp)
	case []sql.NullTime:
		par.encodeArrayNullTime(connection.session, value)
	case *[]TimeStamp:
		par.encodeArrayTimeStamp(connection.session, *value)
	case []*TimeStamp:
		temp := make([]TimeStamp, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayTimeStamp(connection.session, temp)
	case []TimeStamp:
		par.encodeArrayTimeStamp(connection.session, value)
	case *[]NullTimeStamp:
		par.encodeArrayNullTimeStamp(connection.session, *value)
	case []*NullTimeStamp:
		temp := make([]NullTimeStamp, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullTimeStamp(connection.session, temp)
	case []NullTimeStamp:
		par.encodeArrayNullTimeStamp(connection.session, value)
	case *[]string:
		par.encodeArrayString(connection, *value)
	case []*string:
		temp := make([]string, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayString(connection, temp)
	case []string:
		par.encodeArrayString(connection, value)
	case []sql.NullString:
		par.encodeArrayNullString(connection, value)
	case *[]sql.NullString:
		par.encodeArrayNullString(connection, *value)
	case []*sql.NullString:
		temp := make([]sql.NullString, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullString(connection, temp)
	case []NVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		tempArray := make([]string, 0, len(value))
		for _, tempItem := range value {
			tempArray = append(tempArray, string(tempItem))
		}
		par.encodeArrayString(connection, tempArray)
	case *[]NVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		tempArray := make([]string, 0, len(*value))
		for _, tempItem := range *value {
			tempArray = append(tempArray, string(tempItem))
		}
		par.encodeArrayString(connection, tempArray)
	case []*NVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		temp := make([]string, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = string(*val)
			}
		}
		par.encodeArrayString(connection, temp)
	case []NullNVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		par.encodeArrayNullNVarchar(connection, value)
	case *[]NullNVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		par.encodeArrayNullNVarchar(connection, *value)
	case []*NullNVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		temp := make([]NullNVarChar, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullNVarchar(connection, temp)
	case []int:
		tempArray := make([]int64, len(value))
		for idx, tempItem := range value {
			tempArray[idx] = int64(tempItem)
		}
		par.encodeArrayInt(connection.session, tempArray)
	case *[]int:
		tempArray := make([]int64, len(*value))
		for idx, tempItem := range *value {
			tempArray[idx] = int64(tempItem)
		}
		par.encodeArrayInt(connection.session, tempArray)
	case []*int:
		temp := make([]int64, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = int64(*val)
			}
		}
		par.encodeArrayInt(connection.session, temp)
	case []int16:
		tempArray := make([]int64, len(value))
		for idx, tempItem := range value {
			tempArray[idx] = int64(tempItem)
		}
		par.encodeArrayInt(connection.session, tempArray)
	case *[]int16:
		tempArray := make([]int64, len(*value))
		for idx, tempItem := range *value {
			tempArray[idx] = int64(tempItem)
		}
		par.encodeArrayInt(connection.session, tempArray)
	case []*int16:
		temp := make([]int64, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = int64(*val)
			}
		}
		par.encodeArrayInt(connection.session, temp)
	case []sql.NullInt16:
		par.encodeArrayNullInt16(connection.session, value)
	case *[]sql.NullInt16:
		par.encodeArrayNullInt16(connection.session, *value)
	case []*sql.NullInt16:
		temp := make([]sql.NullInt16, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullInt16(connection.session, temp)
	case []int32:
		tempArray := make([]int64, len(value))
		for idx, tempItem := range value {
			tempArray[idx] = int64(tempItem)
		}
		par.encodeArrayInt(connection.session, tempArray)
	case *[]int32:
		tempArray := make([]int64, len(*value))
		for idx, tempItem := range *value {
			tempArray[idx] = int64(tempItem)
		}
		par.encodeArrayInt(connection.session, tempArray)
	case []*int32:
		temp := make([]int64, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = int64(*val)
			}
		}
		par.encodeArrayInt(connection.session, temp)
	case []sql.NullInt32:
		par.encodeArrayNullInt32(connection.session, value)
	case *[]sql.NullInt32:
		par.encodeArrayNullInt32(connection.session, *value)
	case []*sql.NullInt32:
		temp := make([]sql.NullInt32, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullInt32(connection.session, temp)
	case []int64:
		par.encodeArrayInt(connection.session, value)
	case *[]int64:
		par.encodeArrayInt(connection.session, *value)
	case []*int64:
		temp := make([]int64, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayInt(connection.session, temp)
	case []sql.NullInt64:
		par.encodeArrayNullInt64(connection.session, value)
	case *[]sql.NullInt64:
		par.encodeArrayNullInt64(connection.session, *value)
	case []*sql.NullInt64:
		temp := make([]sql.NullInt64, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullInt64(connection.session, temp)
	case []float32:
		tempArray := make([]float64, len(value))
		for idx, tempItem := range value {
			tempArray[idx] = float64(tempItem)
		}
		err = par.encodeArrayFloat(connection.session, tempArray)
		if err != nil {
			return err
		}
	case []float64:
		err = par.encodeArrayFloat(connection.session, value)
		if err != nil {
			return err
		}
	case *[]float32:
		tempArray := make([]float64, len(*value))
		for idx, tempItem := range *value {
			tempArray[idx] = float64(tempItem)
		}
		err = par.encodeArrayFloat(connection.session, tempArray)
		if err != nil {
			return err
		}
	case []*float32:
		temp := make([]float64, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = float64(*val)
			}
		}
		err = par.encodeArrayFloat(connection.session, temp)
		if err != nil {
			return err
		}
	case *[]float64:
		err = par.encodeArrayFloat(connection.session, *value)
		if err != nil {
			return err
		}
	case []*float64:
		temp := make([]float64, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		err = par.encodeArrayFloat(connection.session, temp)
		if err != nil {
			return err
		}
	case []sql.NullFloat64:
		err = par.encodeArrayNullFloat64(connection.session, value)
		if err != nil {
			return err
		}
	case *[]sql.NullFloat64:
		err = par.encodeArrayNullFloat64(connection.session, *value)
		if err != nil {
			return err
		}
	case []*sql.NullFloat64:
		temp := make([]sql.NullFloat64, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		err = par.encodeArrayNullFloat64(connection.session, temp)
		if err != nil {
			return err
		}
	case []sql.NullBool:
		par.encodeArrayNullBool(connection.session, value)
	case *[]sql.NullBool:
		par.encodeArrayNullBool(connection.session, *value)
	case []*sql.NullBool:
		temp := make([]sql.NullBool, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullBool(connection.session, temp)
	case []sql.NullByte:
		par.encodeArrayNullByte(connection.session, value)
	case *[]sql.NullByte:
		par.encodeArrayNullByte(connection.session, *value)
	case []*sql.NullByte:
		temp := make([]sql.NullByte, len(value))
		for index, val := range value {
			if val != nil {
				temp[index] = *val
			}
		}
		par.encodeArrayNullByte(connection.session, temp)
	default:
		return errors.New("unsupported array type")
	}

	if par.MaxNoOfArrayElements < size {
		par.MaxNoOfArrayElements = size
	}
	return nil
}
