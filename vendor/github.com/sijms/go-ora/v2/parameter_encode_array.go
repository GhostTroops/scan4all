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
	par.setForNumber()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForNumber()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForNumber()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForNumber()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForNumber()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForNumber()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForNumber()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForNumber()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForTime()
	par.DataType = TIMESTAMP
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForTime()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
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
	par.setForTime()
	par.DataType = TIMESTAMP
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			session.WriteClr(&arrayBuffer, converters.EncodeTimeStamp(time.Time(tempVal)))
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayTime(session *network.Session, value []time.Time) {
	par.setForTime()
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			session.WriteClr(&arrayBuffer, converters.EncodeDate(tempVal))
		}
		par.BValue = arrayBuffer.Bytes()
	}
}

func (par *ParameterInfo) encodeArrayNullNVarchar(session *network.Session, converter converters.IStringConverter, value []NullNVarChar) {
	par.DataType = NCHAR
	par.ContFlag = 16
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			if !tempVal.Valid {
				session.WriteClr(&arrayBuffer, nil)
				continue
			}
			tempLen := len([]rune(string(tempVal.NVarChar)))
			if par.MaxCharLen < tempLen {
				par.MaxCharLen = tempLen
			}
			var tempBytes []byte
			if converter.GetLangID() != par.CharsetID {
				tempCharset := converter.SetLangID(par.CharsetForm)
				tempBytes = converter.Encode(string(tempVal.NVarChar))
				converter.SetLangID(tempCharset)
			} else {
				tempBytes = converter.Encode(string(tempVal.NVarChar))
			}
			session.WriteClr(&arrayBuffer, tempBytes)
			if par.MaxLen < len(tempBytes) {
				par.MaxLen = len(tempBytes)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	} else {
		par.MaxLen = converters.MAX_LEN_NVARCHAR2
		par.MaxCharLen = par.MaxLen / converters.MaxBytePerChar(par.CharsetID)
	}
}
func (par *ParameterInfo) encodeArrayNullString(session *network.Session, converter converters.IStringConverter, value []sql.NullString) {
	par.DataType = NCHAR
	par.ContFlag = 16
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			if !tempVal.Valid {
				session.WriteClr(&arrayBuffer, nil)
				continue
			}
			tempLen := len([]rune(tempVal.String))
			if par.MaxCharLen < tempLen {
				par.MaxCharLen = tempLen
			}
			var tempBytes []byte
			if converter.GetLangID() != par.CharsetID {
				tempCharset := converter.SetLangID(par.CharsetForm)
				tempBytes = converter.Encode(tempVal.String)
				converter.SetLangID(tempCharset)
			} else {
				tempBytes = converter.Encode(tempVal.String)
			}
			session.WriteClr(&arrayBuffer, tempBytes)
			if par.MaxLen < len(tempBytes) {
				par.MaxLen = len(tempBytes)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	} else {
		par.MaxLen = converters.MAX_LEN_VARCHAR2
		par.MaxCharLen = par.MaxLen / converters.MaxBytePerChar(par.CharsetID)
	}
}
func (par *ParameterInfo) encodeArrayString(session *network.Session, converter converters.IStringConverter, value []string) {
	par.DataType = NCHAR
	par.ContFlag = 16
	par.Flag = 0x43
	par.MaxNoOfArrayElements = len(value)
	if len(value) > 0 {
		arrayBuffer := bytes.Buffer{}
		session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
		for _, tempVal := range value {
			tempLen := len([]rune(tempVal))
			if par.MaxCharLen < tempLen {
				par.MaxCharLen = tempLen
			}
			var tempBytes []byte
			if converter.GetLangID() != par.CharsetID {
				tempCharset := converter.SetLangID(par.CharsetForm)
				tempBytes = converter.Encode(tempVal)
				converter.SetLangID(tempCharset)
			} else {
				tempBytes = converter.Encode(tempVal)
			}
			session.WriteClr(&arrayBuffer, tempBytes)
			if par.MaxLen < len(tempBytes) {
				par.MaxLen = len(tempBytes)
			}
		}
		par.BValue = arrayBuffer.Bytes()
	} else {
		par.MaxLen = converters.MAX_LEN_VARCHAR2
		par.MaxCharLen = par.MaxLen / converters.MaxBytePerChar(par.CharsetID)
	}
}

func (par *ParameterInfo) encodeArrayValue(val driver.Value, size int, connection *Connection) error {
	var err error
	switch value := val.(type) {
	case *[]time.Time:
		par.encodeArrayTime(connection.session, *value)
	case []time.Time:
		par.encodeArrayTime(connection.session, value)
	case *[]sql.NullTime:
		par.encodeArrayNullTime(connection.session, *value)
	case []sql.NullTime:
		par.encodeArrayNullTime(connection.session, value)
	case *[]TimeStamp:
		par.encodeArrayTimeStamp(connection.session, *value)
	case []TimeStamp:
		par.encodeArrayTimeStamp(connection.session, value)
	case *[]NullTimeStamp:
		par.encodeArrayNullTimeStamp(connection.session, *value)
	case []NullTimeStamp:
		par.encodeArrayNullTimeStamp(connection.session, value)
	case *[]string:
		par.encodeArrayString(connection.session, connection.strConv, *value)
	case []string:
		par.encodeArrayString(connection.session, connection.strConv, value)
	case []sql.NullString:
		par.encodeArrayNullString(connection.session, connection.strConv, value)
	case *[]sql.NullString:
		par.encodeArrayNullString(connection.session, connection.strConv, *value)
	case []NVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		tempArray := make([]string, 0, len(value))
		for _, tempItem := range value {
			tempArray = append(tempArray, string(tempItem))
		}
		par.encodeArrayString(connection.session, connection.strConv, tempArray)
	case *[]NVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		tempArray := make([]string, 0, len(*value))
		for _, tempItem := range *value {
			tempArray = append(tempArray, string(tempItem))
		}
		par.encodeArrayString(connection.session, connection.strConv, tempArray)
	case []NullNVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		par.encodeArrayNullNVarchar(connection.session, connection.strConv, value)
	case *[]NullNVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		par.encodeArrayNullNVarchar(connection.session, connection.strConv, *value)
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
	case []sql.NullInt16:
		par.encodeArrayNullInt16(connection.session, value)
	case *[]sql.NullInt16:
		par.encodeArrayNullInt16(connection.session, *value)
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
	case []sql.NullInt32:
		par.encodeArrayNullInt32(connection.session, value)
	case *[]sql.NullInt32:
		par.encodeArrayNullInt32(connection.session, *value)
	case []int64:
		par.encodeArrayInt(connection.session, value)
	case *[]int64:
		par.encodeArrayInt(connection.session, *value)
	case []sql.NullInt64:
		par.encodeArrayNullInt64(connection.session, value)
	case *[]sql.NullInt64:
		par.encodeArrayNullInt64(connection.session, *value)
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
	case *[]float64:
		err = par.encodeArrayFloat(connection.session, *value)
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
	case []sql.NullBool:
		par.encodeArrayNullBool(connection.session, value)
	case *[]sql.NullBool:
		par.encodeArrayNullBool(connection.session, *value)
	case []sql.NullByte:
		par.encodeArrayNullByte(connection.session, value)
	case *[]sql.NullByte:
		par.encodeArrayNullByte(connection.session, *value)
	default:
		return errors.New("unsupported array type")
	}

	if par.MaxNoOfArrayElements < size {
		par.MaxNoOfArrayElements = size
	}
	return nil
}
