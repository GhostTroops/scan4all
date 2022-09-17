package go_ora

import (
	"database/sql/driver"
	"errors"
	"github.com/sijms/go-ora/v2/converters"
	"time"
)

type ValueEncoder interface {
	EncodeValue(param *ParameterInfo, connection *Connection) error
}
type NVarChar string
type TimeStamp time.Time
type NullNVarChar struct {
	Valid    bool
	NVarChar NVarChar
}
type NullTimeStamp struct {
	Valid     bool
	TimeStamp TimeStamp
}

func (val *NVarChar) Value() (driver.Value, error) {
	return driver.Value(string(*val)), nil
}
func (val *NVarChar) Scan(value interface{}) error {
	*val = NVarChar(getString(value))
	return nil
}

//func (val *NVarChar) ValueDecoder(buffer []byte) error {
//
//}

func (val *NVarChar) EncodeValue(param *ParameterInfo, connection *Connection) error {
	strVal := string(*val)
	param.DataType = NCHAR
	param.CharsetForm = 2
	param.ContFlag = 0x10
	param.CharsetID = connection.tcpNego.ServernCharset
	param.MaxCharLen = len([]rune(strVal))
	if len(string(*val)) == 0 {
		param.BValue = nil
	}
	if param.CharsetID != connection.strConv.GetLangID() {
		tempCharset := connection.strConv.SetLangID(param.CharsetID)
		defer connection.strConv.SetLangID(tempCharset)
		param.BValue = connection.strConv.Encode(strVal)
	} else {
		param.BValue = connection.strConv.Encode(strVal)
	}
	if param.MaxLen < len(param.BValue) {
		param.MaxLen = len(param.BValue)
	}
	if param.BValue == nil && param.MaxLen == 0 {
		param.MaxLen = 1
	}
	if (param.Direction == Output && param.MaxLen == 0) || param.MaxLen > converters.MAX_LEN_NVARCHAR2 {
		param.MaxLen = converters.MAX_LEN_NVARCHAR2
	}
	return nil
}
func (val *TimeStamp) EncodeValue(param *ParameterInfo, connection *Connection) error {
	param.setForTime()
	param.DataType = TIMESTAMP
	param.BValue = converters.EncodeTimeStamp(time.Time(*val))
	return nil
}
func (val *TimeStamp) Value() (driver.Value, error) {
	return driver.Value(time.Time(*val)), nil
}

func (val *TimeStamp) Scan(value interface{}) error {
	switch temp := value.(type) {
	case TimeStamp:
		*val = temp
	case *TimeStamp:
		*val = *temp
	case time.Time:
		*val = TimeStamp(temp)
	case *time.Time:
		*val = TimeStamp(*temp)
	default:
		return errors.New("go-ora: TimeStamp column type require time.Time value")
	}
	return nil
}

func (val *NullNVarChar) Value() (driver.Value, error) {
	if val.Valid {
		return val.NVarChar.Value()
	} else {
		return nil, nil
	}
}
func (val *NullNVarChar) Scan(value interface{}) error {
	if value == nil {
		val.Valid = false
		return nil
	}
	val.Valid = true
	return val.NVarChar.Scan(value)
}

func (val *NullTimeStamp) Value() (driver.Value, error) {
	if val.Valid {
		return val.TimeStamp.Value()
	} else {
		return nil, nil
	}
}

func (val *NullTimeStamp) Scan(value interface{}) error {
	if value == nil {
		val.Valid = false
		return nil
	}
	val.Valid = true
	return val.TimeStamp.Scan(value)
}

//func (val *NullNVarChar) Value() (driver.Value, error) {
//	return
//}
