package go_ora

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"errors"
	"github.com/sijms/go-ora/v2/converters"
	"reflect"
	"time"
)

func (par *ParameterInfo) setForNull() {
	par.DataType = NCHAR
	par.BValue = nil
	par.ContFlag = 0
	par.MaxCharLen = 0
	par.MaxLen = 1
	par.CharsetForm = 1
}

func (par *ParameterInfo) setForNumber() {
	par.DataType = NUMBER
	par.ContFlag = 0
	par.MaxCharLen = 0
	par.MaxLen = converters.MAX_LEN_NUMBER
	par.CharsetForm = 0
	par.CharsetID = 0
}
func (par *ParameterInfo) setForTime() {
	par.DataType = DATE
	par.ContFlag = 0
	par.MaxLen = converters.MAX_LEN_DATE
	par.CharsetID = 0
	par.CharsetForm = 0
}
func (par *ParameterInfo) setForRefCursor() {
	par.BValue = nil
	par.MaxCharLen = 0
	par.MaxLen = 1
	par.DataType = REFCURSOR
	par.ContFlag = 0
	par.CharsetForm = 0
}
func (par *ParameterInfo) setForUDT() {
	par.Flag = 3
	par.Version = 1
	par.DataType = XMLType
	par.CharsetID = 0
	par.CharsetForm = 0
	par.MaxLen = 2000
}
func (par *ParameterInfo) encodeInt(value int64) {
	par.setForNumber()
	par.BValue = converters.EncodeInt64(value)
}

func (par *ParameterInfo) encodeFloat(value float64) error {
	par.setForNumber()
	var err error
	par.BValue, err = converters.EncodeDouble(value)
	return err
}

func (par *ParameterInfo) encodeString(value string, converter converters.IStringConverter, size int) {
	par.DataType = NCHAR
	par.ContFlag = 16
	par.MaxCharLen = len([]rune(value))
	if len(value) == 0 {
		par.BValue = nil
	} else {
		if converter.GetLangID() != par.CharsetID {
			tempCharset := converter.SetLangID(par.CharsetID)
			par.BValue = converter.Encode(value)
			converter.SetLangID(tempCharset)
		} else {
			par.BValue = converter.Encode(value)
		}
	}
	if size > len(value) {
		par.MaxCharLen = size
	}
	if par.Direction == Input {
		if par.BValue == nil {
			par.MaxLen = 1
		} else {
			par.MaxLen = len(par.BValue)
		}
	} else {
		par.MaxLen = par.MaxCharLen * converters.MaxBytePerChar(par.CharsetID)
	}
}

func (par *ParameterInfo) encodeTime(value time.Time) {
	par.setForTime()
	par.BValue = converters.EncodeDate(value)
}

func (par *ParameterInfo) encodeTimeStamp(value TimeStamp) {
	par.setForTime()
	par.DataType = TIMESTAMP
	par.BValue = converters.EncodeTimeStamp(time.Time(value))
}

func (par *ParameterInfo) encodeRaw(value []byte, size int) {
	par.BValue = value
	par.DataType = RAW
	par.MaxLen = len(value)
	if size > par.MaxLen {
		par.MaxLen = size
	}
	par.ContFlag = 0
	par.MaxCharLen = 0
	par.CharsetForm = 0
	par.CharsetID = 0
}

func (par *ParameterInfo) encodeValue(val driver.Value, size int, connection *Connection) error {
	var err error
	par.Value = val
	if val == nil {
		par.setForNull()
		return nil
	}
	tempType := reflect.TypeOf(val)
	if tempType.Kind() == reflect.Ptr {
		tempType = tempType.Elem()
	}
	if tempType != reflect.TypeOf([]byte{}) {
		if tempType.Kind() == reflect.Array || tempType.Kind() == reflect.Slice {
			return par.encodeArrayValue(val, size, connection)
		}
	}
	switch value := val.(type) {
	case int:
		par.encodeInt(int64(value))
	case int8:
		par.encodeInt(int64(value))
	case int16:
		par.encodeInt(int64(value))
	case int32:
		par.encodeInt(int64(value))
	case int64:
		par.encodeInt(value)
	case *int:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case *int8:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case *int16:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case *int32:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case *int64:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(*value)
		}
	case uint:
		par.encodeInt(int64(value))
	case uint8:
		par.encodeInt(int64(value))
	case uint16:
		par.encodeInt(int64(value))
	case uint32:
		par.encodeInt(int64(value))
	case uint64:
		par.encodeInt(int64(value))
	case *uint:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case *uint8:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case *uint16:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case *uint32:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case *uint64:
		if value == nil {
			par.setForNumber()
		} else {
			par.encodeInt(int64(*value))
		}
	case float32:
		err = par.encodeFloat(float64(value))
		if err != nil {
			return err
		}
	case float64:
		err = par.encodeFloat(value)
		if err != nil {
			return err
		}
	case *float32:
		if value == nil {
			par.setForNumber()
		} else {
			err = par.encodeFloat(float64(*value))
			if err != nil {
				return err
			}
		}
	case *float64:
		if value == nil {
			par.setForNumber()
		} else {
			err = par.encodeFloat(*value)
			if err != nil {
				return err
			}
		}
	case sql.NullByte:
		if value.Valid {
			par.encodeInt(int64(value.Byte))
		} else {
			par.setForNull()
		}
	case sql.NullInt16:
		if value.Valid {
			par.encodeInt(int64(value.Int16))
		} else {
			par.setForNull()
		}
	case sql.NullInt32:
		if value.Valid {
			par.encodeInt(int64(value.Int32))
		} else {
			par.setForNull()
		}
	case sql.NullInt64:
		if value.Valid {
			par.encodeInt(value.Int64)
		} else {
			par.setForNull()
		}
	case *sql.NullByte:
		if value == nil {
			par.setForNumber()
		} else {
			if value.Valid {
				par.encodeInt(int64(value.Byte))
			} else {
				par.setForNull()
			}
		}
	case *sql.NullInt16:
		if value == nil {
			par.setForNumber()
		} else {
			if value.Valid {
				par.encodeInt(int64(value.Int16))
			} else {
				par.setForNull()
			}
		}
	case *sql.NullInt32:
		if value == nil {
			par.setForNumber()
		} else {
			if value.Valid {
				par.encodeInt(int64(value.Int32))
			} else {
				par.setForNull()
			}
		}
	case *sql.NullInt64:
		if value == nil {
			par.setForNumber()
		} else {
			if value.Valid {
				par.encodeInt(value.Int64)
			} else {
				par.setForNull()
			}
		}
	case sql.NullFloat64:
		if value.Valid {
			err = par.encodeFloat(value.Float64)
			if err != nil {
				return err
			}
		} else {
			par.setForNull()
		}
	case *sql.NullFloat64:
		if value == nil {
			par.setForNumber()
		} else {
			if value.Valid {
				err = par.encodeFloat(value.Float64)
				if err != nil {
					return err
				}
			} else {
				par.setForNull()
			}
		}
	case sql.NullBool:
		if value.Valid {
			var tempVal int64 = 0
			if value.Bool {
				tempVal = 1
			}
			par.encodeInt(tempVal)
		} else {
			par.setForNull()
		}
	case *sql.NullBool:
		if value == nil {
			par.setForNumber()
		} else {
			if value.Valid {
				var tempVal int64 = 0
				if value.Bool {
					tempVal = 1
				}
				par.encodeInt(tempVal)
			} else {
				par.setForNull()
			}
		}
	case time.Time:
		par.encodeTime(value)
	case *time.Time:
		if value == nil {
			par.setForTime()
		} else {
			par.encodeTime(*value)
		}
	case sql.NullTime:
		if value.Valid {
			par.encodeTime(value.Time)
		} else {
			par.setForNull()
		}
	case *sql.NullTime:
		if value == nil {
			par.setForTime()
		} else {
			if value.Valid {
				par.encodeTime(value.Time)
			} else {
				par.setForNull()
			}
		}
	case TimeStamp:
		par.encodeTimeStamp(value)
	case *TimeStamp:
		if value == nil {
			par.setForTime()
			par.DataType = TIMESTAMP
		} else {
			par.encodeTimeStamp(*value)
		}

	case NullTimeStamp:
		if value.Valid {
			par.encodeTimeStamp(value.TimeStamp)
		} else {
			par.setForNull()
		}
	case *NullTimeStamp:
		if value == nil {
			par.setForTime()
			par.DataType = TIMESTAMP
		} else {
			if value.Valid {
				par.encodeTimeStamp(value.TimeStamp)
			} else {
				par.setForNull()
			}
		}
	case NClob:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		par.encodeString(value.String, connection.strConv, size)
		if par.Direction == Output {
			par.DataType = OCIClobLocator
		} else {
			if par.MaxLen >= converters.MAX_LEN_NVARCHAR2 {
				par.DataType = OCIClobLocator
				lob := newLob(connection)
				err = lob.createTemporaryClob(connection.tcpNego.ServernCharset, 2)
				if err != nil {
					return err
				}
				err = lob.putString(value.String, connection.tcpNego.ServernCharset)
				if err != nil {
					return err
				}
				value.locator = lob.sourceLocator
				par.BValue = lob.sourceLocator
				par.Value = value
			}
		}
	case *NClob:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		par.encodeString(value.String, connection.strConv, size)
		if par.Direction == Output {
			par.DataType = OCIClobLocator
		} else {
			if par.MaxLen >= converters.MAX_LEN_NVARCHAR2 {
				par.DataType = OCIClobLocator
				lob := newLob(connection)
				err = lob.createTemporaryClob(connection.tcpNego.ServernCharset, 2)
				if err != nil {
					return err
				}
				err = lob.putString(value.String, connection.tcpNego.ServernCharset)
				if err != nil {
					return err
				}
				value.locator = lob.sourceLocator
				par.BValue = lob.sourceLocator
			}
		}
	case Clob:
		par.encodeString(value.String, connection.strConv, size)
		if par.Direction == Output {
			par.DataType = OCIClobLocator
		} else {
			if par.MaxLen >= converters.MAX_LEN_VARCHAR2 {
				// here we need to use clob
				par.DataType = OCIClobLocator
				lob := newLob(connection)
				err = lob.createTemporaryClob(connection.tcpNego.ServerCharset, 1)
				if err != nil {
					return err
				}
				err = lob.putString(value.String, connection.tcpNego.ServerCharset)
				if err != nil {
					return err
				}
				value.locator = lob.sourceLocator
				par.BValue = lob.sourceLocator
				par.Value = value
			}
		}
	case *Clob:
		if value == nil {
			par.encodeString("", connection.strConv, size)
		} else {
			par.encodeString(value.String, connection.strConv, size)
		}
		if par.Direction == Output {
			par.DataType = OCIClobLocator
		} else {
			if par.MaxLen >= converters.MAX_LEN_VARCHAR2 {
				par.DataType = OCIClobLocator
				lob := newLob(connection)
				err = lob.createTemporaryClob(connection.tcpNego.ServerCharset, 1)
				if err != nil {
					return err
				}
				err = lob.putString(value.String, connection.tcpNego.ServerCharset)
				if err != nil {
					return err
				}
				value.locator = lob.sourceLocator
				par.BValue = lob.sourceLocator
			}
		}
	case BFile:
		par.encodeRaw(nil, size)
		if par.MaxLen == 0 {
			par.MaxLen = 4000
		}
		par.DataType = OCIFileLocator
		if par.Direction == Input {
			if !value.isInit() {
				return errors.New("BFile must be initialized")
			}
			par.BValue = value.lob.sourceLocator
		}
	case *BFile:
		par.encodeRaw(nil, size)
		if par.MaxLen == 0 {
			par.MaxLen = 4000
		}
		par.DataType = OCIFileLocator
		if par.Direction == Input {
			if !value.isInit() {
				return errors.New("BFile must be initialized")
			}
			par.BValue = value.lob.sourceLocator
		}
	case Blob:
		par.encodeRaw(value.Data, size)
		if par.Direction == Output {
			par.DataType = OCIBlobLocator
		} else {
			if len(value.Data) >= converters.MAX_LEN_RAW {
				par.DataType = OCIBlobLocator
				lob := newLob(connection)
				err = lob.createTemporaryBLOB()
				if err != nil {
					return err
				}
				err = lob.putData(value.Data)
				if err != nil {
					return err
				}
				value.locator = lob.sourceLocator
				par.BValue = lob.sourceLocator
				par.Value = value
			}
		}
	case *Blob:
		if value == nil {
			par.encodeRaw(nil, size)
		} else {
			par.encodeRaw(value.Data, size)
		}
		if par.Direction == Output {
			par.DataType = OCIBlobLocator
		} else {
			if len(value.Data) >= converters.MAX_LEN_RAW {
				par.DataType = OCIBlobLocator
				lob := newLob(connection)
				err = lob.createTemporaryBLOB()
				if err != nil {
					return err
				}
				err = lob.putData(value.Data)
				if err != nil {
					return err
				}
				value.locator = lob.sourceLocator
				par.BValue = lob.sourceLocator
			}
		}
	case []byte:
		if len(value) > converters.MAX_LEN_RAW && par.Direction == Input {
			return par.encodeValue(Blob{Valid: true, Data: value}, size, connection)
		}
		par.encodeRaw(value, size)
	case *[]byte:
		if value == nil {
			par.encodeRaw(nil, size)
		} else {
			if len(*value) > converters.MAX_LEN_RAW && par.Direction == Input {
				return par.encodeValue(&Blob{Valid: true, Data: *value}, size, connection)
			}
			par.encodeRaw(*value, size)
		}
	case RefCursor, *RefCursor:
		par.setForRefCursor()
	case string:
		if len(value) > converters.MAX_LEN_NVARCHAR2 && par.Direction == Input {
			return par.encodeValue(Clob{Valid: true, String: value}, size, connection)
		}
		par.encodeString(value, connection.strConv, size)
	case *string:
		if value == nil {
			par.encodeString("", connection.strConv, size)
		} else {
			if len(*value) > converters.MAX_LEN_NVARCHAR2 && par.Direction == Input {
				return par.encodeValue(&Clob{Valid: true, String: *value}, size, connection)
			}
			par.encodeString(*value, connection.strConv, size)
		}
	case sql.NullString:
		if value.Valid {
			par.encodeString(value.String, connection.strConv, size)
		} else {
			par.setForNull()
		}
	case *sql.NullString:
		if value == nil {
			par.encodeString("", connection.strConv, size)
		} else {
			if value.Valid {
				par.encodeString(value.String, connection.strConv, size)
			} else {
				par.setForNull()
			}
		}
	case NVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		par.encodeString(string(value), connection.strConv, size)
	case *NVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		if value == nil {
			par.encodeString("", connection.strConv, size)
		} else {
			par.encodeString(string(*value), connection.strConv, size)
		}
	case NullNVarChar:
		if value.Valid {
			par.CharsetForm = 2
			par.CharsetID = connection.tcpNego.ServernCharset
			par.encodeString(string(value.NVarChar), connection.strConv, size)
		} else {
			par.setForNull()
		}
	case *NullNVarChar:
		par.CharsetForm = 2
		par.CharsetID = connection.tcpNego.ServernCharset
		if value == nil {
			par.encodeString("", connection.strConv, size)
		} else {
			if value.Valid {
				par.encodeString(string(value.NVarChar), connection.strConv, size)
			} else {
				par.setForNull()
			}
		}
	default:
		custVal := reflect.ValueOf(val)
		if custVal.Kind() == reflect.Ptr {
			custVal = custVal.Elem()
		}
		if custVal.Kind() == reflect.Struct {
			par.setForUDT()
			for _, cusTyp := range connection.cusTyp {
				if custVal.Type() == cusTyp.typ {
					par.cusType = &cusTyp
					par.ToID = cusTyp.toid
				}
			}
			if par.cusType == nil {
				return errors.New("struct parameter only allowed with user defined type (UDT)")
			}
			var objectBuffer bytes.Buffer
			for _, attrib := range par.cusType.attribs {
				if fieldIndex, ok := par.cusType.filedMap[attrib.Name]; ok {
					tempPar := ParameterInfo{
						Direction:   par.Direction,
						Flag:        3,
						CharsetID:   connection.tcpNego.ServerCharset,
						CharsetForm: 1,
					}
					err = tempPar.encodeValue(custVal.Field(fieldIndex).Interface(), 0, connection)
					if err != nil {
						return err
					}
					connection.session.WriteClr(&objectBuffer, tempPar.BValue)
				}
			}
			par.BValue = objectBuffer.Bytes()
		}
	}
	return nil
}

//func fromStringToClob(s string) Clob {
//	return Clob{
//		String: s,
//	}
//}

//func fromBytesToBlob(b []byte) Blob {
//	return Blob{
//		Data: b,
//	}
//}
