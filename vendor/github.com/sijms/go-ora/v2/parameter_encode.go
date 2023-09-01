package go_ora

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/sijms/go-ora/v2/converters"
)

//func (par *ParameterInfo) setForNull() {
//	par.DataType = NCHAR
//	par.BValue = nil
//	par.ContFlag = 0
//	par.MaxCharLen = 0
//	par.MaxLen = 1
//	par.CharsetForm = 1
//}
//
//func (par *ParameterInfo) setForNumber() {
//	par.DataType = NUMBER
//	par.ContFlag = 0
//	par.MaxCharLen = 0
//	par.MaxLen = converters.MAX_LEN_NUMBER
//	par.CharsetForm = 0
//	par.CharsetID = 0
//}
//func (par *ParameterInfo) setForTime() {
//	par.DataType = DATE
//	par.ContFlag = 0
//	par.MaxLen = converters.MAX_LEN_DATE
//	par.CharsetID = 0
//	par.CharsetForm = 0
//}
//func (par *ParameterInfo) setForRefCursor() {
//	par.BValue = nil
//	par.MaxCharLen = 0
//	par.MaxLen = 1
//	par.DataType = REFCURSOR
//	par.ContFlag = 0
//	par.CharsetForm = 0
//}
//func (par *ParameterInfo) setForUDT() {
//	par.Flag = 3
//	par.Version = 1
//	par.DataType = XMLType
//	par.CharsetID = 0
//	par.CharsetForm = 0
//	par.MaxLen = 2000
//}
//func (par *ParameterInfo) encodeInt(value int64) {
//	par.setForNumber()
//	par.BValue = converters.EncodeInt64(value)
//}

//func (par *ParameterInfo) encodeFloat(value float64) error {
//	par.setForNumber()
//	var err error
//	par.BValue, err = converters.EncodeDouble(value)
//	return err
//}

//func (par *ParameterInfo) encodeString(value string, converter converters.IStringConverter, size int) {
//	par.DataType = NCHAR
//	par.ContFlag = 16
//	par.MaxCharLen = len([]rune(value))
//	if len(value) == 0 {
//		par.BValue = nil
//	} else {
//		par.BValue = converter.Encode(value)
//	}
//	if size > len(value) {
//		par.MaxCharLen = size
//	}
//	if par.Direction == Input {
//		if par.BValue == nil {
//			par.MaxLen = 1
//		} else {
//			par.MaxLen = len(par.BValue)
//			par.MaxCharLen = par.MaxLen
//		}
//	} else {
//		par.MaxLen = par.MaxCharLen * converters.MaxBytePerChar(par.CharsetID)
//	}
//}
//
//func (par *ParameterInfo) encodeTime(value time.Time) {
//	par.setForTime()
//	par.BValue = converters.EncodeDate(value)
//}

//	func (par *ParameterInfo) encodeTimeStampTZ(value TimeStampTZ, conn *Connection) {
//		par.setForTime()
//		par.DataType = TimeStampTZ_DTY
//		par.MaxLen = converters.MAX_LEN_TIMESTAMP
//		temp := converters.EncodeTimeStamp(time.Time(value), true)
//		if conn.dataNego.clientTZVersion != conn.dataNego.serverTZVersion {
//			if temp[11]&0x80 != 0 {
//				temp[12] |= 1
//				if time.Time(value).IsDST() {
//					temp[12] |= 2
//				}
//			} else {
//				temp[11] |= 0x40
//			}
//		}
//		par.BValue = temp
//	}
//
//	func (par *ParameterInfo) encodeTimeStamp(value TimeStamp) {
//		par.setForTime()
//		par.DataType = TIMESTAMP
//		par.BValue = converters.EncodeTimeStamp(time.Time(value), false)
//	}
//
//	func (par *ParameterInfo) encodeRaw(value []byte, size int) {
//		par.BValue = value
//		par.DataType = RAW
//		par.MaxLen = len(value)
//		if size > par.MaxLen {
//			par.MaxLen = size
//		}
//		if par.MaxLen == 0 {
//			par.MaxLen = 1
//		}
//		par.ContFlag = 0
//		par.MaxCharLen = 0
//		par.CharsetForm = 0
//		par.CharsetID = 0
//	}

func (par *ParameterInfo) encodePrimValue(conn *Connection) error {
	var err error
	if par.iPrimValue == nil {
		par.BValue = nil
		return nil
	}
	switch value := par.iPrimValue.(type) {
	case float64:
		par.BValue, err = converters.EncodeDouble(value)
		if err != nil {
			return err
		}
	case int64:
		par.BValue = converters.EncodeInt64(value)
	case uint64:
		par.BValue = converters.EncodeUint64(value)
	case bool:
		par.BValue = converters.EncodeBool(value)
	case string:
		conv, err := conn.getStrConv(par.CharsetID)
		if err != nil {
			return err
		}
		par.BValue = conv.Encode(value)
		par.MaxLen = len(par.BValue)
		if par.MaxLen == 0 {
			par.MaxLen = 1
		}
	case time.Time:
		switch par.DataType {
		case DATE:
			par.BValue = converters.EncodeDate(value)
		case TIMESTAMP:
			par.BValue = converters.EncodeTimeStamp(value, false)
		case TimeStampTZ_DTY:

			temp := converters.EncodeTimeStamp(value, true)
			if conn.dataNego.clientTZVersion != conn.dataNego.serverTZVersion {
				if temp[11]&0x80 != 0 {
					temp[12] |= 1
					if time.Time(value).IsDST() {
						temp[12] |= 2
					}
				} else {
					temp[11] |= 0x40
				}
			}
			par.BValue = temp
		}
	case *Lob:
		par.BValue = value.sourceLocator
	case *BFile:
		par.BValue = value.lob.sourceLocator
	case []byte:
		par.BValue = value
	case []ParameterInfo:
		if par.MaxNoOfArrayElements > 0 {
			if len(value) > 0 {
				arrayBuffer := bytes.Buffer{}
				session := conn.session
				//arrayBuffer.Write([]byte{1})
				if par.DataType == XMLType {
					// number of fields
					arrayBuffer.Write([]byte{1, 3})
					//session.WriteUint(&arrayBuffer, len(par.cusType.attribs), 2, true, true)
					// number of elements
					session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 2, true, false)
					//arrayBuffer.Write([]byte{uint8(par.MaxNoOfArrayElements)})
				} else {
					session.WriteUint(&arrayBuffer, par.MaxNoOfArrayElements, 4, true, true)
				}
				for _, tempPar := range value {
					// get the binary representation of the item
					err = tempPar.encodePrimValue(conn)
					//if par.DataType == XMLType {
					//	arrayBuffer.Write([]byte{0, 0, 0, 0xfe})
					//}
					if err != nil {
						return err
					}
					if par.MaxCharLen < tempPar.MaxCharLen {
						par.MaxCharLen = tempPar.MaxCharLen
					}
					if par.MaxLen < tempPar.MaxLen {
						par.MaxLen = tempPar.MaxLen
					}
					// save binary representation to the buffer
					session.WriteClr(&arrayBuffer, tempPar.BValue)
				}
				//if par.DataType == XMLType {
				//	arrayBuffer.Write([]byte{0})
				//}
				par.BValue = arrayBuffer.Bytes()
			}
			// for array set maxsize of nchar and raw
			if par.DataType == NCHAR {
				par.MaxLen = conn.maxLen.nvarchar
				par.MaxCharLen = par.MaxLen // / converters.MaxBytePerChar(par.CharsetID)
			}
			if par.DataType == RAW {
				par.MaxLen = conn.maxLen.raw
			}
			if par.DataType == XMLType {
				par.ToID = par.cusType.arrayTOID
				par.BValue = encodeObject(conn.session, par.BValue, true)
				par.Flag = 3
				par.MaxNoOfArrayElements = 0
			}
		} else {
			par.BValue = encodeObject(conn.session, par.BValue, false)
		}
	default:
		return fmt.Errorf("unsupported primitive type: %v", reflect.TypeOf(par.iPrimValue).Name())
	}
	return nil
}

func (par *ParameterInfo) setDataType(goType reflect.Type, value driver.Value, conn *Connection) error {
	if goType == nil {
		par.DataType = NCHAR
		return nil
	}
	if goType.Kind() == reflect.Ptr {
		goType = goType.Elem()
	}
	if goType != tyBytes && (goType.Kind() == reflect.Array || goType.Kind() == reflect.Slice) {
		val, err := getValue(value)
		if err != nil {
			return err
		}
		var inVal driver.Value = nil
		if val != nil {
			rValue := reflect.ValueOf(val)
			size := rValue.Len()
			if size > 0 && rValue.Index(0).CanInterface() {
				inVal = rValue.Index(0).Interface()
			}
		}
		err = par.setDataType(goType.Elem(), inVal, conn)
		par.Flag = 0x43
		par.MaxNoOfArrayElements = 1
		return err
	}
	if tNumber(goType) || tNullNumber(goType) {
		par.DataType = NUMBER
		par.MaxLen = converters.MAX_LEN_NUMBER
		return nil
	}

	switch goType {
	case tyPLBool:
		par.DataType = Boolean
		par.MaxLen = converters.MAX_LEN_BOOL
	case tyString, tyNullString:
		par.DataType = NCHAR
		par.CharsetForm = 1
		par.ContFlag = 16
		par.CharsetID = conn.tcpNego.ServerCharset
	case tyNVarChar, tyNullNVarChar:
		par.DataType = NCHAR
		par.CharsetForm = 2
		par.ContFlag = 16
		par.CharsetID = conn.tcpNego.ServernCharset
	case tyTime, tyNullTime:
		par.DataType = DATE
		par.MaxLen = converters.MAX_LEN_DATE
	case tyTimeStamp, tyNullTimeStamp:
		par.DataType = TIMESTAMP
		par.MaxLen = converters.MAX_LEN_DATE
	case tyTimeStampTZ, tyNullTimeStampTZ:
		par.DataType = TimeStampTZ_DTY
		par.MaxLen = converters.MAX_LEN_TIMESTAMP
	case tyBytes:
		par.DataType = RAW
	case tyClob:
		par.DataType = OCIClobLocator
		par.CharsetForm = 1
		par.CharsetID = conn.tcpNego.ServerCharset
	case tyNClob:
		par.DataType = OCIClobLocator
		par.CharsetForm = 2
		par.CharsetID = conn.tcpNego.ServernCharset
	case tyBlob:
		par.DataType = OCIBlobLocator
	case tyBFile:
		par.DataType = OCIFileLocator
	case tyRefCursor:
		par.DataType = REFCURSOR
	default:
		val, err := getValue(value)
		if err != nil {
			return err
		}
		if val == nil {
			par.DataType = NCHAR
			return nil
		}
		if val != value {
			return par.setDataType(reflect.TypeOf(val), val, conn)
		}
		if goType.Kind() == reflect.Struct {
			for _, cusTyp := range conn.cusTyp {
				if goType == cusTyp.typ {
					par.cusType = new(customType)
					*par.cusType = cusTyp
					par.ToID = cusTyp.toid
				}
			}
			if par.cusType == nil {
				return errors.New("call register type before use user defined type (UDT)")
			}
			par.Version = 1
			par.DataType = XMLType
			par.MaxLen = 2000
		} else {
			return fmt.Errorf("unsupported go type: %v", goType.Name())
		}
	}
	return nil
}

func (par *ParameterInfo) encodeWithType(connection *Connection) error {
	var err error
	var val driver.Value
	val, err = getValue(par.Value)
	if err != nil {
		return err
	}
	if val == nil {
		par.iPrimValue = nil
		return nil
	}
	// check if array
	if par.MaxNoOfArrayElements > 0 {
		rValue := reflect.ValueOf(val)
		size := rValue.Len()
		if size > par.MaxNoOfArrayElements {
			par.MaxNoOfArrayElements = size
		}

		pars := make([]ParameterInfo, 0, size)
		for x := 0; x < size; x++ {
			var tempPar = par.clone()
			if rValue.Index(x).CanInterface() {
				tempPar.Value = rValue.Index(x).Interface()
			}
			err = tempPar.encodeWithType(connection)
			if err != nil {
				return err
			}
			pars = append(pars, tempPar)
		}
		par.iPrimValue = pars

		return nil
	}
	switch par.DataType {
	case Boolean:
		par.iPrimValue, err = getBool(val)
		if err != nil {
			return err
		}
	case NUMBER:
		par.iPrimValue, err = getNumber(val)
		if err != nil {
			return err
		}
	case NCHAR:
		tempString := getString(val)
		par.MaxCharLen = len(tempString)
		par.iPrimValue = tempString
	case DATE:
		fallthrough
	case TIMESTAMP:
		par.iPrimValue, err = getDate(val)
		if err != nil {
			return err
		}
	case TimeStampTZ_DTY:
		par.iPrimValue, err = getDate(val)
		if err != nil {
			return err
		}
	case RAW:
		var tempByte []byte
		tempByte, err = getBytes(val)
		if err != nil {
			return err
		}
		par.MaxLen = len(tempByte)
		par.iPrimValue = tempByte
		if par.MaxLen == 0 {
			par.MaxLen = 1
		}
	case OCIClobLocator:
		fallthrough
	case OCIBlobLocator:
		var temp *Lob
		temp, err = getLob(val, connection)
		if err != nil {
			return err
		}
		if temp == nil {
			if par.Direction == Input {
				par.DataType = NCHAR
			}
			par.MaxLen = 1
			par.iPrimValue = nil
		} else {
			par.iPrimValue = temp
		}
	case OCIFileLocator:
		if value, ok := val.(BFile); ok {
			if par.Direction == Input && !value.isInit() {
				return errors.New("BFile should be initialized first")
			}
			par.iPrimValue = &value
		}
	case REFCURSOR:
		par.iPrimValue = nil
	case XMLType:
		rValue := reflect.ValueOf(val)
		var objectBuffer bytes.Buffer
		pars := make([]ParameterInfo, 0, 10)
		for _, attrib := range par.cusType.attribs {
			if fieldIndex, ok := par.cusType.fieldMap[attrib.Name]; ok {
				//tempPar := ParameterInfo{Direction: par.Direction, DataType: attrib.DataType}
				tempPar := attrib.clone()
				tempPar.Direction = par.Direction
				tempPar.Value = rValue.Field(fieldIndex).Interface()
				err = tempPar.encodeWithType(connection)
				if err != nil {
					return err
				}
				err = tempPar.encodePrimValue(connection)
				if err != nil {
					return err

				}
				if tempPar.DataType == OCIFileLocator && tempPar.MaxLen == 0 {
					tempPar.MaxLen = 4000
				}
				if tempPar.Direction == Output {
					tempPar.BValue = nil
				}
				pars = append(pars, tempPar)
				connection.session.WriteClr(&objectBuffer, tempPar.BValue)
			}
		}
		par.iPrimValue = pars
		par.BValue = objectBuffer.Bytes()
	}
	return nil
}

func (par *ParameterInfo) init() {
	par.DataType = 0
	par.Flag = 3
	par.ContFlag = 0
	par.CharsetID = 0
	par.CharsetForm = 0
	par.MaxLen = 1
	par.MaxCharLen = 0
	par.MaxNoOfArrayElements = 0
	par.BValue = nil
	par.iPrimValue = nil
	par.oPrimValue = nil
}

func (par *ParameterInfo) encodeValue(val driver.Value, size int, connection *Connection) error {
	par.init()
	par.Value = val

	err := par.setDataType(reflect.TypeOf(val), val, connection)
	if err != nil {
		return err
	}
	if par.MaxNoOfArrayElements > 0 && par.MaxNoOfArrayElements < size {
		par.MaxNoOfArrayElements = size
	}
	err = par.encodeWithType(connection)
	if err != nil {
		return err
	}
	err = par.encodePrimValue(connection)
	if err != nil {
		return err
	}

	if par.DataType == OCIFileLocator {
		par.MaxLen = size
		if par.MaxLen == 0 {
			par.MaxLen = 4000
		}
	}
	if par.Direction != Input {
		if par.DataType == NCHAR {
			if par.MaxCharLen < size {
				par.MaxCharLen = size
			}
			conv, err := connection.getStrConv(par.CharsetID)
			if err != nil {
				return err
			}
			par.MaxLen = par.MaxCharLen * converters.MaxBytePerChar(conv.GetLangID())
		}
		if par.DataType == RAW {
			if par.MaxLen < size {
				par.MaxLen = size
			}
		}
	}

	if par.Direction == Output && !(par.DataType == XMLType) {
		par.BValue = nil
	}
	return nil
}
