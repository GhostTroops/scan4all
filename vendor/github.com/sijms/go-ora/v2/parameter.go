package go_ora

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"github.com/sijms/go-ora/v2/converters"
	"github.com/sijms/go-ora/v2/network"
	"math"
	"reflect"
	"strings"
	"time"
)

type OracleType int
type ParameterDirection int

//func (n *NVarChar) ConvertValue(v interface{}) (driver.Value, error) {
//	return driver.Value(string(*n)), nil
//}

const (
	Input  ParameterDirection = 1
	Output ParameterDirection = 2
	InOut  ParameterDirection = 3
	RetVal ParameterDirection = 9
)

type Out struct {
	Dest driver.Value
	Size int
}

//internal enum BindDirection
//{
//Output = 16,
//Input = 32,
//InputOutput = 48,
//}

//go:generate stringer -type=OracleType

const (
	NCHAR            OracleType = 1
	NUMBER           OracleType = 2
	SB1              OracleType = 3
	SB2              OracleType = 3
	SB4              OracleType = 3
	FLOAT            OracleType = 4
	NullStr          OracleType = 5
	VarNum           OracleType = 6
	LONG             OracleType = 8
	VARCHAR          OracleType = 9
	ROWID            OracleType = 11
	DATE             OracleType = 12
	VarRaw           OracleType = 15
	BFloat           OracleType = 21
	BDouble          OracleType = 22
	RAW              OracleType = 23
	LongRaw          OracleType = 24
	UINT             OracleType = 68
	LongVarChar      OracleType = 94
	LongVarRaw       OracleType = 95
	CHAR             OracleType = 96
	CHARZ            OracleType = 97
	IBFloat          OracleType = 100
	IBDouble         OracleType = 101
	REFCURSOR        OracleType = 102
	OCIXMLType       OracleType = 108
	XMLType          OracleType = 109
	OCIRef           OracleType = 110
	OCIClobLocator   OracleType = 112
	OCIBlobLocator   OracleType = 113
	OCIFileLocator   OracleType = 114
	ResultSet        OracleType = 116
	OCIString        OracleType = 155
	OCIDate          OracleType = 156
	TimeStampDTY     OracleType = 180
	TimeStampTZ_DTY  OracleType = 181
	IntervalYM_DTY   OracleType = 182
	IntervalDS_DTY   OracleType = 183
	TimeTZ           OracleType = 186
	TIMESTAMP        OracleType = 187
	TimeStampTZ      OracleType = 188
	IntervalYM       OracleType = 189
	IntervalDS       OracleType = 190
	UROWID           OracleType = 208
	TimeStampLTZ_DTY OracleType = 231
	TimeStampeLTZ    OracleType = 232
)

type ParameterType int

const (
	Number ParameterType = 1
	String ParameterType = 2
)

type ParameterInfo struct {
	Name                 string
	TypeName             string
	Direction            ParameterDirection
	IsNull               bool
	AllowNull            bool
	ColAlias             string
	DataType             OracleType
	IsXmlType            bool
	Flag                 uint8
	Precision            uint8
	Scale                uint8
	MaxLen               int
	MaxCharLen           int
	MaxNoOfArrayElements int
	ContFlag             int
	ToID                 []byte
	Version              int
	CharsetID            int
	CharsetForm          int
	BValue               []byte
	Value                driver.Value
	OutputVarPtr         interface{}
	getDataFromServer    bool
	oaccollid            int
	cusType              *customType
}

// load get parameter information form network session
func (par *ParameterInfo) load(conn *Connection) error {
	session := conn.session
	par.getDataFromServer = true
	dataType, err := session.GetByte()
	if err != nil {
		return err
	}
	par.DataType = OracleType(dataType)
	par.Flag, err = session.GetByte()
	if err != nil {
		return err
	}
	par.Precision, err = session.GetByte()
	//precision, err := session.GetInt(1, false, false)
	//var scale int
	switch par.DataType {
	case NUMBER:
		fallthrough
	case TimeStampDTY:
		fallthrough
	case TimeStampTZ_DTY:
		fallthrough
	case IntervalDS_DTY:
		fallthrough
	case TIMESTAMP:
		fallthrough
	case TimeStampTZ:
		fallthrough
	case IntervalDS:
		fallthrough
	case TimeStampLTZ_DTY:
		fallthrough
	case TimeStampeLTZ:
		if scale, err := session.GetInt(2, true, true); err != nil {
			return err
		} else {
			if scale == -127 {
				par.Precision = uint8(math.Ceil(float64(par.Precision) * 0.30103))
				par.Scale = 0xFF
			} else {
				par.Scale = uint8(scale)
			}
		}
	default:
		par.Scale, err = session.GetByte()
		//scale, err = session.GetInt(1, false, false)
	}
	//if par.Scale == uint8(-127) {
	//
	//}
	if par.DataType == NUMBER && par.Precision == 0 && (par.Scale == 0 || par.Scale == 0xFF) {
		par.Precision = 38
		par.Scale = 0xFF
	}

	//par.Scale = uint16(scale)
	//par.Precision = uint16(precision)
	par.MaxLen, err = session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	switch par.DataType {
	case ROWID:
		par.MaxLen = 128
	case DATE:
		par.MaxLen = 7
	case IBFloat:
		par.MaxLen = 4
	case IBDouble:
		par.MaxLen = 8
	case TimeStampTZ_DTY:
		par.MaxLen = 13
	case IntervalYM_DTY:
		fallthrough
	case IntervalDS_DTY:
		fallthrough
	case IntervalYM:
		fallthrough
	case IntervalDS:
		par.MaxLen = 11
	}
	par.MaxNoOfArrayElements, err = session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	if session.TTCVersion >= 10 {
		par.ContFlag, err = session.GetInt(8, true, true)
	} else {
		par.ContFlag, err = session.GetInt(4, true, true)
	}
	if err != nil {
		return err
	}
	par.ToID, err = session.GetDlc()
	par.Version, err = session.GetInt(2, true, true)
	if err != nil {
		return err
	}
	par.CharsetID, err = session.GetInt(2, true, true)
	if err != nil {
		return err
	}
	par.CharsetForm, err = session.GetInt(1, false, false)
	if err != nil {
		return err
	}
	par.MaxCharLen, err = session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	if session.TTCVersion >= 8 {
		par.oaccollid, err = session.GetInt(4, true, true)
	}
	num1, err := session.GetInt(1, false, false)
	if err != nil {
		return err
	}
	par.AllowNull = num1 > 0
	_, err = session.GetByte() //  session.GetInt(1, false, false)
	if err != nil {
		return err
	}
	bName, err := session.GetDlc()
	if err != nil {
		return err
	}
	par.Name = session.StrConv.Decode(bName)
	_, err = session.GetDlc()
	bName, err = session.GetDlc()
	if err != nil {
		return err
	}
	par.TypeName = strings.ToUpper(session.StrConv.Decode(bName))
	if par.DataType == XMLType && par.TypeName != "XMLTYPE" {
		for typName, cusTyp := range conn.cusTyp {
			if typName == par.TypeName {
				par.cusType = &cusTyp
			}
		}
	}
	if par.TypeName == "XMLTYPE" {
		par.DataType = XMLType
		par.IsXmlType = true
	}
	if session.TTCVersion < 3 {
		return nil
	}
	_, err = session.GetInt(2, true, true)
	if session.TTCVersion < 6 {
		return nil
	}
	_, err = session.GetInt(4, true, true)
	return nil
}

// write parameter information to network session
func (par *ParameterInfo) write(session *network.Session) error {
	session.PutBytes(uint8(par.DataType), par.Flag, par.Precision, par.Scale)
	session.PutUint(par.MaxLen, 4, true, true)
	session.PutInt(par.MaxNoOfArrayElements, 4, true, true)
	if session.TTCVersion >= 10 {
		session.PutInt(par.ContFlag, 8, true, true)
	} else {
		session.PutInt(par.ContFlag, 4, true, true)
	}
	if par.ToID == nil {
		session.PutBytes(0)
		//session.PutInt(0, 1, false, false)
	} else {
		session.PutInt(len(par.ToID), 4, true, true)
		session.PutClr(par.ToID)
	}
	session.PutUint(par.Version, 2, true, true)
	session.PutUint(par.CharsetID, 2, true, true)
	session.PutBytes(uint8(par.CharsetForm))
	//session.PutUint(par.CharsetForm, 1, false, false)
	session.PutUint(par.MaxCharLen, 4, true, true)
	if session.TTCVersion >= 8 {
		session.PutInt(par.oaccollid, 4, true, true)
	}
	return nil
}

func (par *ParameterInfo) setParameterValue(newValue driver.Value) error {
	if par.Value == nil {
		par.Value = newValue
		return nil
	}
	switch value := par.Value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		par.Value = newValue
	case float32, float64, string, []byte:
		par.Value = newValue
	case *int:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = int(temp)
	case *int8:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = int8(temp)
	case *int16:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = int16(temp)
	case *int32:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = int32(temp)
	case *int64:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = temp
	case *uint:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = uint(temp)
	case *uint8:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = uint8(temp)
	case *uint16:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = uint16(temp)
	case *uint32:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = uint32(temp)
	case *uint64:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = uint64(temp)
	case *float32:
		temp, err := getFloat(newValue)
		if err != nil {
			return err
		}
		*value = float32(temp)
	case *float64:
		temp, err := getFloat(newValue)
		if err != nil {
			return err
		}
		*value = temp
	case sql.NullByte:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			value.Byte = uint8(temp)
		}
		par.Value = value
	case sql.NullInt16:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			value.Int16 = int16(temp)
		}
		par.Value = value
	case sql.NullInt32:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			value.Int32 = int32(temp)
		}
		par.Value = value
	case sql.NullInt64:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			value.Int64 = temp
		}
		par.Value = value
	case sql.NullBool:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			value.Bool = temp != 0
		}
		par.Value = value
	case sql.NullFloat64:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			temp, err := getFloat(newValue)
			if err != nil {
				return err
			}
			value.Float64 = temp
		}
		par.Value = value
	case *sql.NullByte:
		var tempValue sql.NullByte
		if newValue == nil {
			tempValue.Valid = false
		} else {
			tempValue.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			tempValue.Byte = uint8(temp)
		}
		if value == nil {
			par.Value = &tempValue
		} else {
			*value = tempValue
		}
	case *sql.NullInt16:
		var tempValue sql.NullInt16
		if newValue == nil {
			tempValue.Valid = false
		} else {
			tempValue.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			tempValue.Int16 = int16(temp)
		}
		if value == nil {
			par.Value = &tempValue
		} else {
			*value = tempValue
		}
	case *sql.NullInt32:
		var tempValue sql.NullInt32
		if newValue == nil {
			tempValue.Valid = false
		} else {
			tempValue.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			tempValue.Int32 = int32(temp)
		}
		if value == nil {
			par.Value = &tempValue
		} else {
			*value = tempValue
		}
	case *sql.NullInt64:
		var tempValue sql.NullInt64
		if newValue == nil {
			tempValue.Valid = false
		} else {
			tempValue.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			tempValue.Int64 = temp
		}
		if value == nil {
			par.Value = &tempValue
		} else {
			*value = tempValue
		}
	case *sql.NullFloat64:
		var tempValue sql.NullFloat64
		if newValue == nil {
			tempValue.Valid = false
		} else {
			tempValue.Valid = true
			temp, err := getFloat(newValue)
			if err != nil {
				return err
			}
			tempValue.Float64 = temp
		}
		if value == nil {
			par.Value = &tempValue
		} else {
			*value = tempValue
		}
	case *sql.NullBool:
		var tempValue sql.NullBool
		if newValue == nil {
			tempValue.Valid = false
		} else {
			tempValue.Valid = true
			temp, err := getInt(newValue)
			if err != nil {
				return err
			}
			tempValue.Bool = temp != 0
		}
		if value == nil {
			par.Value = &tempValue
		} else {
			*value = tempValue
		}
	case time.Time:
		if tempNewVal, ok := newValue.(time.Time); ok {
			par.Value = tempNewVal
		} else {
			return errors.New("time.Time col/par need time.Time value")
		}
	case *time.Time:
		if tempNewVal, ok := newValue.(time.Time); ok {
			*value = tempNewVal
		} else {
			return errors.New("*time.Time col/par need time.Time value")
		}
	case sql.NullTime:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			if tempNewVal, ok := newValue.(time.Time); ok {
				value.Time = tempNewVal
			} else {
				return errors.New("sql.NullTime col/par need time.Time or Nil value")
			}
		}
		par.Value = value
	case *sql.NullTime:
		var tempVal sql.NullTime
		if newValue == nil {
			tempVal.Valid = false
		} else {
			tempVal.Valid = true
			if tempNewVal, ok := newValue.(time.Time); ok {
				tempVal.Time = tempNewVal
			} else {
				return errors.New("*sql.NullTime col/par need time.Time or Nil value")
			}
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
		}
	case TimeStamp:
		if tempNewVal, ok := newValue.(TimeStamp); ok {
			par.Value = tempNewVal
		} else if tempNewVal, ok := newValue.(time.Time); ok {
			par.Value = TimeStamp(tempNewVal)
		} else {
			return errors.New("TimeStamp col/par need TimeStamp or time.Time value")
		}
	case *TimeStamp:
		if tempNewVal, ok := newValue.(TimeStamp); ok {
			*value = tempNewVal
		} else if tempNewVal, ok := newValue.(time.Time); ok {
			*value = TimeStamp(tempNewVal)
		} else {
			return errors.New("*TimeStamp col/par need TimeStamp or time.Time value")
		}
	case NullTimeStamp:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			if tempNewVal, ok := newValue.(TimeStamp); ok {
				value.TimeStamp = tempNewVal
			} else if tempNewVal, ok := newValue.(time.Time); ok {
				value.TimeStamp = TimeStamp(tempNewVal)
			} else {
				return errors.New("NullTimeStamp col/par need TimeStamp, time.Time or Nil value")
			}
		}
		par.Value = value
	case *NullTimeStamp:
		var tempVal NullTimeStamp
		if newValue == nil {
			tempVal.Valid = false
		} else {
			tempVal.Valid = true
			if tempNewVal, ok := newValue.(TimeStamp); ok {
				tempVal.TimeStamp = tempNewVal
			} else if tempNewVal, ok := newValue.(time.Time); ok {
				tempVal.TimeStamp = TimeStamp(tempNewVal)
			} else {
				return errors.New("*NullTimeStamp col/par need TimeStamp, time.Time or Nil value")
			}
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
		}
	case BFile:
		if tempNewVal, ok := newValue.(BFile); ok {
			par.Value = tempNewVal
		} else {
			return errors.New("BFile col/par requires BFile value")
		}
	case *BFile:
		var tempVal BFile
		if tempNewVal, ok := newValue.(BFile); ok {
			tempVal = tempNewVal
		} else {
			return errors.New("*BFile col/par requires BFile value")
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
		}
	case Clob:
		if tempNewVal, ok := newValue.(Clob); ok {
			par.Value = tempNewVal
		} else {
			return errors.New("Clob col/par requires Clob value")
		}

	case *Clob:
		var tempVal Clob
		if tempNewVal, ok := newValue.(Clob); ok {
			tempVal = tempNewVal
		} else {
			return errors.New("*Clob col/par requires Clob value")
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
		}
	case Blob:
		if tempNewVal, ok := newValue.(Blob); ok {
			par.Value = tempNewVal
		} else {
			return errors.New("Blob clo/par requires Blob value")
		}
	case *Blob:
		var tempVal Blob
		if tempNewVal, ok := newValue.(Blob); ok {
			tempVal = tempNewVal
		} else {
			return errors.New("*Blob col/par requires Blob value")
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
		}
	case *[]byte:
		var tempVal []byte
		if tempNewVal, ok := newValue.([]byte); ok {
			tempVal = tempNewVal
		} else {
			return errors.New("[]byte col/par requires []byte or nil value")
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
		}
	//case RefCursor:
	//case *RefCursor:
	case *string:
		*value = getString(newValue)
	case sql.NullString:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			value.String = getString(newValue)
		}
		par.Value = value
	case *sql.NullString:
		var tempVal sql.NullString
		if newValue == nil {
			tempVal.Valid = false
		} else {
			tempVal.Valid = true
			tempVal.String = getString(newValue)
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
		}
	case NVarChar:
		par.Value = NVarChar(getString(newValue))
	case *NVarChar:
		*value = NVarChar(getString(newValue))
	case NullNVarChar:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			value.NVarChar = NVarChar(getString(newValue))
		}
		par.Value = value
	case *NullNVarChar:
		var tempVal NullNVarChar
		if newValue == nil {
			tempVal.Valid = false
		} else {
			tempVal.Valid = true
			tempVal.NVarChar = NVarChar(getString(newValue))
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
		}
	default:
		typ := reflect.TypeOf(par.Value)
		return errors.New("unsupported type: " + typ.Name())
	}
	return nil
}

func (par *ParameterInfo) decodeValue(connection *Connection) (driver.Value, error) {
	session := connection.session
	var tempVal driver.Value
	var err error
	if par.DataType == ROWID {
		rowid, err := newRowID(session)
		if err != nil {
			return nil, err
		}
		if rowid == nil {
			tempVal = nil
		} else {
			tempVal = string(rowid.getBytes())
		}
		return tempVal, nil
	}
	if (par.DataType == NCHAR || par.DataType == CHAR) && par.MaxCharLen == 0 {
		par.BValue = nil
		return nil, nil
	}
	if par.DataType == RAW && par.MaxLen == 0 {
		par.BValue = nil
		return nil, nil
	}
	par.BValue, err = session.GetClr()
	if err != nil {
		return nil, err
	}
	if par.BValue == nil {
		switch par.DataType {
		case OCIClobLocator:
			tempVal = Clob{locator: nil, Valid: false}
		case OCIBlobLocator:
			tempVal = Blob{locator: nil, Valid: false}
		case OCIFileLocator:
			tempVal = BFile{lob: Lob{sourceLocator: nil, connection: connection}}
		default:
			tempVal = nil
		}
	} else {
		switch par.DataType {
		case ROWID:

		case NCHAR, CHAR, LONG:
			if connection.strConv.GetLangID() != par.CharsetID {
				tempCharset := connection.strConv.SetLangID(par.CharsetID)
				tempVal = connection.strConv.Decode(par.BValue)
				connection.strConv.SetLangID(tempCharset)
			} else {
				tempVal = connection.strConv.Decode(par.BValue)
			}
		case NUMBER:
			tempVal = converters.DecodeNumber(par.BValue)
		case TimeStampDTY:
			fallthrough
		case TimeStampeLTZ:
			fallthrough
		case TimeStampLTZ_DTY:
			fallthrough
		case TimeStampTZ:
			fallthrough
		case TimeStampTZ_DTY:
			fallthrough
		case TIMESTAMP:
			dateVal, err := converters.DecodeDate(par.BValue)
			if err != nil {
				return nil, err
			}
			tempVal = TimeStamp(dateVal)
		case DATE:
			dateVal, err := converters.DecodeDate(par.BValue)
			if err != nil {
				return nil, err
			}
			tempVal = dateVal
		case OCIBlobLocator, OCIClobLocator:
			locator, err := session.GetClr()
			if err != nil {
				return nil, err
			}
			if par.DataType == OCIClobLocator {
				tempVal = Clob{locator: locator}
			} else {
				tempVal = Blob{locator: locator}
			}
		case OCIFileLocator:
			locator, err := session.GetClr()
			if err != nil {
				return nil, err
			}
			tempVal = BFile{
				isOpened: false,
				lob: Lob{
					sourceLocator: locator,
					sourceLen:     len(locator),
					connection:    connection,
				},
			}
		case IBFloat:
			tempVal = converters.ConvertBinaryFloat(par.BValue)
		case IBDouble:
			tempVal = converters.ConvertBinaryDouble(par.BValue)
		case IntervalYM_DTY:
			tempVal = converters.ConvertIntervalYM_DTY(par.BValue)
		case IntervalDS_DTY:
			tempVal = converters.ConvertIntervalDS_DTY(par.BValue)
		default:
			tempVal = par.BValue
		}
	}
	return tempVal, nil
}

func (par *ParameterInfo) decodeParameterValue(connection *Connection) error {
	tempVal, err := par.decodeValue(connection)
	if err != nil {
		return err
	}
	return par.setParameterValue(tempVal)
}

func (par *ParameterInfo) decodeColumnValue(connection *Connection) error {
	var err error
	par.Value, err = par.decodeValue(connection)
	return err
}
