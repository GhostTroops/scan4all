package go_ora

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/sijms/go-ora/v2/converters"
	"github.com/sijms/go-ora/v2/network"
)

type TNSType int
type ParameterDirection int

// func (n *NVarChar) ConvertValue(v interface{}) (driver.Value, error) {
//	return driver.Value(string(*n)), nil
// }

const (
	Input  ParameterDirection = 1
	Output ParameterDirection = 2
	InOut  ParameterDirection = 3
	//RetVal ParameterDirection = 9
)

type Out struct {
	Dest driver.Value
	Size int
	In   bool
}

// internal enum BindDirection
// {
// Output = 16,
// Input = 32,
// InputOutput = 48,
// }

//go:generate stringer -type=TNSType

const (
	NCHAR    TNSType = 1
	NUMBER   TNSType = 2
	BInteger TNSType = 3
	//SB1              TNSType = 3
	//SB2              TNSType = 3
	//SB4              TNSType = 3
	FLOAT            TNSType = 4
	NullStr          TNSType = 5
	VarNum           TNSType = 6
	LONG             TNSType = 8
	VARCHAR          TNSType = 9
	ROWID            TNSType = 11
	DATE             TNSType = 12
	VarRaw           TNSType = 15
	BFloat           TNSType = 21
	BDouble          TNSType = 22
	RAW              TNSType = 23
	LongRaw          TNSType = 24
	UINT             TNSType = 68
	LongVarChar      TNSType = 94
	LongVarRaw       TNSType = 95
	CHAR             TNSType = 96
	CHARZ            TNSType = 97
	IBFloat          TNSType = 100
	IBDouble         TNSType = 101
	REFCURSOR        TNSType = 102
	OCIXMLType       TNSType = 108
	XMLType          TNSType = 109
	OCIRef           TNSType = 110
	OCIClobLocator   TNSType = 112
	OCIBlobLocator   TNSType = 113
	OCIFileLocator   TNSType = 114
	ResultSet        TNSType = 116
	OCIString        TNSType = 155
	OCIDate          TNSType = 156
	TimeStampDTY     TNSType = 180
	TimeStampTZ_DTY  TNSType = 181
	IntervalYM_DTY   TNSType = 182
	IntervalDS_DTY   TNSType = 183
	TimeTZ           TNSType = 186
	TIMESTAMP        TNSType = 187
	TIMESTAMPTZ      TNSType = 188
	IntervalYM       TNSType = 189
	IntervalDS       TNSType = 190
	UROWID           TNSType = 208
	TimeStampLTZ_DTY TNSType = 231
	TimeStampeLTZ    TNSType = 232
	Boolean          TNSType = 0xFC
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
	DataType             TNSType
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
	iPrimValue           driver.Value
	oPrimValue           driver.Value
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
	par.DataType = TNSType(dataType)
	par.Flag, err = session.GetByte()
	if err != nil {
		return err
	}
	par.Precision, err = session.GetByte()
	// precision, err := session.GetInt(1, false, false)
	// var scale int
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
	case TIMESTAMPTZ:
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
		// scale, err = session.GetInt(1, false, false)
	}
	// if par.Scale == uint8(-127) {
	//
	// }
	if par.DataType == NUMBER && par.Precision == 0 && (par.Scale == 0 || par.Scale == 0xFF) {
		par.Precision = 38
		par.Scale = 0xFF
	}

	// par.Scale = uint16(scale)
	// par.Precision = uint16(precision)
	par.MaxLen, err = session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	switch par.DataType {
	case ROWID:
		par.MaxLen = 128
	case DATE:
		par.MaxLen = converters.MAX_LEN_DATE
	case IBFloat:
		par.MaxLen = 4
	case IBDouble:
		par.MaxLen = 8
	case TimeStampTZ_DTY:
		par.MaxLen = converters.MAX_LEN_TIMESTAMP
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
				par.cusType = new(customType)
				*par.cusType = cusTyp
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
	// MaxNoOfArrayElements should be 0 in case of XML type
	session.PutInt(par.MaxNoOfArrayElements, 4, true, true)
	if session.TTCVersion >= 10 {
		session.PutInt(par.ContFlag, 8, true, true)
	} else {
		session.PutInt(par.ContFlag, 4, true, true)
	}
	if par.ToID == nil {
		session.PutBytes(0)
		// session.PutInt(0, 1, false, false)
	} else {
		session.PutInt(len(par.ToID), 4, true, true)
		session.PutClr(par.ToID)
	}
	session.PutUint(par.Version, 2, true, true)
	session.PutUint(par.CharsetID, 2, true, true)
	session.PutBytes(uint8(par.CharsetForm))
	// session.PutUint(par.CharsetForm, 1, false, false)
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

	if temp, ok := par.Value.(sql.Scanner); ok {
		if temp != nil && !reflect.ValueOf(temp).IsNil() {
			return temp.Scan(newValue)
		}
	}
	switch value := par.Value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		par.Value = newValue
	case float32, float64, string, []byte:
		par.Value = newValue
	case bool:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		par.Value = temp != 0
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
	case NClob:
		if tempNewVal, ok := newValue.(NClob); ok {
			par.Value = tempNewVal
		} else {
			return errors.New("NClob col/par requires NClob value")
		}
	case *NClob:
		var tempVal NClob
		if tempNewVal, ok := newValue.(NClob); ok {
			tempVal = tempNewVal
		} else {
			return errors.New("*NClob col/par requires NClob value")
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
	case *string:
		*value = getString(newValue)
	case *bool:
		temp, err := getInt(newValue)
		if err != nil {
			return err
		}
		*value = temp != 0
	case NVarChar:
		par.Value = NVarChar(getString(newValue))
	case *NVarChar:
		*value = NVarChar(getString(newValue))
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
	case NullTimeStampTZ:
		if newValue == nil {
			value.Valid = false
		} else {
			value.Valid = true
			if tempNewVal, ok := newValue.(TimeStampTZ); ok {
				value.TimeStampTZ = tempNewVal
			} else if tempNewVal, ok := newValue.(time.Time); ok {
				value.TimeStampTZ = TimeStampTZ(tempNewVal)
			} else {
				return errors.New("NullTimeStampTZ col/par need TimeStamp, time.Time or Nil value")
			}
		}
		par.Value = value
	case *NullTimeStampTZ:
		var tempVal NullTimeStampTZ
		if newValue == nil {
			tempVal.Valid = false
		} else {
			tempVal.Valid = true
			if tempNewVal, ok := newValue.(TimeStampTZ); ok {
				tempVal.TimeStampTZ = tempNewVal
			} else if tempNewVal, ok := newValue.(time.Time); ok {
				tempVal.TimeStampTZ = TimeStampTZ(tempNewVal)
			} else {
				return errors.New("*NullTimeStampTZ col/par need TimeStampTZ, time.Time or Nil value")
			}
		}
		if value == nil {
			par.Value = &tempVal
		} else {
			*value = tempVal
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
				return errors.New("NullTimeStamp col/par need TimeStampTZ, time.Time or Nil value")
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

func (par *ParameterInfo) clone() ParameterInfo {
	tempPar := ParameterInfo{}
	tempPar.DataType = par.DataType
	tempPar.cusType = par.cusType
	tempPar.TypeName = par.TypeName
	tempPar.MaxLen = par.MaxLen
	tempPar.MaxCharLen = par.MaxCharLen
	tempPar.CharsetID = par.CharsetID
	tempPar.CharsetForm = par.CharsetForm
	tempPar.Scale = par.Scale
	tempPar.Precision = par.Precision
	return tempPar
}

func (par *ParameterInfo) decodePrimValue(conn *Connection, udt bool) error {
	session := conn.session
	var err error
	par.oPrimValue = nil
	par.BValue = nil
	if par.MaxNoOfArrayElements > 0 {
		size, err := session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		par.MaxNoOfArrayElements = size
		if size > 0 {
			pars := make([]ParameterInfo, 0, size)
			for x := 0; x < size; x++ {
				tempPar := par.clone()
				err = tempPar.decodeParameterValue(conn)
				if err != nil {
					return err
				}
				//, err = tempPar.decodeValue(stmt.connection, false)
				if x < size-1 {
					_, err = session.GetInt(2, true, true)
					if err != nil {
						return err
					}
				}
				pars = append(pars, tempPar)
			}
			par.oPrimValue = pars
		}
		return nil
	}
	if par.DataType == XMLType {
		if par.TypeName == "XMLTYPE" {
			return errors.New("unsupported data type: XMLTYPE")
		}
		if par.cusType == nil {
			return fmt.Errorf("unregister custom type: %s. call RegisterType first", par.TypeName)
		}
		_, err = session.GetDlc() // contain toid and some 0s
		if err != nil {
			return err
		}
		_, err = session.GetBytes(3) // 3 0s
		if err != nil {
			return err
		}
		_, err = session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		_, err = session.GetByte()
		if err != nil {
			return err
		}
		_, err = session.GetByte()
		if err != nil {
			return err
		}
	}
	if par.DataType == ROWID {
		rowid, err := newRowID(session)
		if err != nil {
			return err
		}
		if rowid != nil {
			par.oPrimValue = string(rowid.getBytes())
		}
		return nil
	}
	if par.DataType == UROWID {
		rowid, err := newURowID(session)
		if err != nil {
			return err
		}
		if rowid != nil {
			par.oPrimValue = string(rowid.getBytes())
		}
		return nil
	}
	if (par.DataType == NCHAR || par.DataType == CHAR) && par.MaxCharLen == 0 {
		return nil
	}
	if par.DataType == RAW && par.MaxLen == 0 {
		return nil
	}
	par.BValue, err = session.GetClr()
	if err != nil {
		return err
	}
	if par.BValue == nil {

		return nil
	}
	switch par.DataType {
	case NCHAR, CHAR, LONG:
		strConv, err := conn.getStrConv(par.CharsetID)
		if err != nil {
			return err
		}
		par.oPrimValue = strConv.Decode(par.BValue)
	case Boolean:
		par.oPrimValue = converters.DecodeBool(par.BValue)
	case RAW:
		par.oPrimValue = par.BValue
	case NUMBER:
		if par.Scale == 0 && par.Precision == 0 {
			var tempFloat string
			tempFloat, err = converters.NumberToString(par.BValue)
			if err != nil {
				return err
			}
			if err != nil {
				return err
			}
			if strings.Contains(tempFloat, ".") {
				par.oPrimValue, err = strconv.ParseFloat(tempFloat, 64)
			} else {
				par.oPrimValue, err = strconv.ParseInt(tempFloat, 10, 64)
			}
		} else if par.Scale == 0 && par.Precision <= 18 {
			par.oPrimValue, err = converters.NumberToInt64(par.BValue)
			if err != nil {
				return err
			}
		} else if par.Scale == 0 && (converters.CompareBytes(par.BValue, converters.Int64MaxByte) > 0 &&
			converters.CompareBytes(par.BValue, converters.Uint64MaxByte) < 0) {
			par.oPrimValue, err = converters.NumberToUInt64(par.BValue)
			if err != nil {
				return err
			}
		} else if par.Scale > 0 {
			//par.oPrimValue, err = converters.NumberToString(par.BValue)
			var tempFloat string
			tempFloat, err = converters.NumberToString(par.BValue)
			if err != nil {
				return err
			}
			if err != nil {
				return err
			}
			if strings.Contains(tempFloat, ".") {
				par.oPrimValue, err = strconv.ParseFloat(tempFloat, 64)
			} else {
				par.oPrimValue, err = strconv.ParseInt(tempFloat, 10, 64)
			}
		} else {
			par.oPrimValue = converters.DecodeNumber(par.BValue)
		}
	case TimeStampDTY, TimeStampeLTZ, TimeStampLTZ_DTY, TIMESTAMPTZ, TimeStampTZ_DTY:
		fallthrough
	case TIMESTAMP, DATE:
		tempTime, err := converters.DecodeDate(par.BValue)
		if err != nil {
			return err
		}
		if par.DataType == DATE && conn.dbTimeLoc != time.UTC {
			par.oPrimValue = time.Date(tempTime.Year(), tempTime.Month(), tempTime.Day(),
				tempTime.Hour(), tempTime.Minute(), tempTime.Second(), tempTime.Nanosecond(), conn.dbTimeLoc)
		} else {
			par.oPrimValue = tempTime
		}
	case OCIClobLocator, OCIBlobLocator:
		var locator []byte
		if !udt {
			locator, err = session.GetClr()
		} else {
			locator = par.BValue

		}
		if err != nil {
			return err
		}
		par.oPrimValue = Lob{
			sourceLocator: locator,
			sourceLen:     len(locator),
			connection:    conn,
			charsetID:     par.CharsetID,
		}
	case OCIFileLocator:
		locator, err := session.GetClr()
		if err != nil {
			return err
		}
		par.oPrimValue = BFile{
			isOpened: false,
			lob: Lob{
				sourceLocator: locator,
				sourceLen:     len(locator),
				connection:    conn,
				charsetID:     par.CharsetID,
			},
		}
	case IBFloat:
		par.oPrimValue = float64(converters.ConvertBinaryFloat(par.BValue))
	case IBDouble:
		par.oPrimValue = converters.ConvertBinaryDouble(par.BValue)
	case IntervalYM_DTY:
		par.oPrimValue = converters.ConvertIntervalYM_DTY(par.BValue)
	case IntervalDS_DTY:
		par.oPrimValue = converters.ConvertIntervalDS_DTY(par.BValue)
	case XMLType:
		err = decodeObject(conn, par)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unable to decode oracle type %v to its primitive value", par.DataType)
	}
	return nil
}

//func (par *ParameterInfo) decodeValue(connection *Connection, udt bool) (driver.Value, error) {
//	session := connection.session
//	var tempVal driver.Value
//	var err error
//	if par.DataType == ROWID {
//		rowid, err := newRowID(session)
//		if err != nil {
//			return nil, err
//		}
//		if rowid == nil {
//			tempVal = nil
//		} else {
//			tempVal = string(rowid.getBytes())
//		}
//		return tempVal, nil
//	}
//	if par.DataType == UROWID {
//		rowid, err := newURowID(session)
//		if err != nil {
//			return nil, err
//		}
//		if rowid == nil {
//			tempVal = nil
//		} else {
//			tempVal = string(rowid.getBytes())
//		}
//		return tempVal, nil
//	}
//	if (par.DataType == NCHAR || par.DataType == CHAR) && par.MaxCharLen == 0 {
//		par.BValue = nil
//		return nil, nil
//	}
//	if par.DataType == RAW && par.MaxLen == 0 {
//		par.BValue = nil
//		return nil, nil
//	}
//	par.BValue, err = session.GetClr()
//	if err != nil {
//		return nil, err
//	}
//	if par.BValue == nil {
//		switch par.DataType {
//		case OCIClobLocator:
//			if par.CharsetForm == 1 {
//				tempVal = Clob{locator: nil, Valid: false}
//			} else {
//				tempVal = NClob{locator: nil, Valid: false}
//			}
//		case OCIBlobLocator:
//			tempVal = Blob{locator: nil, Valid: false}
//		case OCIFileLocator:
//			tempVal = BFile{lob: Lob{sourceLocator: nil, connection: connection}}
//		default:
//			tempVal = nil
//		}
//	} else {
//		switch par.DataType {
//		case NCHAR, CHAR, LONG:
//			strConv, err := connection.getStrConv(par.CharsetID)
//			if err != nil {
//				return nil, err
//			}
//			tempVal = strConv.Decode(par.BValue)
//		case NUMBER:
//			// Scale = 0 and Precision <18 --> int64
//			if par.Scale == 0 && par.Precision <= 18 {
//				tempVal, err = converters.NumberToInt64(par.BValue)
//				if err != nil {
//					return nil, err
//				}
//			} else if par.Scale == 0 && (converters.CompareBytes(par.BValue, converters.Int64MaxByte) > 0 &&
//				converters.CompareBytes(par.BValue, converters.Uint64MaxByte) < 0) {
//				tempVal, err = converters.NumberToUInt64(par.BValue)
//				if err != nil {
//					return tempVal, err
//				}
//			} else if par.Scale > 0 {
//				tempVal, err = converters.NumberToString(par.BValue)
//				if err != nil {
//					return tempVal, err
//				}
//			} else {
//				tempVal = converters.DecodeNumber(par.BValue)
//			}
//		case TimeStampDTY:
//			fallthrough
//		case TimeStampeLTZ:
//			fallthrough
//		case TimeStampLTZ_DTY:
//			fallthrough
//		case TIMESTAMPTZ:
//			fallthrough
//		case TimeStampTZ_DTY:
//			fallthrough
//		case TIMESTAMP:
//			fallthrough
//		case DATE:
//			dateVal, err := converters.DecodeDate(par.BValue)
//			if err != nil {
//				return nil, err
//			}
//			tempVal = dateVal
//		case OCIBlobLocator, OCIClobLocator:
//			var locator []byte
//			var err error
//			if !udt {
//				locator, err = session.GetClr()
//			} else {
//				locator = par.BValue
//				par.BValue = nil
//			}
//			if err != nil {
//				return nil, err
//			}
//			if par.DataType == OCIClobLocator {
//				if par.CharsetForm == 1 {
//					tempVal = Clob{locator: locator}
//				} else {
//					tempVal = NClob{locator: locator}
//				}
//			} else {
//				tempVal = Blob{locator: locator}
//			}
//		case OCIFileLocator:
//			locator, err := session.GetClr()
//			if err != nil {
//				return nil, err
//			}
//			tempVal = BFile{
//				isOpened: false,
//				lob: Lob{
//					sourceLocator: locator,
//					sourceLen:     len(locator),
//					connection:    connection,
//				},
//			}
//		case IBFloat:
//			tempVal = converters.ConvertBinaryFloat(par.BValue)
//		case IBDouble:
//			tempVal = converters.ConvertBinaryDouble(par.BValue)
//		case IntervalYM_DTY:
//			tempVal = converters.ConvertIntervalYM_DTY(par.BValue)
//		case IntervalDS_DTY:
//			tempVal = converters.ConvertIntervalDS_DTY(par.BValue)
//		default:
//			tempVal = par.BValue
//		}
//	}
//	return tempVal, nil
//}

func (par *ParameterInfo) decodeParameterValue(connection *Connection) error {
	return par.decodePrimValue(connection, false)
	//if err != nil {
	//	return err
	//}
	//fieldValue := reflect.ValueOf(par.Value).Elem()
	//return setFieldValue(fieldValue, par.oPrimValue)

	//tempVal, err := par.decodeValue(connection, false)
	//if err != nil {
	//	return err
	//}
	//return par.setParameterValue(tempVal)
}

func (par *ParameterInfo) decodeColumnValue(connection *Connection, udt bool) error {
	//var err error
	if !udt && connection.connOption.Lob == 0 && (par.DataType == OCIBlobLocator || par.DataType == OCIClobLocator) {
		session := connection.session
		maxSize, err := session.GetInt(4, true, true)
		if err != nil {
			return err
		}
		if maxSize > 0 {
			/*size*/ _, err = session.GetInt(8, true, true)
			if err != nil {
				return err
			}
			/*chunkSize*/ _, err := session.GetInt(4, true, true)
			if err != nil {
				return err
			}
			if par.DataType == OCIClobLocator {
				flag, err := session.GetByte()
				if err != nil {
					return err
				}
				par.CharsetID = 0
				if flag == 1 {
					par.CharsetID, err = session.GetInt(2, true, true)
					if err != nil {
						return err
					}
				}
				tempByte, err := session.GetByte()
				if err != nil {
					return err
				}
				par.CharsetForm = int(tempByte)
				if par.CharsetID == 0 {
					if par.CharsetForm == 1 {
						par.CharsetID = connection.tcpNego.ServerCharset
					} else {
						par.CharsetID = connection.tcpNego.ServernCharset
					}
				}
			}
			par.BValue, err = session.GetClr()
			if par.DataType == OCIClobLocator {
				strConv, err := connection.getStrConv(par.CharsetID)
				if err != nil {
					return err
				}
				par.oPrimValue = strConv.Decode(par.BValue)
			} else {
				par.oPrimValue = par.BValue
			}
			_ /*locator*/, err = session.GetClr()
			if err != nil {
				return err
			}
		} else {
			par.oPrimValue = nil
		}
		return nil
	}
	//par.Value, err = par.decodeValue(connection, udt)
	return par.decodePrimValue(connection, udt)
}
