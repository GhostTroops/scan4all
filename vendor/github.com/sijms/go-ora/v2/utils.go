package go_ora

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/converters"
	"github.com/sijms/go-ora/v2/network"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	tyBool            = reflect.TypeOf((*bool)(nil)).Elem()
	tyBytes           = reflect.TypeOf((*[]byte)(nil)).Elem()
	tyString          = reflect.TypeOf((*string)(nil)).Elem()
	tyNVarChar        = reflect.TypeOf((*NVarChar)(nil)).Elem()
	tyTime            = reflect.TypeOf((*time.Time)(nil)).Elem()
	tyTimeStamp       = reflect.TypeOf((*TimeStamp)(nil)).Elem()
	tyTimeStampTZ     = reflect.TypeOf((*TimeStampTZ)(nil)).Elem()
	tyClob            = reflect.TypeOf((*Clob)(nil)).Elem()
	tyNClob           = reflect.TypeOf((*NClob)(nil)).Elem()
	tyBlob            = reflect.TypeOf((*Blob)(nil)).Elem()
	tyBFile           = reflect.TypeOf((*BFile)(nil)).Elem()
	tyNullByte        = reflect.TypeOf((*sql.NullByte)(nil)).Elem()
	tyNullInt16       = reflect.TypeOf((*sql.NullInt16)(nil)).Elem()
	tyNullInt32       = reflect.TypeOf((*sql.NullInt32)(nil)).Elem()
	tyNullInt64       = reflect.TypeOf((*sql.NullInt64)(nil)).Elem()
	tyNullFloat64     = reflect.TypeOf((*sql.NullFloat64)(nil)).Elem()
	tyNullBool        = reflect.TypeOf((*sql.NullBool)(nil)).Elem()
	tyNullString      = reflect.TypeOf((*sql.NullString)(nil)).Elem()
	tyNullNVarChar    = reflect.TypeOf((*NullNVarChar)(nil)).Elem()
	tyNullTime        = reflect.TypeOf((*sql.NullTime)(nil)).Elem()
	tyNullTimeStamp   = reflect.TypeOf((*NullTimeStamp)(nil)).Elem()
	tyNullTimeStampTZ = reflect.TypeOf((*NullTimeStampTZ)(nil)).Elem()
	tyRefCursor       = reflect.TypeOf((*RefCursor)(nil)).Elem()
	tyPLBool          = reflect.TypeOf((*PLBool)(nil)).Elem()
)

func parseSqlText(text string) ([]string, error) {
	index := 0
	length := len(text)
	skip := false
	lineComment := false
	textBuffer := make([]byte, 0, len(text))
	for ; index < length; index++ {
		ch := text[index]
		switch ch {
		case '\\':
			// bypass next character
			index++
			continue
		case '/':
			if index+1 < length && text[index+1] == '*' {
				index += 1
				skip = true
			}
		case '*':
			if index+1 < length && text[index+1] == '/' {
				index += 1
				skip = false
			}
		case '\'':
			skip = !skip
		case '"':
			skip = !skip
		case '-':
			if index+1 < length && text[index+1] == '-' {
				index += 1
				lineComment = true
			}
		case '\n':
			if lineComment {
				lineComment = false
			}
		default:
			if skip || lineComment {
				continue
			}
			textBuffer = append(textBuffer, text[index])
		}
	}
	refinedSql := strings.TrimSpace(string(textBuffer))
	reg, err := regexp.Compile(`:(\w+)`)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, 10)
	matches := reg.FindAllStringSubmatch(refinedSql, -1)
	for _, match := range matches {
		if len(match) > 1 {
			names = append(names, match[1])
		}
	}
	return names, nil
}

func extractTag(tag string) (name, _type string, size int, direction ParameterDirection) {
	extractNameValue := func(input string, pos int) {
		parts := strings.Split(input, "=")
		var id, value string
		if len(parts) < 2 {
			switch pos {
			case 0:
				id = "name"
			case 1:
				id = "type"
			case 2:
				id = "size"
			case 3:
				id = "direction"
			}
			value = input
		} else {
			id = strings.TrimSpace(strings.ToLower(parts[0]))
			value = strings.TrimSpace(parts[1])
		}
		switch id {
		case "name":
			name = value
		case "type":
			_type = value
		case "size":
			tempSize, _ := strconv.ParseInt(value, 10, 32)
			size = int(tempSize)
		case "dir":
			fallthrough
		case "direction":
			switch value {
			case "in", "input":
				direction = Input
			case "out", "output":
				direction = Output
			case "inout":
				direction = InOut
			}
		}
	}
	tag = strings.TrimSpace(tag)
	if len(tag) == 0 {
		return
	}
	tagFields := strings.Split(tag, ",")
	if len(tagFields) > 0 {
		extractNameValue(tagFields[0], 0)
	}
	if len(tagFields) > 1 {
		extractNameValue(tagFields[1], 1)
	}
	if len(tagFields) > 2 {
		extractNameValue(tagFields[2], 2)
	}
	if len(tagFields) > 3 {
		extractNameValue(tagFields[3], 3)
	}
	return
}

func tSigned(input reflect.Type) bool {
	switch input.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	default:
		return false
	}
}
func tUnsigned(input reflect.Type) bool {
	switch input.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}
func tInteger(input reflect.Type) bool {
	return tSigned(input) || tUnsigned(input)
}
func tFloat(input reflect.Type) bool {
	return input.Kind() == reflect.Float32 || input.Kind() == reflect.Float64
}
func tNumber(input reflect.Type) bool {
	return tInteger(input) || tFloat(input) || input == tyBool
}
func tNullNumber(input reflect.Type) bool {
	switch input {
	case tyNullBool, tyNullByte, tyNullInt16, tyNullInt32, tyNullInt64:
		fallthrough
	case tyNullFloat64:
		return true
	}
	return false
}

//======== get primitive data from original data types ========//

// get value to bypass pointer and sql.Null* values
func getValue(origVal driver.Value) (driver.Value, error) {
	if origVal == nil {
		return nil, nil
	}
	rOriginal := reflect.ValueOf(origVal)
	if rOriginal.Kind() == reflect.Ptr && rOriginal.IsNil() {
		return nil, nil
	}
	proVal := reflect.Indirect(rOriginal)
	if valuer, ok := proVal.Interface().(driver.Valuer); ok {
		return valuer.Value()
	}
	return proVal.Interface(), nil
}

// get prim string value from supported types
func getString(col interface{}) string {
	col, _ = getValue(col)
	if col == nil {
		return ""
	}
	switch val := col.(type) {
	case Clob:
		return val.String
	case NClob:
		return val.String
	}
	if temp, ok := col.(string); ok {
		return temp
	} else {
		return fmt.Sprintf("%v", col)
	}
}

func getBool(col interface{}) (bool, error) {
	col, err := getValue(col)
	if err != nil {
		return false, err
	}
	if col == nil {
		return false, nil
	}
	rValue := reflect.ValueOf(col)
	return rValue.Bool(), nil
}
func getNumber(col interface{}) (interface{}, error) {
	var err error
	col, err = getValue(col)
	if err != nil {
		return int64(0), err
	}
	if col == nil {
		return int64(0), nil
	}
	rType := reflect.TypeOf(col)
	rValue := reflect.ValueOf(col)
	if tSigned(rType) {
		return rValue.Int(), nil
	}
	if tUnsigned(rType) {
		return rValue.Uint(), nil
	}
	if f32, ok := col.(float32); ok {
		return strconv.ParseFloat(fmt.Sprint(f32), 64)
	}
	if tFloat(rType) {
		return rValue.Float(), nil
	}
	switch rType.Kind() {
	case reflect.Bool:
		if rValue.Bool() {
			return int64(1), nil
		} else {
			return int64(0), nil
		}
	case reflect.String:
		tempFloat, err := strconv.ParseFloat(rValue.String(), 64)
		if err != nil {
			return 0, err
		}
		return tempFloat, nil
	default:
		return 0, errors.New("conversion of unsupported type to number")
	}
}

// get prim float64 from supported types
func getFloat(col interface{}) (float64, error) {
	var err error
	col, err = getValue(col)
	if err != nil {
		return 0, err
	}
	if col == nil {
		return 0, nil
	}
	rType := reflect.TypeOf(col)
	rValue := reflect.ValueOf(col)
	if tInteger(rType) {
		return float64(rValue.Int()), nil
	}
	if f32, ok := col.(float32); ok {
		return strconv.ParseFloat(fmt.Sprint(f32), 64)
	}
	if tFloat(rType) {
		return rValue.Float(), nil
	}
	switch rType.Kind() {
	case reflect.Bool:
		if rValue.Bool() {
			return 1, nil
		} else {
			return 0, nil
		}
	case reflect.String:
		tempFloat, err := strconv.ParseFloat(rValue.String(), 64)
		if err != nil {
			return 0, err
		}
		return tempFloat, nil
	default:
		return 0, errors.New("conversion of unsupported type to float")
	}
}

// get prim int64 value from supported types
func getInt(col interface{}) (int64, error) {
	var err error
	col, err = getValue(col)
	if err != nil {
		return 0, err
	}
	if col == nil {
		return 0, nil
	}
	rType := reflect.TypeOf(col)
	rValue := reflect.ValueOf(col)
	if tInteger(rType) {
		return rValue.Int(), nil
	}
	if tFloat(rType) {
		return int64(rValue.Float()), nil
	}
	switch rType.Kind() {
	case reflect.String:
		tempInt, err := strconv.ParseInt(rValue.String(), 10, 64)
		if err != nil {
			return 0, err
		}
		return tempInt, nil
	case reflect.Bool:
		if rValue.Bool() {
			return 1, nil
		} else {
			return 0, nil
		}
	default:
		return 0, errors.New("conversion of unsupported type to int")
	}
}

// get prim time.Time from supported types
func getDate(col interface{}) (time.Time, error) {
	var err error
	col, err = getValue(col)
	if err != nil {
		return time.Time{}, err
	}
	if col == nil {
		return time.Time{}, nil
	}
	switch val := col.(type) {
	case time.Time:
		return val, nil
	case TimeStamp:
		return time.Time(val), nil
	case TimeStampTZ:
		return time.Time(val), nil
	case string:
		return time.Parse(time.RFC3339, val)
	default:
		return time.Time{}, errors.New("conversion of unsupported type to time.Time")
	}
}

// get prim []byte from supported types
func getBytes(col interface{}) ([]byte, error) {
	var err error
	col, err = getValue(col)
	if err != nil {
		return nil, err
	}
	if col == nil {
		return nil, nil
	}
	switch val := col.(type) {
	case []byte:
		return val, nil
	case string:
		return []byte(val), nil
	case Blob:
		return val.Data, nil
	default:
		return nil, errors.New("conversion of unsupported type to []byte")
	}
}

// get prim lob from supported types
func getLob(col interface{}, conn *Connection) (*Lob, error) {
	var err error
	col, err = getValue(col)
	if err != nil {
		return nil, err
	}
	if col == nil {
		return nil, nil
	}
	charsetID := conn.tcpNego.ServerCharset
	charsetForm := 1
	stringVar := ""
	var byteVar []byte
	switch val := col.(type) {
	case string:
		stringVar = val
	case Clob:
		stringVar = val.String
	case NVarChar:
		stringVar = string(val)
		charsetForm = 2
		charsetID = conn.tcpNego.ServernCharset
	case NClob:
		stringVar = val.String
		charsetForm = 2
		charsetID = conn.tcpNego.ServernCharset
	case []byte:
		byteVar = val
	case Blob:
		byteVar = val.Data
	}
	if len(stringVar) > 0 {
		lob := newLob(conn)
		err = lob.createTemporaryClob(charsetID, charsetForm)
		if err != nil {
			return nil, err
		}
		err = lob.putString(stringVar)
		return lob, err
	}
	if len(byteVar) > 0 {
		lob := newLob(conn)
		err = lob.createTemporaryBLOB()
		if err != nil {
			return nil, err
		}
		err = lob.putData(byteVar)
		return lob, err
	}
	return nil, nil
}

//=============================================================//

func setBytes(value reflect.Value, input []byte) error {
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setBytes(value.Elem(), input)
	}
	switch value.Kind() {
	case reflect.String:
		value.SetString(string(input))
		return nil
	}
	switch value.Type() {
	case tyBytes:
		value.SetBytes(input)
	case tyNVarChar:
		value.Set(reflect.ValueOf(NVarChar(input)))
	case tyBlob:
		value.Set(reflect.ValueOf(Blob{Data: input, Valid: true}))
	case tyClob:
		value.Set(reflect.ValueOf(Clob{String: string(input), Valid: true}))
	case tyNClob:
		value.Set(reflect.ValueOf(NClob{String: string(input), Valid: true}))
	case tyNullString:
		value.Set(reflect.ValueOf(sql.NullString{string(input), true}))
	case tyNullNVarChar:
		value.Set(reflect.ValueOf(NullNVarChar{NVarChar(input), true}))
	default:
		return fmt.Errorf("can not assign []byte to type: %v", value.Type().Name())
	}
	return nil
}
func setTime(value reflect.Value, input time.Time) error {
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setTime(value.Elem(), input)
	}
	switch value.Kind() {
	case reflect.String:
		value.SetString(input.Format(time.RFC3339))
		return nil
	}
	switch value.Type() {
	case tyTime:
		value.Set(reflect.ValueOf(input))
	case tyTimeStamp:
		value.Set(reflect.ValueOf(TimeStamp(input)))
	case tyTimeStampTZ:
		value.Set(reflect.ValueOf(TimeStampTZ(input)))
	case tyNullString:
		value.Set(reflect.ValueOf(sql.NullString{input.Format(time.RFC3339), true}))
	case tyNullTime:
		value.Set(reflect.ValueOf(sql.NullTime{input, true}))
	case tyNullTimeStamp:
		value.Set(reflect.ValueOf(NullTimeStamp{TimeStamp(input), true}))
	case tyNullTimeStampTZ:
		value.Set(reflect.ValueOf(NullTimeStampTZ{TimeStampTZ(input), true}))
	default:
		return fmt.Errorf("can not assign time to type: %v", value.Type().Name())
	}
	return nil
}
func setFieldValue(fieldValue reflect.Value, cust *customType, input interface{}) error {

	//input should be one of primitive values
	if input == nil {
		return setNull(fieldValue)
	}
	if fieldValue.Kind() == reflect.Ptr && fieldValue.Elem().Kind() == reflect.Interface {
		fieldValue.Elem().Set(reflect.ValueOf(input))
	}
	if fieldValue.Kind() == reflect.Interface {
		fieldValue.Set(reflect.ValueOf(input))
	}
	switch val := input.(type) {
	case int64:
		return setNumber(fieldValue, float64(val))
	case float64:
		return setNumber(fieldValue, val)
	case string:
		return setString(fieldValue, val)
	case time.Time:
		return setTime(fieldValue, val)
	case []byte:
		return setBytes(fieldValue, val)
	case Lob:
		return setLob(fieldValue, val)
	case BFile:
		return setBFile(fieldValue, val)
	case []ParameterInfo:
		return setUDTObject(fieldValue, cust, val)
	default:
		if temp, ok := fieldValue.Interface().(sql.Scanner); ok {
			if temp != nil && !reflect.ValueOf(temp).IsNil() {
				return temp.Scan(input)
			}
		}
		if fieldValue.CanAddr() {
			if temp, ok := fieldValue.Addr().Interface().(sql.Scanner); ok {
				err := temp.Scan(input)
				return err
			}
		}
		return fmt.Errorf("unsupported primitive type: %s", fieldValue.Type().Name())
	}
}
func setNull(value reflect.Value) error {
	if value.Kind() == reflect.Ptr && value.IsNil() {
		return nil
	}
	value.Set(reflect.Zero(value.Type()))
	//value.SetZero()
	return nil
}
func setBFile(value reflect.Value, input BFile) error {
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setBFile(value.Elem(), input)
	}
	switch value.Type() {
	case tyBFile:
		value.Set(reflect.ValueOf(input))
	default:
		return fmt.Errorf("can't assign BFILE to type: %v", value.Type().Name())
	}
	return nil
}
func setArray(value reflect.Value, input []ParameterInfo) error {
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setArray(value.Elem(), input)
	}
	tValue := value.Type()
	tempSlice := reflect.MakeSlice(tValue, 0, len(input))
	for _, par := range input {
		tempObj := reflect.New(tValue.Elem())
		err := setFieldValue(tempObj.Elem(), par.cusType, par.oPrimValue)
		if err != nil {
			return err
		}
		tempSlice = reflect.Append(tempSlice, tempObj.Elem())
	}
	value.Set(tempSlice)
	return nil
}

func setUDTObject(value reflect.Value, cust *customType, input []ParameterInfo) error {
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setUDTObject(value.Elem(), cust, input)
	}
	if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		arrayObj := reflect.MakeSlice(reflect.SliceOf(cust.typ), 0, len(input))
		for _, par := range input {
			if temp, ok := par.oPrimValue.([]ParameterInfo); ok {
				tempObj2 := reflect.New(cust.typ)
				err := setFieldValue(tempObj2.Elem(), par.cusType, temp)
				if err != nil {
					return err
				}
				arrayObj = reflect.Append(arrayObj, tempObj2.Elem())
			}
		}
		value.Set(arrayObj)
	} else {
		tempObj := reflect.New(cust.typ)
		for _, par := range input {

			if fieldIndex, ok := cust.fieldMap[par.Name]; ok {
				err := setFieldValue(tempObj.Elem().Field(fieldIndex), par.cusType, par.oPrimValue)
				if err != nil {
					return err
				}
			}
		}
		value.Set(tempObj.Elem())
	}
	return nil
}

func setLob(value reflect.Value, input Lob) error {
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setLob(value.Elem(), input)
	}
	//dataSize, err := input.getSize()
	//if err != nil {
	//	return err
	//}
	if input.connection == nil || len(input.sourceLocator) == 0 {
		return setNull(value)
	}
	lobData, err := input.getData()
	if err != nil {
		return err
	}
	conn := input.connection
	if len(lobData) == 0 {
		return setNull(value)
	}
	getStrConv := func() (converters.IStringConverter, error) {
		var ret converters.IStringConverter
		if input.variableWidthChar() {
			if conn.dBVersion.Number < 10200 && input.littleEndianClob() {
				ret, _ = conn.getStrConv(2002)
			} else {
				ret, _ = conn.getStrConv(2000)
			}
		} else {
			ret, err = conn.getStrConv(input.charsetID)
			if err != nil {
				return nil, err
			}
		}
		return ret, nil
	}
	var strConv converters.IStringConverter
	switch value.Kind() {
	case reflect.String:
		strConv, err = getStrConv()
		if err != nil {
			return err
		}
		value.SetString(strConv.Decode(lobData))
		return nil
	}
	switch value.Type() {
	case tyNullString:
		strConv, err = getStrConv()
		if err != nil {
			return err
		}
		value.Set(reflect.ValueOf(sql.NullString{strConv.Decode(lobData), true}))
	case tyNVarChar:
		strConv, err = getStrConv()
		if err != nil {
			return err
		}
		value.Set(reflect.ValueOf(NVarChar(strConv.Decode(lobData))))
	case tyNullNVarChar:
		strConv, err = getStrConv()
		if err != nil {
			return err
		}
		value.Set(reflect.ValueOf(NullNVarChar{NVarChar(strConv.Decode(lobData)), true}))
	case tyClob:
		strConv, err = getStrConv()
		if err != nil {
			return err
		}
		value.Set(reflect.ValueOf(Clob{
			String:  strConv.Decode(lobData),
			Valid:   true,
			locator: input.sourceLocator}))
	case tyNClob:
		strConv, err = getStrConv()
		if err != nil {
			return err
		}
		value.Set(reflect.ValueOf(NClob{
			String:  strConv.Decode(lobData),
			Valid:   true,
			locator: input.sourceLocator}))
	case tyBlob:
		value.Set(reflect.ValueOf(Blob{
			Data:    lobData,
			Valid:   true,
			locator: input.sourceLocator}))
	case tyBytes:
		value.Set(reflect.ValueOf(lobData))
	default:
		return fmt.Errorf("can't assign LOB to type: %v", value.Type().Name())
	}
	return nil
}

func setString(value reflect.Value, input string) error {
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setString(value.Elem(), input)
	}
	var intErr, floatErr, timeErr error
	tempInt, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		intErr = fmt.Errorf(`can't assign string "%v" to int variable`, input)
	}
	tempFloat, err := strconv.ParseFloat(input, 64)
	if err != nil {
		floatErr = fmt.Errorf(`can't assign string "%v" to float variablle`, input)
	}
	tempTime, err := time.Parse(time.RFC3339, input)
	if err != nil {
		timeErr = fmt.Errorf(`can't assign string "%v" to time.Time variable`, input)
	}
	if tSigned(value.Type()) {
		if intErr == nil {
			value.SetInt(tempInt)
		}
		return intErr
	}
	if tUnsigned(value.Type()) {
		if intErr == nil {
			value.SetUint(uint64(tempInt))
		}
		return intErr
	}
	if tFloat(value.Type()) {
		if floatErr == nil {
			value.SetFloat(tempFloat)
		}
		return floatErr
	}
	switch value.Kind() {
	case reflect.String:
		value.SetString(input)
		return nil
	case reflect.Bool:
		if strings.ToLower(input) == "true" {
			value.SetBool(true)
		} else {
			value.SetBool(false)
		}
		return nil
	}
	switch value.Type() {
	case tyNullString:
		value.Set(reflect.ValueOf(sql.NullString{input, true}))
	case tyNullByte:
		if intErr == nil {
			value.Set(reflect.ValueOf(sql.NullByte{uint8(tempInt), true}))
		}
		return intErr
	case tyNullInt16:
		if intErr == nil {
			value.Set(reflect.ValueOf(sql.NullInt16{int16(tempInt), true}))
		}
		return intErr
	case tyNullInt32:
		if intErr == nil {
			value.Set(reflect.ValueOf(sql.NullInt32{int32(tempInt), true}))
		}
		return intErr
	case tyNullInt64:
		if intErr == nil {
			value.Set(reflect.ValueOf(sql.NullInt64{tempInt, true}))
		}
		return intErr
	case tyNullFloat64:
		if floatErr == nil {
			value.Set(reflect.ValueOf(sql.NullFloat64{float64(tempInt), true}))
		}
		return floatErr
	case tyNullBool:
		temp := strings.ToLower(input) == "true"
		value.Set(reflect.ValueOf(sql.NullBool{temp, true}))
	case tyNVarChar:
		value.Set(reflect.ValueOf(NVarChar(input)))
	case tyNullNVarChar:
		value.Set(reflect.ValueOf(NullNVarChar{NVarChar(input), true}))
	case tyTime:
		if timeErr == nil {
			value.Set(reflect.ValueOf(tempTime))
		}
		return timeErr
	case tyNullTime:
		if timeErr == nil {
			value.Set(reflect.ValueOf(sql.NullTime{tempTime, true}))
		}
		return timeErr
	case tyTimeStamp:
		if timeErr == nil {
			value.Set(reflect.ValueOf(TimeStamp(tempTime)))
		}
		return timeErr
	case tyNullTimeStamp:
		if timeErr == nil {
			value.Set(reflect.ValueOf(NullTimeStamp{TimeStamp(tempTime), true}))
		}
		return timeErr
	case tyTimeStampTZ:
		if timeErr == nil {
			value.Set(reflect.ValueOf(TimeStampTZ(tempTime)))
		}
		return timeErr
	case tyNullTimeStampTZ:
		if timeErr == nil {
			value.Set(reflect.ValueOf(NullTimeStampTZ{TimeStampTZ(tempTime), true}))
		}
		return timeErr
	case tyClob:
		value.Set(reflect.ValueOf(Clob{String: input, Valid: true}))
	case tyNClob:
		value.Set(reflect.ValueOf(NClob{String: input, Valid: true}))
	default:
		return fmt.Errorf("can not assign string to type: %v", value.Type().Name())
	}
	return nil
}

//	func setInt(value reflect.Value, input int64) error {
//		if value.Kind() == reflect.Ptr && value.IsNil() {
//			value.Set(reflect.New(value.Type().Elem()))
//			return setInt(value.Elem(), input)
//		}
//		if tSigned(value.Type()) {
//			value.SetInt(input)
//			return nil
//		}
//		if tUnsigned(value.Type()) {
//			value.SetUint(uint64(input))
//			return nil
//		}
//		if tFloat(value.Type()) {
//			value.SetFloat(float64(input))
//			return nil
//		}
//	}

func setNumber(value reflect.Value, input float64) error {
	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		return setNumber(value.Elem(), input)
	}
	if tSigned(value.Type()) {
		value.SetInt(int64(input))
		return nil
	}
	if tUnsigned(value.Type()) {
		value.SetUint(uint64(input))
		return nil
	}
	if tFloat(value.Type()) {
		value.SetFloat(input)
		return nil
	}
	switch value.Kind() {
	case reflect.Bool:
		value.SetBool(input != 0)
		return nil
	case reflect.String:
		value.SetString(fmt.Sprintf("%v", input))
		return nil
	}
	switch value.Type() {
	case tyNullString:
		value.Set(reflect.ValueOf(sql.NullString{fmt.Sprintf("%v", input), true}))
	case tyNullByte:
		value.Set(reflect.ValueOf(sql.NullByte{uint8(input), true}))
	case tyNullInt16:
		value.Set(reflect.ValueOf(sql.NullInt16{int16(input), true}))
	case tyNullInt32:
		value.Set(reflect.ValueOf(sql.NullInt32{int32(input), true}))
	case tyNullInt64:
		value.Set(reflect.ValueOf(sql.NullInt64{int64(input), true}))
	case tyNullFloat64:
		value.Set(reflect.ValueOf(sql.NullFloat64{input, true}))
	case tyNullBool:
		value.Set(reflect.ValueOf(sql.NullBool{input != 0, true}))
	case tyNullNVarChar:
		value.Set(reflect.ValueOf(NullNVarChar{NVarChar(fmt.Sprintf("%v", input)), true}))
	default:
		return fmt.Errorf("can not assign number to type: %v", value.Type().Name())
	}
	return nil
}

func isBadConn(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE)
}

func collectLocators(pars []ParameterInfo) [][]byte {
	output := make([][]byte, 0, 10)
	for _, par := range pars {
		switch value := par.iPrimValue.(type) {
		case *Lob:
			if value != nil && value.sourceLocator != nil {
				output = append(output, value.sourceLocator)
			}
		case *BFile:
			if value != nil && value.lob.sourceLocator != nil {
				output = append(output, value.lob.sourceLocator)
			}
		case []ParameterInfo:
			temp := collectLocators(value)
			output = append(output, temp...)
		}
	}
	return output
}

//func initializePtr(v interface{}) {
//	rv := reflect.ValueOf(v).Elem()
//	rv.Set(reflect.New(rv.Type().Elem()))
//}

func getTOID(conn *Connection, owner, typeName string) ([]byte, error) {
	sqlText := `SELECT type_oid FROM ALL_TYPES WHERE UPPER(OWNER)=:1 AND UPPER(TYPE_NAME)=:2`
	stmt := NewStmt(sqlText, conn)
	defer func(stmt *Stmt) {
		_ = stmt.Close()
	}(stmt)
	var ret []byte
	rows, err := stmt.Query_([]driver.NamedValue{driver.NamedValue{Value: strings.ToUpper(owner)},
		driver.NamedValue{Value: strings.ToUpper(typeName)}})
	if err != nil {
		return nil, err
	}
	if rows.Next_() {
		err = rows.Scan(&ret)
		if err != nil {
			return nil, err
		}
	}
	if len(ret) == 0 {
		return nil, fmt.Errorf("unknown type: %s", typeName)
	}
	return ret, rows.Err()
}

func encodeObject(session *network.Session, objectData []byte, isArray bool) []byte {
	size := len(objectData)
	fieldsData := bytes.Buffer{}
	if isArray {
		fieldsData.Write([]byte{0x88, 0x1})
	} else {
		fieldsData.Write([]byte{0x84, 0x1})
	}
	if (size + 7) < 0xfe {
		size += 3
		fieldsData.Write([]byte{uint8(size)})
	} else {
		size += 7
		fieldsData.Write([]byte{0xfe})
		session.WriteInt(&fieldsData, size, 4, true, false)
	}
	fieldsData.Write(objectData)
	return fieldsData.Bytes()
}

func decodeObject(conn *Connection, parent *ParameterInfo) error {
	session := conn.session
	newState := network.SessionState{InBuffer: parent.BValue}
	session.SaveState(&newState)
	objectType, err := session.GetByte()
	if err != nil {
		return err
	}
	ctl, err := session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	if ctl == 0xFE {
		_, err = session.GetInt(4, false, true)
		if err != nil {
			return err
		}
	}
	switch objectType {
	case 0x88:
		_ /*attribsLen*/, err := session.GetInt(2, true, true)
		if err != nil {
			return err
		}

		itemsLen, err := session.GetInt(2, false, true)
		if err != nil {
			return err
		}
		pars := make([]ParameterInfo, 0, itemsLen)
		for x := 0; x < itemsLen; x++ {
			tempPar := parent.clone()
			tempPar.Direction = parent.Direction
			ctlByte, err := session.GetByte()
			if err != nil {
				return err
			}
			var objectBufferSize int
			if ctlByte == 0xFE {
				objectBufferSize, err = session.GetInt(4, false, true)
				if err != nil {
					return err
				}
			} else {
				objectBufferSize = int(ctlByte)
			}
			tempPar.BValue, err = session.GetBytes(objectBufferSize)
			if err != nil {
				return err
			}
			err = decodeObject(conn, &tempPar)
			if err != nil {
				return err
			}
			pars = append(pars, tempPar)
		}
		parent.oPrimValue = pars
	case 0x84:
		pars := make([]ParameterInfo, 0, len(parent.cusType.attribs))
		for _, attrib := range parent.cusType.attribs {
			tempPar := attrib
			tempPar.Direction = parent.Direction
			err = tempPar.decodePrimValue(conn, true)
			if err != nil {
				return err
			}
			pars = append(pars, tempPar)
		}
		parent.oPrimValue = pars
	}
	_ = session.LoadState()
	return nil
}
