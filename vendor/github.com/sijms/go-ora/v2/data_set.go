package go_ora

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
	"github.com/sijms/go-ora/v2/trace"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Compile time Sentinels for implemented Interfaces.
var _ = driver.Rows((*DataSet)(nil))
var _ = driver.RowsColumnTypeDatabaseTypeName((*DataSet)(nil))
var _ = driver.RowsColumnTypeLength((*DataSet)(nil))
var _ = driver.RowsColumnTypeNullable((*DataSet)(nil))

// var _ = driver.RowsColumnTypePrecisionScale((*DataSet)(nil))
// var _ = driver.RowsColumnTypeScanType((*DataSet)(nil))
// var _ = driver.RowsNextResultSet((*DataSet)(nil))

type Row []driver.Value

type DataSet struct {
	columnCount     int
	rowCount        int
	uACBufferLength int
	maxRowSize      int
	Cols            []ParameterInfo
	rows            []Row
	currentRow      Row
	lasterr         error
	index           int
	parent          StmtInterface
}

// load Loading dataset information from network session
func (dataSet *DataSet) load(session *network.Session) error {
	_, err := session.GetByte()
	if err != nil {
		return err
	}
	columnCount, err := session.GetInt(2, true, true)
	if err != nil {
		return err
	}
	num, err := session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	columnCount += num * 0x100
	if columnCount > dataSet.columnCount {
		dataSet.columnCount = columnCount
	}
	if len(dataSet.currentRow) != dataSet.columnCount {
		dataSet.currentRow = make(Row, dataSet.columnCount)
	}
	dataSet.rowCount, err = session.GetInt(4, true, true)
	if err != nil {
		return err
	}
	dataSet.uACBufferLength, err = session.GetInt(2, true, true)
	if err != nil {
		return err
	}
	bitVector, err := session.GetDlc()
	if err != nil {
		return err
	}
	dataSet.setBitVector(bitVector)
	_, err = session.GetDlc()
	return nil
}

// setBitVector bit vector is an array of bit that define which column need to be read
// from network session
func (dataSet *DataSet) setBitVector(bitVector []byte) {
	index := dataSet.columnCount / 8
	if dataSet.columnCount%8 > 0 {
		index++
	}
	if len(bitVector) > 0 {
		for x := 0; x < len(bitVector); x++ {
			for i := 0; i < 8; i++ {
				if (x*8)+i < dataSet.columnCount {
					dataSet.Cols[(x*8)+i].getDataFromServer = bitVector[x]&(1<<i) > 0
				}
			}
		}
	} else {
		for x := 0; x < len(dataSet.Cols); x++ {
			dataSet.Cols[x].getDataFromServer = true
		}
	}

}

func (dataSet *DataSet) Close() error {
	if dataSet.parent.CanAutoClose() {
		return dataSet.parent.Close()
	}
	return nil
}

// Next_ act like Next in sql package return false if no other rows in dataset
func (dataSet *DataSet) Next_() bool {
	err := dataSet.Next(dataSet.currentRow)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return false
		}
		dataSet.lasterr = err
		return false
	}

	return true
}

// Scan act like scan in sql package return row values to dest variable pointers
func (dataSet *DataSet) Scan(dest ...interface{}) error {
	if dataSet.lasterr != nil {
		return dataSet.lasterr
	}
	for srcIndex, destIndex := 0, 0; srcIndex < len(dataSet.currentRow); srcIndex, destIndex = srcIndex+1, destIndex+1 {
		if destIndex >= len(dest) {
			return errors.New("go-ora: mismatching between Scan function input count and column count")
		}
		if dest[destIndex] == nil {
			return fmt.Errorf("go-ora: argument %d is nil", destIndex)
		}
		destTyp := reflect.TypeOf(dest[destIndex])
		if destTyp.Kind() != reflect.Ptr {
			return errors.New("go-ora: argument in scan should be passed as pointers")
		}
		col := dataSet.currentRow[srcIndex]
		result, err := dataSet.setObjectValue(reflect.ValueOf(dest[destIndex]).Elem(), srcIndex)
		if err != nil {
			return err
		}
		if result {
			continue
		}
		if destTyp.Elem().Kind() != reflect.Struct {
			return fmt.Errorf("go-ora: column %d require type %v", srcIndex, reflect.TypeOf(col))
		}
		processedFields := 0
		for x := 0; x < destTyp.Elem().NumField(); x++ {
			if srcIndex+processedFields >= len(dataSet.currentRow) {
				continue
				//return errors.New("go-ora: mismatching between Scan function input count and column count")
			}
			//col := dataSet.currentRow[srcIndex + processedFields]
			f := destTyp.Elem().Field(x)
			tag := f.Tag.Get("db")
			if len(tag) == 0 {
				continue
			}
			tag = strings.Trim(tag, "\"")
			parts := strings.Split(tag, ",")
			for _, part := range parts {
				subs := strings.Split(part, ":")
				if len(subs) != 2 {
					continue
				}
				if strings.TrimSpace(strings.ToLower(subs[0])) == "name" {
					fieldID := strings.TrimSpace(strings.ToUpper(subs[1]))
					colInfo := dataSet.Cols[srcIndex+processedFields]
					if strings.ToUpper(colInfo.Name) != fieldID {
						continue
						//return fmt.Errorf(
						//	"go-ora: column %d name %s is mismatching with tag name %s of structure field",
						//	srcIndex+processedFields, colInfo.Name, fieldID)
					}
					result, err := dataSet.setObjectValue(reflect.ValueOf(dest[destIndex]).Elem().Field(x), srcIndex+processedFields)
					if err != nil {
						return err
					}
					if !result {
						return errors.New("only basic types are allowed inside struct object")
					}
					processedFields++
				}
			}
		}
		if processedFields == 0 {
			return errors.New("passing struct to scan without matching tags")
		}
		srcIndex = srcIndex + processedFields - 1

	}
	return nil
}

// set object value using currentRow[colIndex] return true if succeed or false
// for non-supported type
// error means error occur during operation
func (dataSet DataSet) setObjectValue(obj reflect.Value, colIndex int) (bool, error) {
	field := dataSet.currentRow[colIndex]
	col := dataSet.Cols[colIndex]
	if col.cusType != nil && col.cusType.typ == obj.Type() {
		obj.Set(reflect.ValueOf(field))
		return true, nil
	}
	if temp, ok := obj.Interface().(sql.Scanner); ok {
		err := temp.Scan(field)
		return err == nil, err
	}
	if obj.CanAddr() {
		if temp, ok := obj.Addr().Interface().(sql.Scanner); ok {
			err := temp.Scan(field)
			return err == nil, err
		}
	}
	switch obj.Type().Kind() {
	case reflect.String:
		obj.SetString(getString(field))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		temp, err := getInt(field)
		if err != nil {
			return false, fmt.Errorf("go-ora: column %d require an integer", colIndex)
		}
		obj.SetInt(temp)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		temp, err := getInt(field)
		if err != nil {
			return false, fmt.Errorf("go-ora: column %d require an integer", colIndex)
		}
		obj.SetUint(uint64(temp))
	case reflect.Float32, reflect.Float64:
		temp, err := getFloat(field)
		if err != nil {
			return false, fmt.Errorf("go-ora: column %d require type float", colIndex)
		}
		obj.SetFloat(temp)
	default:
		switch obj.Type() {
		case reflect.TypeOf(time.Time{}):
			switch tempField := field.(type) {
			case time.Time:
				obj.Set(reflect.ValueOf(field))
			case TimeStamp:
				obj.Set(reflect.ValueOf(time.Time(tempField)))
			default:
				return false, fmt.Errorf("go-ora: column %d require type time.Time", colIndex)
			}
		case reflect.TypeOf([]byte{}):
			if _, ok := field.([]byte); ok {
				obj.Set(reflect.ValueOf(field))
			} else {
				return false, fmt.Errorf("go-ora: column %d require type []byte", colIndex)
			}
		//case reflect.TypeOf(sql.NullTime{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(sql.NullTime{Valid: false}))
		//	} else {
		//		switch tempField := field.(type) {
		//		case time.Time:
		//			obj.Set(reflect.ValueOf(sql.NullTime{Valid: true, Time: tempField}))
		//		case TimeStamp:
		//			obj.Set(reflect.ValueOf(sql.NullTime{Valid: true, Time: time.Time(tempField)}))
		//		default:
		//			return false, fmt.Errorf("go-ora: column %d require type time.Time or null", colIndex)
		//		}
		//	}
		//case reflect.TypeOf(NullTimeStamp{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(NullTimeStamp{Valid: false}))
		//	} else {
		//		switch tempField := field.(type) {
		//		case time.Time:
		//			obj.Set(reflect.ValueOf(NullTimeStamp{Valid: true, TimeStamp: TimeStamp(tempField)}))
		//		case TimeStamp:
		//			obj.Set(reflect.ValueOf(NullTimeStamp{Valid: true, TimeStamp: tempField}))
		//		default:
		//			return false, fmt.Errorf("go-ora: column %d require type time.Time or null", colIndex)
		//		}
		//	}
		//case reflect.TypeOf(sql.NullString{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(sql.NullString{Valid: false}))
		//	} else {
		//		obj.Set(reflect.ValueOf(sql.NullString{Valid: true, String: getString(field)}))
		//	}
		//case reflect.TypeOf(NullNVarChar{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(NullNVarChar{Valid: false}))
		//	} else {
		//		obj.Set(reflect.ValueOf(NullNVarChar{Valid: true, NVarChar: NVarChar(getString(field))}))
		//	}
		//case reflect.TypeOf(sql.NullBool{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(sql.NullBool{Valid: false}))
		//	} else {
		//		tempInt, err := getInt(field)
		//		if err != nil {
		//			return false, err
		//		}
		//		obj.Set(reflect.ValueOf(sql.NullBool{Valid: true, Bool: tempInt != 0}))
		//	}
		//case reflect.TypeOf(sql.NullFloat64{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(sql.NullFloat64{Valid: false}))
		//	} else {
		//		tempFloat, err := getFloat(field)
		//		if err != nil {
		//			return false, err
		//		}
		//		obj.Set(reflect.ValueOf(sql.NullFloat64{Valid: true, Float64: tempFloat}))
		//	}
		//case reflect.TypeOf(sql.NullInt64{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(sql.NullInt64{Valid: false}))
		//	} else {
		//		tempInt, err := getInt(field)
		//		if err != nil {
		//			return false, err
		//		}
		//		obj.Set(reflect.ValueOf(sql.NullInt64{Valid: true, Int64: tempInt}))
		//	}
		//case reflect.TypeOf(sql.NullInt32{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(sql.NullInt32{Valid: false}))
		//	} else {
		//		tempInt, err := getInt(field)
		//		if err != nil {
		//			return false, err
		//		}
		//		obj.Set(reflect.ValueOf(sql.NullInt32{Valid: true, Int32: int32(tempInt)}))
		//	}
		//case reflect.TypeOf(sql.NullInt16{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(sql.NullInt16{Valid: false}))
		//	} else {
		//		tempInt, err := getInt(field)
		//		if err != nil {
		//			return false, err
		//		}
		//		obj.Set(reflect.ValueOf(sql.NullInt16{Valid: true, Int16: int16(tempInt)}))
		//	}
		//case reflect.TypeOf(sql.NullByte{}):
		//	if field == nil {
		//		obj.Set(reflect.ValueOf(sql.NullByte{Valid: false}))
		//	} else {
		//		tempInt, err := getInt(field)
		//		if err != nil {
		//			return false, err
		//		}
		//		obj.Set(reflect.ValueOf(sql.NullByte{Valid: true, Byte: uint8(tempInt)}))
		//	}
		//case reflect.TypeOf(BFile{}):
		//	obj.Set(reflect.ValueOf(field))
		default:
			return false, nil
		}
	}
	return true, nil
}

// try to get string data from row field
func getString(col interface{}) string {
	if temp, ok := col.(string); ok {
		return temp
	} else {
		return fmt.Sprintf("%v", col)
	}
}

// try to get float64 data from row field
func getFloat(col interface{}) (float64, error) {
	if temp, ok := col.(float64); ok {
		return temp, nil
	} else if temp, ok := col.(int64); ok {
		return float64(temp), nil
	} else if temp, ok := col.(string); ok {
		tempFloat, err := strconv.ParseFloat(temp, 64)
		if err != nil {
			return 0, err
		}
		return tempFloat, nil
	} else {
		return 0, errors.New("unkown type")
	}
}

// try to get int64 value from the row field
func getInt(col interface{}) (int64, error) {
	if temp, ok := col.(int64); ok {
		return temp, nil
	} else if temp, ok := col.(float64); ok {
		return int64(temp), nil
	} else if temp, ok := col.(string); ok {
		tempInt, err := strconv.ParseInt(temp, 10, 64)
		if err != nil {
			return 0, err
		}
		return tempInt, nil
	} else {
		return 0, errors.New("unkown type")
	}
}

func (dataSet *DataSet) Err() error {
	return dataSet.lasterr
}

// Next implement method need for sql.Rows interface
func (dataSet *DataSet) Next(dest []driver.Value) error {
	hasMoreRows := dataSet.parent.hasMoreRows()
	noOfRowsToFetch := len(dataSet.rows) // dataSet.parent.noOfRowsToFetch()
	if noOfRowsToFetch == 0 {
		return io.EOF
	}
	//hasBLOB := dataSet.parent.hasBLOB()
	//hasLONG := dataSet.parent.hasLONG()
	if !hasMoreRows && noOfRowsToFetch == 0 {
		return io.EOF
	}
	if dataSet.index > 0 && dataSet.index%len(dataSet.rows) == 0 {
		if hasMoreRows {
			dataSet.rows = make([]Row, 0, dataSet.parent.noOfRowsToFetch())
			err := dataSet.parent.fetch(dataSet)
			if err != nil {
				return err
			}
			noOfRowsToFetch = len(dataSet.rows)
			hasMoreRows = dataSet.parent.hasMoreRows()
			dataSet.index = 0
			if !hasMoreRows && noOfRowsToFetch == 0 {
				return io.EOF
			}
		} else {
			return io.EOF
		}
	}
	//if hasMoreRows && (hasBLOB || hasLONG) && dataSet.index == 0 {
	//	//dataSet.rows = make([]Row, 0, dataSet.parent.noOfRowsToFetch())
	//	if err := dataSet.parent.fetch(dataSet); err != nil {
	//		return err
	//	}
	//}
	if dataSet.index%noOfRowsToFetch < len(dataSet.rows) {
		for x := 0; x < len(dataSet.rows[dataSet.index%noOfRowsToFetch]); x++ {
			dest[x] = dataSet.rows[dataSet.index%noOfRowsToFetch][x]
		}
		dataSet.index++
		return nil
	}
	return io.EOF
}

//func (dataSet *DataSet) NextRow(args... interface{}) error {
//	var values = make([]driver.Value, len(args))
//	err := dataSet.Next(values)
//	if err != nil {
//		return err
//	}
//	for index, arg := range args {
//		*arg = values[index]
//		//if val, ok := values[index].(t); !ok {
//		//
//		//}
//	}
//	return nil
//}

// Columns return a string array that represent columns names
func (dataSet *DataSet) Columns() []string {
	if len(dataSet.Cols) == 0 {
		return nil
	}
	ret := make([]string, len(dataSet.Cols))
	for x := 0; x < len(dataSet.Cols); x++ {
		ret[x] = dataSet.Cols[x].Name
	}
	return ret
}

func (dataSet DataSet) Trace(t trace.Tracer) {
	for r, row := range dataSet.rows {
		if r > 25 {
			break
		}
		t.Printf("Row %d", r)
		for c, col := range dataSet.Cols {
			t.Printf("  %-20s: %v", col.Name, row[c])
		}
	}
}

// ColumnTypeDatabaseTypeName return Col DataType name
func (dataSet DataSet) ColumnTypeDatabaseTypeName(index int) string {
	return dataSet.Cols[index].DataType.String()
}

// ColumnTypeLength return length of column type
func (dataSet DataSet) ColumnTypeLength(index int) (length int64, ok bool) {
	length = int64(len(dataSet.Cols[index].BValue))
	ok = true
	return
	//switch dataSet.Cols[index].DataType {
	//case NCHAR, CHAR:
	//	return int64(dataSet.Cols[index].MaxCharLen), true
	//case NUMBER:
	//	return int64(dataSet.Cols[index].Precision), true
	//}
	//return int64(0), false

}

// ColumnTypeNullable return if column allow null or not
func (dataSet DataSet) ColumnTypeNullable(index int) (nullable, ok bool) {
	return dataSet.Cols[index].AllowNull, true
}
