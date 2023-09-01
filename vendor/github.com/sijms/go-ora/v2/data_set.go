package go_ora

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/sijms/go-ora/v2/network"
	"github.com/sijms/go-ora/v2/trace"
)

// Compile time Sentinels for implemented Interfaces.
var _ = driver.Rows((*DataSet)(nil))
var _ = driver.RowsColumnTypeDatabaseTypeName((*DataSet)(nil))
var _ = driver.RowsColumnTypeLength((*DataSet)(nil))
var _ = driver.RowsColumnTypeNullable((*DataSet)(nil))
var _ = driver.RowsColumnTypePrecisionScale((*DataSet)(nil))

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
		destTyp = destTyp.Elem()

		// if struct and tag
		if destTyp.Kind() == reflect.Struct {
			processedFields := 0
			for x := 0; x < destTyp.NumField(); x++ {
				if srcIndex+processedFields >= len(dataSet.currentRow) {
					continue
				}
				field := destTyp.Field(x)
				name, _, _, _ := extractTag(field.Tag.Get("db"))
				if len(name) == 0 {
					continue
				}
				colInfo := dataSet.Cols[srcIndex+processedFields]
				if strings.ToUpper(colInfo.Name) != strings.ToUpper(name) {
					continue
				}
				err := dataSet.setObjectValue(reflect.ValueOf(dest[destIndex]).Elem().Field(x), srcIndex+processedFields)
				//err := setFieldValue(reflect.ValueOf(dest[destIndex]).Elem().Field(x), colInfo.cusType, dataSet.currentRow[srcIndex+processedFields])
				if err != nil {
					return err
				}
				processedFields++
			}
			if processedFields != 0 {
				srcIndex = srcIndex + processedFields - 1
				continue
			}

		}
		// else
		err := dataSet.setObjectValue(reflect.ValueOf(dest[destIndex]).Elem(), srcIndex)
		if err != nil {
			return err
		}
		// first check if the input is struct
		// if struct is custom type finish it
		// other structure should support db tag
		// non structure input
		//result, err := dataSet.setObjectValue(reflect.ValueOf(dest[destIndex]).Elem(), srcIndex)
		//if err != nil {
		//	return err
		//}
		//if result {
		//	continue
		//}
	}
	return nil
}

// set object value using currentRow[colIndex] return true if succeed or false
// for non-supported type
// error means error occur during operation
func (dataSet *DataSet) setObjectValue(obj reflect.Value, colIndex int) error {
	value := dataSet.currentRow[colIndex]
	col := dataSet.Cols[colIndex]
	if value == nil {
		return setNull(obj)
	}
	if obj.Kind() == reflect.Interface {
		obj.Set(reflect.ValueOf(value))
		return nil
	}
	switch val := value.(type) {
	case int64:
		return setNumber(obj, float64(val))
	case float64:
		return setNumber(obj, val)
	case string:
		return setString(obj, val)
	case time.Time:
		return setTime(obj, val)
	case []byte:
		return setBytes(obj, val)
	case bool:
		if val {
			return setNumber(obj, 1)
		} else {
			return setNumber(obj, 0)
		}
	default:
		if col.cusType != nil && col.cusType.typ == obj.Type() {
			obj.Set(reflect.ValueOf(value))
			return nil
		}
		return fmt.Errorf("can't assign value: %v to object of type: %v", value, obj.Type().Name())
	}
	//err := setFieldValue(obj, col.cusType, dataSet.currentRow[colIndex])
	//if err != nil {
	//	return err
	//}
	//if col.cusType != nil && col.cusType.typ == obj.Type() {
	//	obj.Set(reflect.ValueOf(field))
	//	return true, nil
	//}
	//return true, setFieldValue(obj, nil, field)

	//if temp, ok := obj.Interface().(sql.Scanner); ok {
	//	err := temp.Scan(field)
	//	return err == nil, err
	//}
	//if obj.CanAddr() {
	//	if temp, ok := obj.Addr().Interface().(sql.Scanner); ok {
	//		err := temp.Scan(field)
	//		return err == nil, err
	//	}
	//}
	//switch obj.Type().Kind() {
	//case reflect.String:
	//	obj.SetString(getString(field))
	//case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	//	temp, err := getInt(field)
	//	if err != nil {
	//		return false, fmt.Errorf("go-ora: column %d require an integer", colIndex)
	//	}
	//	obj.SetInt(temp)
	//case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	//	temp, err := getInt(field)
	//	if err != nil {
	//		return false, fmt.Errorf("go-ora: column %d require an integer", colIndex)
	//	}
	//	obj.SetUint(uint64(temp))
	//case reflect.Float32, reflect.Float64:
	//	temp, err := getFloat(field)
	//	if err != nil {
	//		return false, fmt.Errorf("go-ora: column %d require type float", colIndex)
	//	}
	//	obj.SetFloat(temp)
	//default:
	//	switch obj.Type() {
	//	case reflect.TypeOf(time.Time{}):
	//		switch tempField := field.(type) {
	//		case time.Time:
	//			obj.Set(reflect.ValueOf(field))
	//		case TimeStamp:
	//			obj.Set(reflect.ValueOf(time.Time(tempField)))
	//		default:
	//			return false, fmt.Errorf("go-ora: column %d require type time.Time", colIndex)
	//		}
	//	case reflect.TypeOf([]byte{}):
	//		if _, ok := field.([]byte); ok {
	//			obj.Set(reflect.ValueOf(field))
	//		} else {
	//			return false, fmt.Errorf("go-ora: column %d require type []byte", colIndex)
	//		}
	//	default:
	//		return false, nil
	//	}
	//}
}

func (dataSet *DataSet) Err() error {
	return dataSet.lasterr
}

// Next implement method need for sql.Rows interface
func (dataSet *DataSet) Next(dest []driver.Value) error {
	hasMoreRows := dataSet.parent.hasMoreRows()
	noOfRowsToFetch := len(dataSet.rows) // dataSet.parent.noOfRowsToFetch()
	//if noOfRowsToFetch == 0 {
	//	return io.EOF
	//}
	hasBLOB := dataSet.parent.hasBLOB()
	hasLONG := dataSet.parent.hasLONG()
	if !hasMoreRows && noOfRowsToFetch == 0 {
		return io.EOF
	}
	if hasMoreRows && (hasBLOB || hasLONG) && dataSet.index == 0 {
		//dataSet.rows = make([]Row, 0, dataSet.parent.noOfRowsToFetch())
		if err := dataSet.parent.fetch(dataSet); err != nil {
			return err
		}
		noOfRowsToFetch = len(dataSet.rows)
		hasMoreRows = dataSet.parent.hasMoreRows()
		if !hasMoreRows && noOfRowsToFetch == 0 {
			return io.EOF
		}
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

	if noOfRowsToFetch > 0 && dataSet.index%noOfRowsToFetch < len(dataSet.rows) {
		length := len(dataSet.rows[dataSet.index%noOfRowsToFetch])
		if len(dest) < length {
			length = len(dest)
		}
		for x := 0; x < length; x++ {
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

func (dataSet *DataSet) Trace(t trace.Tracer) {
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
func (dataSet *DataSet) ColumnTypeDatabaseTypeName(index int) string {
	return dataSet.Cols[index].DataType.String()
}

// ColumnTypeLength return length of column type
func (dataSet *DataSet) ColumnTypeLength(index int) (int64, bool) {
	switch dataSet.Cols[index].DataType {
	case NCHAR, CHAR:
		return int64(dataSet.Cols[index].MaxCharLen), true
	}
	return int64(0), false
}

// ColumnTypeNullable return if column allow null or not
func (dataSet *DataSet) ColumnTypeNullable(index int) (nullable, ok bool) {
	return dataSet.Cols[index].AllowNull, true
}

// ColumnTypePrecisionScale return the precision and scale for numeric types
func (dataSet *DataSet) ColumnTypePrecisionScale(index int) (int64, int64, bool) {
	switch dataSet.Cols[index].DataType {
	case NUMBER:
		return int64(dataSet.Cols[index].Precision), int64(dataSet.Cols[index].Scale), true
	}
	return int64(0), int64(0), false
}

func (dataSet *DataSet) ColumnTypeScanType(index int) reflect.Type {
	col := dataSet.Cols[index]
	switch col.DataType {
	case NUMBER:
		if col.Precision > 0 {
			return reflect.TypeOf(float64(0.0))
		} else {
			return reflect.TypeOf(int64(0))
		}
	case ROWID, UROWID:
		fallthrough
	case CHAR, NCHAR:
		fallthrough
	case OCIClobLocator:
		return reflect.TypeOf("")
	case RAW:
		fallthrough
	case OCIBlobLocator, OCIFileLocator:
		return reflect.TypeOf([]byte{})
	case DATE, TIMESTAMP:
		fallthrough
	case TimeStampDTY:
		fallthrough
	case TimeStampeLTZ, TimeStampLTZ_DTY:
		fallthrough
	case TIMESTAMPTZ, TimeStampTZ_DTY:
		return reflect.TypeOf(time.Time{})
	case IBFloat:
		return reflect.TypeOf(float32(0.0))
	case IBDouble:
		return reflect.TypeOf(float64(0.0))
	case IntervalDS_DTY, IntervalYM_DTY:
		return reflect.TypeOf("")
	default:
		return nil
	}
}
