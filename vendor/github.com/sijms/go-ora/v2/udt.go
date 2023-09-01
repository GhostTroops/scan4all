package go_ora

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/converters"
	"reflect"
	"strings"
)

type customType struct {
	owner         string
	name          string
	arrayTypeName string
	attribs       []ParameterInfo
	typ           reflect.Type
	toid          []byte // type oid
	arrayTOID     []byte
	fieldMap      map[string]int
}

// RegisterType register user defined type with owner equal to user id
func (conn *Connection) RegisterType(typeName, arrayTypeName string, typeObj interface{}) error {
	return conn.RegisterTypeWithOwner(conn.connOption.UserID, typeName, arrayTypeName, typeObj)
}

// RegisterTypeWithOwner take typename, owner and go type object and make an information
// structure that used to create a new type during query and store values in it
//
// DataType of UDT field that can be manipulated by this function are: NUMBER,
// VARCHAR2, NVARCHAR2, TIMESTAMP, DATE AND RAW
func (conn *Connection) RegisterTypeWithOwner(owner, typeName, arrayTypeName string, typeObj interface{}) error {
	if typeObj == nil {
		return errors.New("type object cannot be nil")
	}
	typ := reflect.TypeOf(typeObj)
	switch typ.Kind() {
	case reflect.Ptr:
		return errors.New("unsupported type object: Ptr")
	case reflect.Array:
		return errors.New("unsupported type object: Array")
	case reflect.Chan:
		return errors.New("unsupported type object: Chan")
	case reflect.Map:
		return errors.New("unsupported type object: Map")
	case reflect.Slice:
		return errors.New("unsupported type object: Slice")
	}
	if typ.Kind() != reflect.Struct {
		return errors.New("type object should be of structure type")
	}
	cust := customType{
		owner:         owner,
		name:          typeName,
		arrayTypeName: arrayTypeName,
		typ:           typ,
		fieldMap:      map[string]int{},
	}
	var err error
	cust.toid, err = getTOID(conn, cust.owner, cust.name)
	if err != nil {
		return err
	}
	if len(cust.arrayTypeName) > 0 {
		cust.arrayTOID, err = getTOID(conn, cust.owner, cust.arrayTypeName)
		if err != nil {
			return err
		}
	}
	sqlText := `SELECT ATTR_NAME, ATTR_TYPE_NAME, LENGTH, ATTR_NO 
FROM ALL_TYPE_ATTRS WHERE UPPER(OWNER)=:1 AND UPPER(TYPE_NAME)=:2`

	stmt := NewStmt(sqlText, conn)
	defer func(stmt *Stmt) {
		_ = stmt.Close()
	}(stmt)
	rows, err := stmt.Query_([]driver.NamedValue{{Value: strings.ToUpper(owner)}, {Value: strings.ToUpper(typeName)}})
	if err != nil {
		return err
	}
	var (
		attName     sql.NullString
		attOrder    int64
		attTypeName sql.NullString
		length      sql.NullInt64
	)
	for rows.Next_() {
		err = rows.Scan(&attName, &attTypeName, &length, &attOrder)
		if err != nil {
			return err
		}

		for int(attOrder) > len(cust.attribs) {
			cust.attribs = append(cust.attribs, ParameterInfo{
				Direction: Input,
				Flag:      3,
			})
		}
		param := &cust.attribs[attOrder-1]
		param.Name = attName.String
		param.TypeName = attTypeName.String
		switch strings.ToUpper(attTypeName.String) {
		case "NUMBER":
			param.DataType = NUMBER
			param.MaxLen = converters.MAX_LEN_NUMBER
		case "VARCHAR2":
			param.DataType = NCHAR
			param.CharsetForm = 1
			param.ContFlag = 16
			param.MaxCharLen = int(length.Int64)
			param.CharsetID = conn.tcpNego.ServerCharset
			param.MaxLen = int(length.Int64) * converters.MaxBytePerChar(param.CharsetID)
		case "NVARCHAR2":
			param.DataType = NCHAR
			param.CharsetForm = 2
			param.ContFlag = 16
			param.MaxCharLen = int(length.Int64)
			param.CharsetID = conn.tcpNego.ServernCharset
			param.MaxLen = int(length.Int64) * converters.MaxBytePerChar(param.CharsetID)
		case "TIMESTAMP":
			fallthrough
		case "DATE":
			param.DataType = DATE
			param.MaxLen = 11
		case "RAW":
			param.DataType = RAW
			param.MaxLen = int(length.Int64)
		case "BLOB":
			param.DataType = OCIBlobLocator
			param.MaxLen = int(length.Int64)
		case "CLOB":
			param.DataType = OCIClobLocator
			param.CharsetForm = 1
			param.ContFlag = 16
			param.CharsetID = conn.tcpNego.ServerCharset
			param.MaxCharLen = int(length.Int64)
			param.MaxLen = int(length.Int64) * converters.MaxBytePerChar(param.CharsetID)
		case "NCLOB":
			param.DataType = OCIClobLocator
			param.CharsetForm = 2
			param.ContFlag = 16
			param.CharsetID = conn.tcpNego.ServernCharset
			param.MaxCharLen = int(length.Int64)
			param.MaxLen = int(length.Int64) * converters.MaxBytePerChar(param.CharsetID)
		default:
			// search for type in registered types
			found := false
			for name, value := range conn.cusTyp {
				if name == strings.ToUpper(attTypeName.String) {
					found = true
					param.cusType = new(customType)
					*param.cusType = value
					param.ToID = value.toid
					break
				}
				if value.arrayTypeName == strings.ToUpper(attTypeName.String) {
					found = true
					param.cusType = new(customType)
					*param.cusType = value
					param.ToID = value.toid
					break
				}
			}
			if !found {
				return fmt.Errorf("unsupported attribute type: %s", attTypeName.String)
			}
		}
	}
	//for {
	//	err = rows.Next(values)
	//	if err != nil {
	//		if errors.Is(err, io.EOF) {
	//			break
	//		}
	//		return err
	//	}
	//	if attName, ok = values[0].(string); !ok {
	//		return errors.New(fmt.Sprint("error reading attribute properties for type: ", typeName))
	//	}
	//	if attTypeName, ok = values[1].(string); !ok {
	//		return errors.New(fmt.Sprint("error reading attribute properties for type: ", typeName))
	//	}
	//	if values[2] == nil {
	//		length = 0
	//	} else {
	//		if length, ok = values[2].(int64); !ok {
	//			return fmt.Errorf("error reading attribute properties for type: %s", typeName)
	//		}
	//	}
	//	if attOrder, ok = values[3].(int64); !ok {
	//		return fmt.Errorf("error reading attribute properties for type: %s", typeName)
	//	}
	//
	//}
	if len(cust.attribs) == 0 {
		return fmt.Errorf("unknown or empty type: %s", typeName)
	}
	cust.loadFieldMap()
	conn.cusTyp[strings.ToUpper(typeName)] = cust
	return nil
}

// RegisterType2 same as RegisterType but get user defined type data
// with pl/sql package function: dbms_pickler.get_type_shape
//
// DataType of UDT field that can be manipulated by this function are: NUMBER,
// VARCHAR2, NVARCHAR2, TIMESTAMP, DATE AND RAW
//func (conn *Connection) RegisterType2(typeName string, typeObj interface{}) error {
//	if typeObj == nil {
//		return errors.New("type object cannot be nil")
//	}
//	typ := reflect.TypeOf(typeObj)
//	switch typ.Kind() {
//	case reflect.Ptr:
//		return errors.New("unsupported type object: Ptr")
//	case reflect.Array:
//		return errors.New("unsupported type object: Array")
//	case reflect.Chan:
//		return errors.New("unsupported type object: Chan")
//	case reflect.Map:
//		return errors.New("unsupported type object: Map")
//	case reflect.Slice:
//		return errors.New("unsupported type object: Slice")
//	}
//	if typ.Kind() != reflect.Struct {
//		return errors.New("type object should be of structure type")
//	}
//	cust := customType{typ: typ, fieldMap: map[string]int{}}
//	sqlText := `
//DECLARE
//    toid raw(128);
//    vers number;
//    tds long raw;
//    instantiable varchar(100);
//    supertype_owner varchar(100);
//    supertype_name varchar(100);
//    attr_rc sys_refcursor;
//    subtype_rc sys_refcursor;
//    retVal number;
//BEGIN
//	:retVal := dbms_pickler.get_type_shape(:typeName, toid, vers, tds,
//        instantiable, supertype_owner, supertype_name, :att_rc, subtype_rc);
//END;`
//	stmt := NewStmt(sqlText, conn)
//	defer func(stmt *Stmt) {
//		_ = stmt.Close()
//	}(stmt)
//	var cursor RefCursor
//	var ret int64
//	_, err := stmt.Exec([]driver.Value{Out{Dest: &ret}, typeName, Out{Dest: &cursor}})
//	if err != nil {
//		return err
//	}
//	if ret != 0 {
//		return errors.New(fmt.Sprint("unknown type: ", typeName))
//	}
//	defer func(cursor *RefCursor) {
//		_ = cursor.Close()
//	}(&cursor)
//	rows, err := cursor.Query()
//	if err != nil {
//		return err
//	}
//	var (
//		attName     string
//		attOrder    int64
//		attTypeName string
//	)
//	for rows.Next_() {
//		err = rows.Scan(&attName, &attOrder, &attTypeName)
//		if err != nil {
//			return err
//		}
//		for int(attOrder) > len(cust.attribs) {
//			cust.attribs = append(cust.attribs, ParameterInfo{
//				Direction:   Input,
//				Flag:        3,
//				CharsetID:   conn.tcpNego.ServerCharset,
//				CharsetForm: 1,
//			})
//		}
//		param := &cust.attribs[attOrder-1]
//		param.Name = attName
//		param.TypeName = attTypeName
//		switch strings.ToUpper(attTypeName) {
//		case "NUMBER":
//			param.DataType = NUMBER
//			param.ContFlag = 0
//			param.MaxCharLen = 0
//			param.MaxLen = 22
//			param.CharsetForm = 0
//		case "VARCHAR2":
//			param.DataType = NCHAR
//			param.CharsetForm = 1
//			param.ContFlag = 16
//			param.MaxCharLen = 1000
//			param.MaxLen = 1000 * converters.MaxBytePerChar(param.CharsetID)
//		case "NVARCHAR2":
//			param.DataType = NCHAR
//			param.CharsetForm = 2
//			param.ContFlag = 16
//			param.MaxCharLen = 1000
//			param.CharsetID = conn.tcpNego.ServernCharset
//			param.MaxLen = 1000 * converters.MaxBytePerChar(param.CharsetID)
//		case "TIMESTAMP":
//			fallthrough
//		case "DATE":
//			param.DataType = DATE
//			param.ContFlag = 0
//			param.MaxLen = 11
//			param.MaxCharLen = 11
//		case "RAW":
//			param.DataType = RAW
//			param.ContFlag = 0
//			param.MaxLen = 1000
//			param.MaxCharLen = 0
//			param.CharsetForm = 0
//		default:
//			return errors.New(fmt.Sprint("unsupported attribute type: ", attTypeName))
//		}
//	}
//	cust.loadFieldMap()
//	conn.cusTyp[strings.ToUpper(typeName)] = cust
//	return nil
//}

// loadFieldMap read struct tag that supplied with golang type object passed in RegisterType
// function
func (cust *customType) loadFieldMap() {
	typ := cust.typ
	for x := 0; x < typ.NumField(); x++ {
		f := typ.Field(x)
		fieldID, _, _, _ := extractTag(f.Tag.Get("udt"))
		if len(fieldID) == 0 {
			continue
		}
		fieldID = strings.ToUpper(fieldID)
		cust.fieldMap[fieldID] = x
		//tag := f.Tag.Get("oracle")
		//if len(tag) == 0 {
		//	continue
		//}
		//tag = strings.Trim(tag, "\"")
		//parts := strings.Split(tag, ",")
		//for _, part := range parts {
		//	subs := strings.Split(part, ":")
		//	if len(subs) == 0 {
		//		continue
		//	}
		//	if strings.TrimSpace(strings.ToLower(subs[0])) == "name" {
		//		if len(subs) == 1 {
		//			continue
		//		}
		//		fieldID := strings.TrimSpace(strings.ToUpper(subs[1]))
		//		cust.fieldMap[fieldID] = x
		//	}
		//}
	}
}

// getObject return an object of Golang type supplied in RegisterType function
// the object is filled with data from attrib []ParameterInfo
// which is filled inside Stmt during data reading
func (cust *customType) getObject() (interface{}, error) {
	typ := cust.typ
	obj := reflect.New(typ)
	for _, attrib := range cust.attribs {
		if fieldIndex, ok := cust.fieldMap[attrib.Name]; ok {
			if attrib.Value != nil {
				//tempField := obj.Elem().Field(fieldIndex)

				//err := setValue(&tempField, attrib.Value)
				//if err != nil {
				//	panic(err)
				//}
				tempPar := ParameterInfo{Value: obj.Elem().Field(fieldIndex).Interface()}
				err := tempPar.setParameterValue(attrib.Value)
				if err != nil {
					return nil, err
				}
				err = setFieldValue(obj.Elem().Field(fieldIndex), tempPar.cusType, tempPar.Value)
				if err != nil {
					return nil, err
				}
				//obj.Elem().Field(fieldIndex).Set(reflect.ValueOf(tempPar.Value))
			}
		}
	}
	return obj.Elem().Interface(), nil
}

//func (cust *customType) getFieldRepr(index int, input_value interface{}) ([]byte, error) {
//	attrib := cust.attribs[index]
//	//typ := reflect.TypeOf(val)
//	val := reflect.ValueOf(input_value)
//	typ := val.Type()
//	switch attrib.DataType {
//	case NUMBER:
//		switch typ.Kind() {
//		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
//			fallthrough
//		case reflect.Int, reflect.Int32, reflect.Int16, reflect.Int64, reflect.Int8:
//			return converters.EncodeInt64(reflect.ValueOf(val).Int()), nil
//		case reflect.Float32, reflect.Float64:
//			return converters.EncodeDouble(reflect.ValueOf(val).Float())
//		default:
//			return nil, fmt.Errorf("field %d require NUMBER data type", index)
//		}
//	case DATE:
//		if typ == reflect.TypeOf(time.Time{}) {
//			//return converters.EncodeDate(val.Interface())
//		}
//
//	}
//	return nil, nil
//}
