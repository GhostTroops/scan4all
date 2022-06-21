package go_ora

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"
)

func (par *ParameterInfo) setParameterArrayValue(newValue []driver.Value) error {
	if len(newValue) == 0 {
		return nil
	}
	switch value := par.Value.(type) {
	case *[]int16:
		for _, temp := range newValue {
			val, err := getInt(temp)
			if err != nil {
				return err
			}
			*value = append(*value, int16(val))
		}
	case []int16:
		for _, temp := range newValue {
			val, err := getInt(temp)
			if err != nil {
				return err
			}
			value = append(value, int16(val))
		}
		par.Value = value
	case []sql.NullInt16:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, sql.NullInt16{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				value = append(value, sql.NullInt16{Valid: true, Int16: int16(val)})
			}
		}
		par.Value = value
	case *[]sql.NullInt16:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, sql.NullInt16{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				*value = append(*value, sql.NullInt16{Valid: true, Int16: int16(val)})
			}
		}
	case *[]int32:
		for _, temp := range newValue {
			val, err := getInt(temp)
			if err != nil {
				return err
			}
			*value = append(*value, int32(val))
		}
	case []int32:
		for _, temp := range newValue {
			val, err := getInt(temp)
			if err != nil {
				return err
			}
			value = append(value, int32(val))
		}
		par.Value = value
	case []sql.NullInt32:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, sql.NullInt32{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				value = append(value, sql.NullInt32{Valid: true, Int32: int32(val)})
			}
		}
		par.Value = value
	case *[]sql.NullInt32:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, sql.NullInt32{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				*value = append(*value, sql.NullInt32{Valid: true, Int32: int32(val)})
			}
		}
	case *[]int:
		for _, temp := range newValue {
			val, err := getInt(temp)
			if err != nil {
				return err
			}
			*value = append(*value, int(val))
		}
	case []int:
		for _, temp := range newValue {
			val, err := getInt(temp)
			if err != nil {
				return err
			}
			value = append(value, int(val))
		}
		par.Value = value
	case *[]int64:
		for _, temp := range newValue {
			val, err := getInt(temp)
			if err != nil {
				return err
			}
			*value = append(*value, val)
		}
	case []int64:
		for _, temp := range newValue {
			val, err := getInt(temp)
			if err != nil {
				return err
			}
			value = append(value, val)
		}
		par.Value = value
	case []sql.NullInt64:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, sql.NullInt64{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				value = append(value, sql.NullInt64{Valid: true, Int64: val})
			}
		}
		par.Value = value
	case *[]sql.NullInt64:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, sql.NullInt64{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				*value = append(*value, sql.NullInt64{Valid: true, Int64: val})
			}
		}
	case *[]float32:
		for _, temp := range newValue {
			val, err := getFloat(temp)
			if err != nil {
				return err
			}
			*value = append(*value, float32(val))
		}
	case []float32:
		for _, temp := range newValue {
			val, err := getFloat(temp)
			if err != nil {
				return err
			}
			value = append(value, float32(val))
		}
		par.Value = value
	case *[]float64:
		for _, temp := range newValue {
			val, err := getFloat(temp)
			if err != nil {
				return err
			}
			*value = append(*value, val)
		}
	case []float64:
		for _, temp := range newValue {
			val, err := getFloat(temp)
			if err != nil {
				return err
			}
			value = append(value, val)
		}
		par.Value = value
	case []sql.NullFloat64:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, sql.NullFloat64{Valid: false})
			} else {
				val, err := getFloat(temp)
				if err != nil {
					return err
				}
				value = append(value, sql.NullFloat64{Valid: true, Float64: val})
			}
		}
		par.Value = value
	case *[]sql.NullFloat64:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, sql.NullFloat64{Valid: false})
			} else {
				val, err := getFloat(temp)
				if err != nil {
					return err
				}
				*value = append(*value, sql.NullFloat64{Valid: true, Float64: val})
			}
		}
	case *[]string:
		for _, temp := range newValue {
			*value = append(*value, getString(temp))
		}
	case []string:
		for _, temp := range newValue {
			value = append(value, getString(temp))
		}
		par.Value = value
	case []sql.NullString:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, sql.NullString{Valid: false})
			} else {
				value = append(value, sql.NullString{Valid: true, String: getString(temp)})
			}
		}
		par.Value = value
	case *[]sql.NullString:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, sql.NullString{Valid: false})
			} else {
				*value = append(*value, sql.NullString{Valid: true, String: getString(temp)})
			}
		}
	case *[]NVarChar:
		for _, temp := range newValue {
			*value = append(*value, NVarChar(getString(temp)))
		}
	case []NVarChar:
		for _, temp := range newValue {
			value = append(value, NVarChar(getString(temp)))
		}
		par.Value = value
	case []NullNVarChar:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, NullNVarChar{Valid: false})
			} else {
				value = append(value, NullNVarChar{Valid: true, NVarChar: NVarChar(getString(temp))})
			}
		}
		par.Value = value
	case *[]NullNVarChar:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, NullNVarChar{Valid: false})
			} else {
				*value = append(*value, NullNVarChar{Valid: true, NVarChar: NVarChar(getString(temp))})
			}
		}
	case *[]time.Time:
		for _, temp := range newValue {
			if tempVal, ok := temp.(time.Time); ok {
				*value = append(*value, tempVal)
			} else {
				return errors.New("*[]time.Time parameter need time.Time value")
			}
		}
	case []time.Time:
		for _, temp := range newValue {
			if tempVal, ok := temp.(time.Time); ok {
				value = append(value, tempVal)
			} else {
				return errors.New("[]time.Time parameter need time.Time value")
			}
		}
		par.Value = value
	case []sql.NullTime:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, sql.NullTime{Valid: false})
			} else {
				if tempVal, ok := temp.(time.Time); ok {
					value = append(value, sql.NullTime{Valid: true, Time: tempVal})
				} else {
					return errors.New("[]sql.NullTime parameter need time.Time or nil values")
				}
			}
		}
		par.Value = value
	case *[]sql.NullTime:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, sql.NullTime{Valid: false})
			} else {
				if tempVal, ok := temp.(time.Time); ok {
					*value = append(*value, sql.NullTime{Valid: true, Time: tempVal})
				} else {
					return errors.New("*[]sql.NullTime parameter need time.Time or nil values")
				}
			}
		}
	case *[]TimeStamp:
		for _, temp := range newValue {
			if tempVal, ok := temp.(time.Time); ok {
				*value = append(*value, TimeStamp(tempVal))
			} else {
				return errors.New("*[]TimeStamp parameter need time.Time value")
			}
		}
	case []TimeStamp:
		for _, temp := range newValue {
			if tempVal, ok := temp.(time.Time); ok {
				value = append(value, TimeStamp(tempVal))
			} else {
				return errors.New("[]TimeStamp parameter need time.Time value")
			}
		}
		par.Value = value
	case []NullTimeStamp:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, NullTimeStamp{Valid: false})
			} else {
				if tempVal, ok := temp.(time.Time); ok {
					value = append(value, NullTimeStamp{Valid: true, TimeStamp: TimeStamp(tempVal)})
				} else {
					return errors.New("[]NullTimeStamp parameter need time.Time value")
				}
			}
		}
		par.Value = value
	case *[]NullTimeStamp:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, NullTimeStamp{Valid: false})
			} else {
				if tempVal, ok := temp.(time.Time); ok {
					*value = append(*value, NullTimeStamp{Valid: true, TimeStamp: TimeStamp(tempVal)})
				} else {
					return errors.New("[]NullTimeStamp parameter need time.Time value")
				}
			}
		}
	case []sql.NullBool:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, sql.NullBool{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				value = append(value, sql.NullBool{Valid: true, Bool: val != 0})
			}
		}
		par.Value = value
	case *[]sql.NullBool:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, sql.NullBool{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				*value = append(*value, sql.NullBool{Valid: true, Bool: val != 0})
			}
		}
	case []sql.NullByte:
		for _, temp := range newValue {
			if temp == nil {
				value = append(value, sql.NullByte{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				value = append(value, sql.NullByte{Valid: true, Byte: uint8(val)})
			}
		}
		par.Value = value
	case *[]sql.NullByte:
		for _, temp := range newValue {
			if temp == nil {
				*value = append(*value, sql.NullByte{Valid: false})
			} else {
				val, err := getInt(temp)
				if err != nil {
					return err
				}
				*value = append(*value, sql.NullByte{Valid: true, Byte: uint8(val)})
			}
		}
	default:
		return errors.New("unsupported array type")
	}
	return nil
}
