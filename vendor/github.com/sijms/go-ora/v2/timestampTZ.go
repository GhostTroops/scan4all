package go_ora

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

type TimeStampTZ time.Time

func (val *TimeStampTZ) Value() (driver.Value, error) {
	return val, nil
}

func (val *TimeStampTZ) Scan(value interface{}) error {
	switch temp := value.(type) {
	case TimeStampTZ:
		*val = temp
	case *TimeStampTZ:
		*val = *temp
	case time.Time:
		*val = TimeStampTZ(temp)
	case *time.Time:
		*val = TimeStampTZ(*temp)
	default:
		return errors.New("go-ora: TimeStamp column type require time.Time value")
	}
	return nil
}

func (val TimeStampTZ) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(val))
}

func (val *TimeStampTZ) UnmarshalJSON(data []byte) error {
	var temp time.Time
	err := json.Unmarshal(data, &temp)
	if err != nil {
		return err
	}
	*val = TimeStampTZ(temp)
	return nil
}

type NullTimeStampTZ struct {
	TimeStampTZ TimeStampTZ
	Valid       bool
}

func (val NullTimeStampTZ) Value() (driver.Value, error) {
	if val.Valid {
		return val.TimeStampTZ.Value()
	} else {
		return nil, nil
	}
}

func (val *NullTimeStampTZ) Scan(value interface{}) error {
	if value == nil {
		val.Valid = false
		return nil
	}
	val.Valid = true
	return val.TimeStampTZ.Scan(value)
}

func (val NullTimeStampTZ) MarshalJSON() ([]byte, error) {
	if val.Valid {
		return json.Marshal(time.Time(val.TimeStampTZ))
	}
	return json.Marshal(nil)
}

func (val *NullTimeStampTZ) UnmarshalJSON(data []byte) error {
	var temp = new(time.Time)
	err := json.Unmarshal(data, temp)
	if err != nil {
		return err
	}
	if temp == nil {
		val.Valid = false
	} else {
		val.Valid = true
		val.TimeStampTZ = TimeStampTZ(*temp)
	}
	return nil
}
