package go_ora

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

type TimeStamp time.Time

func (val *TimeStamp) Value() (driver.Value, error) {
	return val, nil
}

func (val *TimeStamp) Scan(value interface{}) error {
	switch temp := value.(type) {
	case TimeStamp:
		*val = temp
	case *TimeStamp:
		*val = *temp
	case time.Time:
		*val = TimeStamp(temp)
	case *time.Time:
		*val = TimeStamp(*temp)
	default:
		return errors.New("go-ora: TimeStamp column type require time.Time value")
	}
	return nil
}

func (val TimeStamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(val))
}

func (val *TimeStamp) UnmarshalJSON(data []byte) error {
	var temp time.Time
	err := json.Unmarshal(data, &temp)
	if err != nil {
		return err
	}
	*val = TimeStamp(temp)
	return nil
}

type NullTimeStamp struct {
	TimeStamp TimeStamp
	Valid     bool
}

func (val NullTimeStamp) Value() (driver.Value, error) {
	if val.Valid {
		return val.TimeStamp.Value()
	} else {
		return nil, nil
	}
}

func (val *NullTimeStamp) Scan(value interface{}) error {
	if value == nil {
		val.Valid = false
		return nil
	}
	val.Valid = true
	return val.TimeStamp.Scan(value)
}

func (val NullTimeStamp) MarshalJSON() ([]byte, error) {
	if val.Valid {
		return json.Marshal(time.Time(val.TimeStamp))
	}
	return json.Marshal(nil)
}

func (val *NullTimeStamp) UnmarshalJSON(data []byte) error {
	var temp = new(time.Time)
	err := json.Unmarshal(data, temp)
	if err != nil {
		return err
	}
	if temp == nil {
		val.Valid = false
	} else {
		val.Valid = true
		val.TimeStamp = TimeStamp(*temp)
	}
	return nil
}
