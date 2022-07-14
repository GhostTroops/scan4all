package fingerprint

import (
	"encoding/json"
)

type Packjson struct {
	Fingerprint []*Fingerprint
}

type Fingerprint struct {
	Cms      string
	Method   string
	Location string
	Keyword  []string
	Id       int // 扩展id属性，通过id关联到组件
}

var (
	Webfingerprint *Packjson
)

func LoadWebfingerprintEhole() error {
	var config Packjson
	err := json.Unmarshal([]byte(eHoleFinger), &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

func LoadWebfingerprintLocal() error {
	var config Packjson
	err := json.Unmarshal([]byte(localFinger), &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

func GetWebfingerprintLocal() *Packjson {
	return Webfingerprint
}

func GetWebfingerprintEhole() *Packjson {
	return Webfingerprint
}
