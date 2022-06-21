package goconfig

import (
	"fmt"
	"strconv"

	"github.com/projectdiscovery/reflectutil"
	ini "gopkg.in/ini.v1"
)

func init() {
	ini.PrettyFormat = false
}

// Save convert to INI for readability
func Save(v interface{}, saveTo string) error {
	kv, err := reflectutil.ToMapWithDefault(v)
	if err != nil {
		return err
	}
	// iterate over map setting key => value in ini file
	cfg := ini.Empty()
	for k, v := range kv {
		var data string
		switch v.(type) {
		case float64, float32:
			data = strconv.FormatFloat(v.(float64), 'f', -1, 64)
		default:
			data = fmt.Sprint(v)
		}
		cfg.Section("").NewKey(k, data)
	}
	return cfg.SaveTo(saveTo)
}

// Load uses the same json taggers but reads from INI for readability
func Load(v interface{}, loadFrom string) error {
	cfg, err := ini.Load(loadFrom)
	if err != nil {
		return err
	}
	cfg.NameMapper = ini.TitleUnderscore

	return cfg.MapTo(v)
}
