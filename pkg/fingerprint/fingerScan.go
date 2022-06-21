package fingerprint

import (
	"encoding/json"
)

var EholeFinpx *Packjson
var LocalFinpx *Packjson

func New() error {
	err := LoadWebfingerprintEhole()
	if err != nil {
		return err
	}
	EholeFinpx = GetWebfingerprintEhole()

	err = LoadWebfingerprintLocal()
	if err != nil {
		return err
	}
	LocalFinpx = GetWebfingerprintLocal()
	return nil
}

func mapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

func FingerScan(headers map[string][]string, body []byte, title string, url string) []string {
	bodyString := string(body)
	headersjson := mapToJson(headers)
	favhash := getfavicon(bodyString, url)
	var cms []string
	for _, finp := range EholeFinpx.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if iskeyword(bodyString, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "faviconhash" {
				if favhash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(bodyString, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if iskeyword(headersjson, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(headersjson, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if iskeyword(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
	}
	for _, finp := range LocalFinpx.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if iskeyword(bodyString, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "faviconhash" {
				if favhash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(bodyString, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if iskeyword(headersjson, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(headersjson, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if iskeyword(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
	}
	return cms
}
