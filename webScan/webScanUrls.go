package webScan

import (
	"bytes"
	"github.com/hktalent/scan4all/lib/util"
	ws01 "github.com/hktalent/scan4all/webScan/Functions"
	Configs "github.com/hktalent/scan4all/webScan/config"
	"strings"
)

type ExpJsons struct {
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Product     string `json:"Product"`
	Author      string `json:"author"`
	Request     []struct {
		Method           string            `json:"Method"`
		Header           map[string]string `json:"Header"`
		Uri              string            `json:"Uri"`
		Port             string            `json:"Port"`
		Data             string            `json:"Data"`
		Follow_redirects string            `json:"Follow_redirects"`
		Upload           struct {
			Name     string `json:"Name"`
			FileName string `json:"fileName"`
			FilePath string `json:"FilePath"`
		} `json:"Upload"`
		Response struct {
			Check_Steps string `json:"Check_Steps"`
			Checks      []struct {
				Operation string `json:"Operation"`
				Key       string `json:"Key"`
				Value     string `json:"Value"`
			} `json:"Checks"`
		}
		Next_decide string `json:"Next_decide"`
	} `json:"Request"`
}

// 集成 webscan
func CheckUrls(buf *bytes.Buffer) {
	if nil == buf {
		return
	}
	urllist := strings.Split(strings.TrimSpace(buf.String()), "\n")
	Configs.UserObject.GetTitle = true
	Configs.UserObject.AllJson = true
	Configs.UserObject.ThreadNum = util.GetValAsInt("Fuzzthreads", 4)
	ws01.Choose(urllist)
}
