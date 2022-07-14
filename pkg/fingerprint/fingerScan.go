package fingerprint

import (
	"encoding/hex"
	"encoding/json"
	"github.com/hktalent/scan4all/pkg"
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

// 合并所有指纹需要请求的链接，也就是合并所有请求，相同的只请求一次
// 会多次调用，所以需要cache中间结果
func PreprocessingFingerScan(url string) []string {
	// 有时间再实现
	return []string{}
}

func CaseMethod(szUrl string, method, bodyString, favhash, md5Body, hexBody string, finp Fingerprint) []string {
	cms := []string{}
	switch method {
	case "keyword":
		if iskeyword(bodyString, finp.Keyword) {
			cms = append(cms, finp.Cms)
		}
	case "faviconhash":
		if iskeyword(favhash, finp.Keyword) {
			cms = append(cms, finp.Cms)
		}
	case "regular":
		if isregular(bodyString, finp.Keyword) {
			cms = append(cms, finp.Cms)
		}
	case "md5": // 支持md5
		if iskeyword(md5Body, finp.Keyword) {
			cms = append(cms, finp.Cms)
		}
	case "base64": // 支持base64
		if iskeyword(bodyString, finp.Keyword) {
			cms = append(cms, finp.Cms)
		}
	case "hex":
		if iskeyword(hexBody, finp.Keyword) {
			cms = append(cms, finp.Cms)
		}
	}
	//if 0 < len(cms) {
	//	log.Println(szUrl, " ", finp.Cms, " method: ", method, " can detect ")
	//	log.Printf("%+v\n", cms)
	//}
	return cms
}

var enableFingerTitleHeaderMd5Hex = pkg.GetValByDefault("enableFingerTitleHeaderMd5Hex", "false")

// 相同的url、组件（产品），>=2 个指纹命中，那么该组件的其他指纹匹配将跳过
//
func FingerScan(headers map[string][]string, body []byte, title string, url string, status_code string) []string {
	bodyString := string(body)
	headersjson := mapToJson(headers)
	favhash, _ := getfavicon(bodyString, url)

	md5Body := FavicohashMd5(0, nil, body, nil)
	hexBody := hex.EncodeToString(body)

	hexTitle := ""
	md5Title := ""
	hexHeader := ""
	md5Header := ""
	if "true" == enableFingerTitleHeaderMd5Hex {
		hexTitle = hex.EncodeToString([]byte(title))
		md5Title = FavicohashMd5(0, nil, []byte(title), nil)
		hexHeader = hex.EncodeToString([]byte(headersjson))
		md5Header = FavicohashMd5(0, nil, []byte(headersjson), nil)
	}
	var cms []string
	for _, x1 := range []*Packjson{EholeFinpx, LocalFinpx} {
		for _, finp := range x1.Fingerprint {
			if finp.Location == "body" { // 识别区域；body
				cms = append(cms, CaseMethod(url, finp.Method, bodyString, favhash, md5Body, hexBody, finp)...)
			} else if finp.Location == "header" { // 识别区域：header
				cms = append(cms, CaseMethod(url, finp.Method, headersjson, favhash, md5Header, hexHeader, finp)...)
			} else if finp.Location == "title" { // 识别区域： title
				cms = append(cms, CaseMethod(url, finp.Method, title, favhash, md5Title, hexTitle, finp)...)
			} else if finp.Location == "status_code" { // 识别区域：status_code
				if iskeyword(status_code, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
	}
	return cms
}
