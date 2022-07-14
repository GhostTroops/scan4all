package fingerprint

import (
	"encoding/hex"
	"encoding/json"
	"github.com/hktalent/scan4all/pkg"
	"log"
	"net/url"
	"sync"
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

// 相同url、cms命中两次就不再匹配
var Max_Count = 2

// 识别期间命中率控制、提高效率
var MUrl *sync.Map = new(sync.Map)

// 图标每个目标只识别一次
var Mfavhash *sync.Map = new(sync.Map)

//  一个url到底和多少组件id关联
var MFid *sync.Map = new(sync.Map)

// 清除数据
func ClearData() {
	Mfavhash = nil
	MUrl = nil
	EholeFinpx = nil
	LocalFinpx = nil
	DelTmpFgFile()
}

func SvUrl2Id(szUrl string, finp *Fingerprint) {
	if 0 < finp.Id {
		if v, ok := MFid.Load(szUrl); ok {
			var d = v.(map[int]struct{})
			d[finp.Id] = struct{}{}
		} else {
			MFid.Store(szUrl, map[int]struct{}{finp.Id: struct{}{}})
		}
	}
}

func CaseMethod(szUrl, method, bodyString, favhash, md5Body, hexBody string, finp *Fingerprint) []string {
	cms := []string{}
	if 0 == len(finp.Keyword) {
		log.Printf("%+v", finp)
		return cms
	}
	u01, _ := url.Parse(szUrl)
	if _, ok := Mfavhash.Load(u01.Host + favhash); ok {
		return cms
	}
	szKey := szUrl + finp.Cms + favhash
	if v, ok := MUrl.Load(szKey); ok {
		n1 := v.(int)
		if Max_Count <= v.(int) {
			return cms
		}
		MUrl.Store(szKey, n1+1)
	} else {
		MUrl.Store(szKey, 1)
	}

	switch method {
	case "keyword":
		if iskeyword(bodyString, finp.Keyword) {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp)
		}
		break
	case "faviconhash": // 相同目标只执行一次
		if iskeyword(favhash, finp.Keyword) {
			Mfavhash.Store(u01.Host+favhash, 1)
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp)
		}
		break
	case "regular":
		if isregular(bodyString, finp.Keyword) {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp)
		}
		break
	case "md5": // 支持md5
		if iskeyword(md5Body, finp.Keyword) {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp)
		}
		break
	case "base64": // 支持base64
		if iskeyword(bodyString, finp.Keyword) {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp)
		}
		break
	case "hex":
		if iskeyword(hexBody, finp.Keyword) {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp)
		}
		break
	}
	//if 0 < len(cms) {
	//	log.Println(szUrl, " ", finp.Cms, " method: ", method, " can detect ")
	//	log.Printf("%+v\n", cms)
	//}
	return cms
}

var enableFingerTitleHeaderMd5Hex = pkg.GetValByDefault("enableFingerTitleHeaderMd5Hex", "false")

// 相同的url、组件（产品），>=2 个指纹命中，那么该组件的其他指纹匹配将跳过
func FingerScan(headers map[string][]string, body []byte, title string, url string, status_code string) []string {
	//log.Println("FgDictFile = ", FgDictFile)
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
					SvUrl2Id(url, finp)
				}
			}
		}
	}
	return cms
}
