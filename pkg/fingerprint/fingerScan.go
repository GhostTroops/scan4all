package fingerprint

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"log"
	"net/url"
	"strings"
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

func headerToString(param map[string][]string) string {
	var a []string
	for k, v := range param {
		a = append(a, k+": "+strings.Join(v, ";"))
	}
	return strings.Join(a, "\n")
}

// 合并所有指纹需要请求的链接，也就是合并所有请求，相同的只请求一次
// 会多次调用，所以需要cache中间结果
func PreprocessingFingerScan(url string) []string {
	// 有时间再实现
	return []string{}
}

// 相同url、cms命中两次就不再匹配
var Max_Count = 10

// 图标每个目标只识别一次
var Mfavhash *sync.Map = new(sync.Map)

// 一个url到底和多少组件id关联
var MFid *sync.Map = new(sync.Map)

// 清除数据
func ClearData() {
	Mfavhash = nil
	EholeFinpx = nil
	LocalFinpx = nil
	DelTmpFgFile()
}

func SvUrl2Id(szUrl string, finp *Fingerprint, rMz string) {
	if 0 < finp.Id {
		if v, ok := MFid.Load(szUrl); ok {
			if d, ok := v.(map[int]map[string]int); ok {
				if n, ok := d[finp.Id][rMz]; ok {
					d[finp.Id][rMz] = n + 1
				} else {
					d[finp.Id] = map[string]int{rMz: 1}
				}
				MFid.Store(szUrl, d)
			}
		} else {
			MFid.Store(szUrl, map[int]map[string]int{finp.Id: map[string]int{rMz: 1}})
		}
	}
}

func CaseMethod(szUrl, method, bodyString, favhash, md5Body, hexBody string, finp *Fingerprint) []string {
	cms := []string{}
	u01, _ := url.Parse(strings.TrimSpace(szUrl))
	if 0 == len(finp.Keyword) {
		//log.Printf("%+v", finp)
		return cms
	}

	if _, ok := Mfavhash.Load(u01.Host + favhash); ok {
		return cms
	}

	switch method {
	case "keyword":
		if ok, rMz := iskeyword(bodyString, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "faviconhash": // 相同目标只执行一次
		if ok, rMz := iskeyword(favhash, finp.Keyword, finp.KeywordMathOr); ok {
			Mfavhash.Store(u01.Host+favhash, 1)
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "regular":
		if ok, rMz := isregular(bodyString, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "md5": // 支持md5
		if ok, rMz := iskeyword(md5Body, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "base64": // 支持base64
		if ok, rMz := iskeyword(bodyString, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	case "hex":
		if ok, rMz := iskeyword(hexBody, finp.Keyword, finp.KeywordMathOr); ok {
			cms = append(cms, finp.Cms)
			SvUrl2Id(szUrl, finp, rMz)
		}
		break
	}
	//if 0 < len(cms) {
	//	log.Println(szUrl, " ", finp.Cms, " method: ", method, " can detect ")
	//	log.Printf("%+v\n", cms)
	//}
	return cms
}

var enableFingerTitleHeaderMd5Hex = util.GetValAsBool("enableFingerTitleHeaderMd5Hex")

func CheckHoneyport(a []string) (bool, []string) {
	bRst := util.EnableHoneyportDetection && 10 < len(a)
	if bRst {
		a = []string{}
	}
	return bRst, a
}

// 相同的url、组件（产品），>=2 个指纹命中，那么该组件的其他指纹匹配将跳过
func FingerScan(headers map[string][]string, body []byte, title string, szUrl string, status_code string) ([]string, []string) {
	if nil == body || 0 == len(body) {
		//log.Println(szUrl, " 存在异常，body为nil")
		return []string{}, nil
	}
	//log.Println("FgDictFile = ", FgDictFile)
	bodyString := string(body)
	headersjson := mapToJson(headers) + "\n" + headerToString(headers)
	favhash, _ := getfavicon(bodyString, szUrl)

	md5Body := FavicohashMd5(0, nil, body, nil)
	hexBody := hex.EncodeToString(body)

	hexTitle := ""
	md5Title := ""
	hexHeader := ""
	md5Header := ""
	if enableFingerTitleHeaderMd5Hex {
		hexTitle = hex.EncodeToString([]byte(title))
		md5Title = FavicohashMd5(0, nil, []byte(title), nil)
		hexHeader = hex.EncodeToString([]byte(headersjson))
		md5Header = FavicohashMd5(0, nil, []byte(headersjson), nil)
	}

	var cms []string
	var fgIds []string
	u01, _ := url.Parse(strings.TrimSpace(szUrl))
	for _, x1 := range []*Packjson{EholeFinpx, LocalFinpx} {
		for _, finp := range x1.Fingerprint {
			// 移到循环体最前，提高效率, finp.Id > 0 兼容自家的指纹,非自家的继续走
			if finp.Id > 0 && u01.Path != finp.UrlPath {
				continue
			}
			n1 := len(cms)
			if finp.UrlPath == "" || strings.HasSuffix(szUrl, finp.UrlPath) {
				//if -1 < strings.Index(szUrl, "/favicon.ico") && finp.Cms == "SpringBoot" {
				//	log.Println(szUrl)
				//}
				if finp.Location == "all" {
					cms = append(cms, CaseMethod(szUrl, finp.Method, headersjson+bodyString, favhash, md5Body, hexBody, finp)...)
				} else if finp.Location == "body" { // 识别区域；body
					cms = append(cms, CaseMethod(szUrl, finp.Method, bodyString, favhash, md5Body, hexBody, finp)...)
				} else if finp.Location == "header" { // 识别区域：header
					cms = append(cms, CaseMethod(szUrl, finp.Method, headersjson, favhash, md5Header, hexHeader, finp)...)
				} else if finp.Location == "title" { // 识别区域： title
					cms = append(cms, CaseMethod(szUrl, finp.Method, title, favhash, md5Title, hexTitle, finp)...)
				} else if finp.Location == "status_code" { // 识别区域：status_code
					if ok, rMz := iskeyword(status_code, finp.Keyword, finp.KeywordMathOr); ok {
						cms = append(cms, finp.Cms)
						SvUrl2Id(szUrl, finp, rMz)
					}
				}
			}
			// 找到指纹
			if len(cms) > n1 {
				fgIds = append(fgIds, fmt.Sprintf("%v", finp.Id))
				log.Printf("%d\n", finp.Id)
				n1 = len(cms)
			}
			// 蜜罐检测、放弃（丢弃）结果
			if ok, a := CheckHoneyport(cms); ok {
				cms = a
				break
			}
			if len(cms) >= Max_Count {
				break
			}
		}

	}
	return cms, fgIds
}
