package fingerprint

import (
	"crypto/md5"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	Reg_idMethod       int = 11515 // 识别方式：正则表达式 == regular
	Text_idMethod      int = 11516 // 识别方式：文本 == keyword
	Bin_idMethod       int = 11517 // 识别方式：hex，二进制
	Base64_idMethod    int = 11518 // 识别方式：hash-base64 // Base64_idMethod    int = 11518 // 识别方式：base64
	Md5_idMethod       int = 11519 // 识别方式：md5
	Header_idPart      int = 11520 // 识别区域：header
	Body_idPart        int = 11521 // 识别区域：body
	Raw_idPart         int = 11522 // 识别区域：all = header + body
	Status_code_idPart int = 8998  // 识别区域：status_code
)

var FgType map[int]string = map[int]string{
	Reg_idMethod:       "regular",
	Text_idMethod:      "keyword",
	Bin_idMethod:       "hex",    // 二进制模式
	Base64_idMethod:    "base64", // 这种类型几乎没有必要
	Md5_idMethod:       "md5",
	Header_idPart:      "header",
	Body_idPart:        "body",
	Raw_idPart:         "all",
	Status_code_idPart: "status_code",
}

//go:embed dicts/fg.json
var FgData string

// 指纹  {id：指纹数据对象}
var FGDataMap []map[string]interface{}

func Get4K(m *map[string]interface{}, k string) string {
	if x, ok := (*m)[k]; ok {
		return fmt.Sprintf("%v", x)
	}
	return ""
}

// 在httpx请求的时候，需要拼接所有的url
var FgUrls = []string{}

// 1、合并相同的请求路径
// 2、合并数据到
func MergeReqUrl() {
	LoadWebfingerprintEhole()
	x1 := GetWebfingerprintEhole()
	// 测试的时候下面代码才打开
	if true || "true" == util.GetValByDefault("MyDebug", "false") {
		x1.Fingerprint = []*Fingerprint{}
		localFinger = "{}"
		log.Println("MyDebug")
	}

	// 不重复的URL
	var urls = []string{}
	// 去重使用
	var oUrl = make(map[string]struct{})
	var oFingerprint = make(map[string]*Fingerprint)

	for _, x := range FGDataMap {
		var j = x["probeList"].([]interface{})
		szName := Get4K(&x, "name")
		sid := Get4K(&x, "_id")

		id, err2 := strconv.Atoi(sid)
		if nil != err2 {
			log.Println("id, err2 := strconv.Atoi(sid) ", err2)
			continue
		}
		// 需要考虑合并：相同url 相同识别区域 相同识别算法
		for _, y1 := range j {
			y := y1.(map[string]interface{})
			// url 去重复 start
			szUrl := Get4K(&y, "url")
			if szUrl == "/" || szUrl == "/favicon.ico" {
				continue
			}
			//log.Println("[", szUrl, "]")
			if _, ok := oUrl[szUrl]; !ok {
				oUrl[szUrl] = struct{}{}
				urls = append(urls, szUrl)
			}
			// url 去重复 end
			sidMethod := Get4K(&y, "idMethod")
			sidPart := Get4K(&y, "idPart")

			idMethod, err := strconv.Atoi(sidMethod)
			idPart, err1 := strconv.Atoi(sidPart)
			if nil != err || nil != err1 || nil != err2 {
				log.Println("idMethod or idPart strconv.Atoi error ", err, err1, err2)
				log.Println("idMethod = ", idMethod, " idPart = ", idPart, " id = ", id)
				continue
			}
			var x2 *Fingerprint
			szKey := szUrl + szName + sidMethod + sidPart
			if x6, ok := oFingerprint[szKey]; ok {
				x2 = x6
			} else {
				x2 = &Fingerprint{Cms: szName, KeywordMathOr: true, UrlPath: Get4K(&y, "url"), Keyword: []string{}, Id: id, Method: FgType[idMethod], Location: FgType[idPart]}
				//x1.Fingerprint = append([]Fingerprint{x2}, x1.Fingerprint...)
				x1.Fingerprint = append(x1.Fingerprint, x2)
				//log.Println(szKey)
			}
			// 这里处理x2的数据项
			x2.Keyword = append(x2.Keyword, Get4K(&y, "pattern"))
			oFingerprint[szKey] = x2
		}
	}
	// 放回去，很重要
	data, err := json.Marshal(x1)
	if nil == err {
		eHoleFinger = string(data)
	}
	FgUrls = append([]string{"/", "/favicon.ico"}, urls...)
}

var FgDictFile string
var tempInput1 *os.File

func DelTmpFgFile() {
	tempInput1.Close()
	defer os.Remove(tempInput1.Name())
}

// 这里可以动态加载远程的url指纹数据到 FgData
func init() {
	util.RegInitFunc(func() {
		FgData = util.GetVal4File("FgData", FgData)
		json.Unmarshal([]byte(FgData), &FGDataMap)
		var aN []map[string]interface{}
		for _, x := range FGDataMap {
			if bD, ok := x["delete"]; !ok || false == bD.(bool) {
				aN = append(aN, x)
			}
		}
		FGDataMap = aN
		MergeReqUrl()
		var err error
		tempInput1, err = ioutil.TempFile("", "dict-in-*")
		if nil == err {
			ioutil.WriteFile(tempInput1.Name(), []byte(strings.Join(FgUrls, "\n")), 0644)
			FgDictFile = tempInput1.Name()
		}
	})
}

func FavicohashMd5(StatusCode int, header http.Header, body []byte, err error) string {
	if nil != err {
		return ""
	}
	srcCode := md5.Sum(body)
	faviconMMH3 := strings.ToLower(fmt.Sprintf("%x", srcCode))
	return faviconMMH3

}
