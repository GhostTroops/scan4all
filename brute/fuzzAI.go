package brute

import (
	_ "embed"
	"encoding/json"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/GhostTroops/scan4all/pkg"
	"github.com/GhostTroops/scan4all/pkg/fingerprint"
	"github.com/antlabs/strsim"
	"gorm.io/gorm"
	"net/url"
	"regexp"
	"strings"
)

// 异常页面数据库
type ErrPage struct {
	gorm.Model
	FingerprintsTag string `json:"fingerprintsTag"` // 指纹标签,带标签是指纹数据，不是异常数据
	Title           string `json:"title"`           // 标题
	Body            string `json:"body"`            // body
	BodyLen         int    `json:"bodyLen"`         // body len
	BodyHash        string `json:"bodyHash"`        // body hash， Favicohash4key
	BodyMd5         string `json:"bodyMd5"`         // body md5
	HitCnt          uint32 `json:"hitCnt"`          // 命中统计
}

var (
	page404Title []string // 404 标题库、正文库
	asz404Url    []string // 404url,智能学习
)

// 异常、404、500、505 标题、内容 存在到信息库
//  允许正则表达式
//go:embed dicts/fuzz404.txt
var fuzz404 string

// 常见404 url 列表,智能学习
//go:embed dicts/404url.txt
var sz404Url string

var asz404UrlKey = "asz404Url"

// 初始化字典到库中，且防止重复
func init() {
	util.RegInitFunc(func() {
		fuzz404 = util.GetVal4File("fuzz404", fuzz404)
		sz404Url = util.GetVal4File("404url", sz404Url)
		page404Title = strings.Split(strings.TrimSpace(fuzz404), "\n")
		asz404Url = strings.Split(strings.TrimSpace(sz404Url), "\n")
		data, err := util.NewKvDbOp().Get(asz404UrlKey)
		if nil == err && 0 < len(data) {
			aT1 := asz404Url
			if nil != json.Unmarshal(data, &asz404Url) {
				asz404Url = aT1 // 容错
			}
		}
		util.InitDb(&ErrPage{})
	})
}

// 智能学习: 非正常页面，并记录到库中永久使用,使用该方法到页面
// 要么是异常页面，要么是需要学习到指纹，带标记带
//  0、识别学习过的url就跳过
//  1、body 学习
//  2、标题 学习
//  3、url 去重记录
func StudyErrPageAI(req *util.Response, page *util.Page, fingerprintsTag string) {
	if nil == req || nil == page || "" == req.Body {
		return
	}
	util.DoSyncFunc(func() {
		var data = &ErrPage{}
		body := []byte(req.Body)
		szHs, szMd5 := fingerprint.GetHahsMd5(body)
		// 这里后期优化基于其他查询
		r1 := util.GetOne[ErrPage](data, "bodyHash=? and bodyMd5=?", szHs, szMd5)
		if nil != r1 {
			data = r1
		} else {
			data = &ErrPage{Title: *page.Title, Body: req.Body, BodyLen: len(body), FingerprintsTag: ""}
			data.BodyHash = szHs
			data.BodyMd5 = szMd5
			if "" != fingerprintsTag {
				data.FingerprintsTag = fingerprintsTag
			}
			// 学些匹配，不重复再记录
			if bRst, _ := CheckRepeat(data); !bRst {
				util.Create[ErrPage](*data)
			}
		}
	})
}

// 相似度精准度
var fXsdPrecision float64 = 0.96

// 判断库中是否已经存在
func CheckRepeat(data *ErrPage) (bool, *ErrPage) {
	var aRst []ErrPage
	aRst1 := util.GetSubQueryLists[ErrPage, ErrPage](*data, "", aRst, 10000, 0)
	if nil != aRst1 {
		aRst = *aRst1
		for _, x := range aRst {
			if 0 == len(x.FingerprintsTag) && x.BodyLen == data.BodyLen && (x.BodyHash == data.BodyHash || x.BodyMd5 == data.BodyMd5) {
				return true, &x
			}
			if strsim.Compare(x.Body, data.Body) >= fXsdPrecision {
				return true, &x
			}
		}
	}
	return false, nil
}

// 检测是否为异常页面，包括状态码检测
func CheckIsErrPageAI(req *util.Response, page *util.Page) bool {
	body := []byte(req.Body)
	szHs, szMd5 := fingerprint.GetHahsMd5(body)
	var data = &ErrPage{Title: *page.Title, Body: req.Body, BodyLen: len(body)}
	data.BodyHash = szHs
	data.BodyMd5 = szMd5
	bRst, _ := CheckRepeat(data)
	if false == bRst && (0 < len(data.Title) || 0 < len(data.Body)) {
		for _, x := range page404Title {
			// 异常页面标题检测成功
			if 0 < len(data.Title) && (util.StrContains(x, data.Title) || util.StrContains(data.Title, x)) || 0 < len(data.Body) && util.StrContains(data.Body, x) {
				util.Create[ErrPage](*data)
				return true
			}
			u01, err := url.Parse(strings.TrimSpace(*page.Url))
			if nil == err && 2 < len(u01.Path) {
				// 加 404 url判断
				if pkg.Contains4sub[string](asz404Url, u01.Path) {
					return true
				}
				// 添加到 asz404Url, 保存到库中
				if 404 == req.StatusCode {
					go func() {
						asz404Url = append(asz404Url, u01.Path)
						util.PutAny[[]string](asz404UrlKey, asz404Url) // 404 path 缓存起来，永久复用
					}()
				}
			}
		}
	}
	return bRst
}

// 获取标题
func Gettitle(body string) *string {
	body = strings.ToLower(body)
	title := ""
	domainreg2 := regexp.MustCompile(`<title>([^<]*)</title>`)
	titlelist := domainreg2.FindStringSubmatch(body)
	if len(titlelist) > 1 {
		title = strings.ToLower(strings.TrimSpace(titlelist[1]))
		return &title
	}
	return &title
}
