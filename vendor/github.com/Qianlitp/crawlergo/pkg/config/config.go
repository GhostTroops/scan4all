package config

import (
	"time"

	mapset "github.com/deckarep/golang-set"
)

const (
	DefaultUA               = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.0 Safari/537.36"
	MaxTabsCount            = 10
	TabRunTimeout           = 20 * time.Second
	DefaultInputText        = "Crawlergo"
	FormInputKeyword        = "Crawlergo"
	SuspectURLRegex         = `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
	URLRegex                = `((https?|ftp|file):)?//[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]`
	AttrURLRegex            = ``
	DomContentLoadedTimeout = 5 * time.Second
	EventTriggerInterval    = 100 * time.Millisecond // 单位毫秒
	BeforeExitDelay         = 1 * time.Second
	DefaultEventTriggerMode = EventTriggerAsync
	MaxCrawlCount           = 200
)

// 请求方法
const (
	GET     = "GET"
	POST    = "POST"
	PUT     = "PUT"
	DELETE  = "DELETE"
	HEAD    = "HEAD"
	OPTIONS = "OPTIONS"
)

// 过滤模式
const (
	SimpleFilterMode = "simple"
	SmartFilterMode  = "smart"
	StrictFilterMode = "strict"
)

// 事件触发模式
const (
	EventTriggerAsync = "async"
	EventTriggerSync  = "sync"
)

// 请求的来源
const (
	FromTarget      = "Target"     //初始输入的目标
	FromNavigation  = "Navigation" //页面导航请求
	FromXHR         = "XHR"        //ajax异步请求
	FromDOM         = "DOM"        //dom解析出来的请求
	FromJSFile      = "JavaScript" //JS脚本中解析
	FromFuzz        = "PathFuzz"   //初始path fuzz
	FromRobots      = "robots.txt" //robots.txt
	FromComment     = "Comment"    //页面中的注释
	FromWebSocket   = "WebSocket"
	FromEventSource = "EventSource"
	FromFetch       = "Fetch"
	FromHistoryAPI  = "HistoryAPI"
	FromOpenWindow  = "OpenWindow"
	FromHashChange  = "HashChange"
	FromStaticRes   = "StaticResource"
	FromStaticRegex = "StaticRegex"
)

// content-type
const (
	JSON       = "application/json"
	URLENCODED = "application/x-www-form-urlencoded"
	MULTIPART  = "multipart/form-data"
)

var (
	StaticSuffix = []string{
		"png", "gif", "jpg", "mp4", "mp3", "mng", "pct", "bmp", "jpeg", "pst", "psp", "ttf",
		"tif", "tiff", "ai", "drw", "wma", "ogg", "wav", "ra", "aac", "mid", "au", "aiff",
		"dxf", "eps", "ps", "svg", "3gp", "asf", "asx", "avi", "mov", "mpg", "qt", "rm",
		"wmv", "m4a", "bin", "xls", "xlsx", "ppt", "pptx", "doc", "docx", "odt", "ods", "odg",
		"odp", "exe", "zip", "rar", "tar", "gz", "iso", "rss", "pdf", "txt", "dll", "ico",
		"gz2", "apk", "crt", "woff", "map", "woff2", "webp", "less", "dmg", "bz2", "otf", "swf",
		"flv", "mpeg", "dat", "xsl", "csv", "cab", "exif", "wps", "m4v", "rmvb",
	}
	StaticSuffixSet mapset.Set
)

var (
	ScriptSuffix = []string{
		"php", "asp", "jsp", "asa",
	}
	ScriptSuffixSet mapset.Set
)

var DefaultIgnoreKeywords = []string{"logout", "quit", "exit"}
var AllowedFormName = []string{"default", "mail", "code", "phone", "username", "password", "qq", "id_card", "url", "date", "number"}

type ContinueResourceList []string

var InputTextMap = map[string]map[string]interface{}{
	"mail": {
		"keyword": []string{"mail"},
		"value":   "crawlergo@gmail.com",
	},
	"code": {
		"keyword": []string{"yanzhengma", "code", "ver", "captcha"},
		"value":   "123a",
	},
	"phone": {
		"keyword": []string{"phone", "number", "tel", "shouji"},
		"value":   "18812345678",
	},
	"username": {
		"keyword": []string{"name", "user", "id", "login", "account"},
		"value":   "crawlergo@gmail.com",
	},
	"password": {
		"keyword": []string{"pass", "pwd"},
		"value":   "Crawlergo6.",
	},
	"qq": {
		"keyword": []string{"qq", "wechat", "tencent", "weixin"},
		"value":   "123456789",
	},
	"IDCard": {
		"keyword": []string{"card", "shenfen"},
		"value":   "511702197409284963",
	},
	"url": {
		"keyword": []string{"url", "site", "web", "blog", "link"},
		"value":   "https://crawlergo.nice.cn/",
	},
	"date": {
		"keyword": []string{"date", "time", "year", "now"},
		"value":   "2018-01-01",
	},
	"number": {
		"keyword": []string{"day", "age", "num", "count"},
		"value":   "10",
	},
}

func init() {
	StaticSuffixSet = initSet(StaticSuffix)
	ScriptSuffixSet = initSet(ScriptSuffix)
}

func initSet(suffixs []string) mapset.Set {
	set := mapset.NewSet()
	for _, s := range suffixs {
		set.Add(s)
	}
	return set
}
