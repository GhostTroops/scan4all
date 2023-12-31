package go_utils

import (
	"bytes"
	"crypto/sha1"
	"embed"
	"encoding/hex"
	"fmt"
	"github.com/karlseguin/ccache"
	"github.com/spf13/viper"
	"io/fs"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// 国家映射
var CountryMap = map[string]string{
	"AL": "阿尔巴尼亚",
	"DZ": "阿尔及利亚",
	"AF": "阿富汗",
	"AR": "阿根廷",
	"AE": "阿拉伯联合酋长国",
	"AW": "阿鲁巴",
	"OM": "阿曼",
	"AZ": "阿塞拜疆",
	"EG": "埃及",
	"ET": "埃塞俄比亚",
	"IE": "爱尔兰",
	"EE": "爱沙尼亚",
	"AD": "安道尔",
	"AO": "安哥拉",
	"AI": "安圭拉",
	"AG": "安提瓜和巴布达",
	"AT": "奥地利",
	"AX": "奥兰群岛",
	"AU": "澳大利亚",
	"BB": "巴巴多斯",
	"PG": "巴布亚新几内亚",
	"BS": "巴哈马",
	"PK": "巴基斯坦",
	"PY": "巴拉圭",
	"PS": "巴勒斯坦领土",
	"BH": "巴林",
	"PA": "巴拿马",
	"BR": "巴西",
	"BY": "白俄罗斯",
	"BM": "百慕大",
	"BG": "保加利亚",
	"MP": "北马里亚纳群岛",
	"MK": "北马其顿",
	"BJ": "贝宁",
	"BE": "比利时",
	"IS": "冰岛",
	"PR": "波多黎各",
	"PL": "波兰",
	"BA": "波斯尼亚和黑塞哥维那",
	"BO": "玻利维亚",
	"BZ": "伯利兹",
	"BW": "博茨瓦纳",
	"BT": "不丹",
	"BF": "布基纳法索",
	"BI": "布隆迪",
	"BV": "布韦岛",
	"KP": "朝鲜",
	"GQ": "赤道几内亚",
	"DK": "丹麦",
	"DE": "德国",
	"TL": "东帝汶",
	"TG": "多哥",
	"DO": "多米尼加共和国",
	"DM": "多米尼克",
	"RU": "俄罗斯",
	"EC": "厄瓜多尔",
	"ER": "厄立特里亚",
	"FR": "法国",
	"FO": "法罗群岛",
	"PF": "法属波利尼西亚",
	"GF": "法属圭亚那",
	"TF": "法属南部领地",
	"MF": "法属圣马丁",
	"VA": "梵蒂冈",
	"PH": "菲律宾",
	"FJ": "斐济",
	"FI": "芬兰",
	"CV": "佛得角",
	"FK": "福克兰群岛",
	"GM": "冈比亚",
	"CG": "刚果（布）",
	"CD": "刚果（金）",
	"CO": "哥伦比亚",
	"CR": "哥斯达黎加",
	"GD": "格林纳达",
	"GL": "格陵兰",
	"GE": "格鲁吉亚",
	"GG": "根西岛",
	"CU": "古巴",
	"GP": "瓜德罗普",
	"GU": "关岛",
	"GY": "圭亚那",
	"KZ": "哈萨克斯坦",
	"HT": "海地",
	"KR": "韩国",
	"NL": "荷兰",
	"BQ": "荷属加勒比区",
	"SX": "荷属圣马丁",
	"HM": "赫德岛和麦克唐纳群岛",
	"ME": "黑山",
	"HN": "洪都拉斯",
	"KI": "基里巴斯",
	"DJ": "吉布提",
	"KG": "吉尔吉斯斯坦",
	"GN": "几内亚",
	"GW": "几内亚比绍",
	"CA": "加拿大",
	"GH": "加纳",
	"GA": "加蓬",
	"KH": "柬埔寨",
	"CZ": "捷克",
	"ZW": "津巴布韦",
	"CM": "喀麦隆",
	"QA": "卡塔尔",
	"KY": "开曼群岛",
	"CC": "科科斯（基林）群岛",
	"KM": "科摩罗",
	"CI": "科特迪瓦",
	"KW": "科威特",
	"HR": "克罗地亚",
	"KE": "肯尼亚",
	"CK": "库克群岛",
	"CW": "库拉索",
	"LV": "拉脱维亚",
	"LS": "莱索托",
	"LA": "老挝",
	"LB": "黎巴嫩",
	"LT": "立陶宛",
	"LR": "利比里亚",
	"LY": "利比亚",
	"LI": "列支敦士登",
	"RE": "留尼汪",
	"LU": "卢森堡",
	"RW": "卢旺达",
	"RO": "罗马尼亚",
	"MG": "马达加斯加",
	"IM": "马恩岛",
	"MV": "马尔代夫",
	"MT": "马耳他",
	"MW": "马拉维",
	"MY": "马来西亚",
	"ML": "马里",
	"MH": "马绍尔群岛",
	"MQ": "马提尼克",
	"YT": "马约特",
	"MU": "毛里求斯",
	"MR": "毛里塔尼亚",
	"US": "美国",
	"UM": "美国本土外小岛屿",
	"AS": "美属萨摩亚",
	"VI": "美属维尔京群岛",
	"MN": "蒙古",
	"MS": "蒙特塞拉特",
	"BD": "孟加拉国",
	"PE": "秘鲁",
	"FM": "密克罗尼西亚",
	"MM": "缅甸",
	"MD": "摩尔多瓦",
	"MA": "摩洛哥",
	"MC": "摩纳哥",
	"MZ": "莫桑比克",
	"MX": "墨西哥",
	"NA": "纳米比亚",
	"ZA": "南非",
	"AQ": "南极洲",
	"GS": "南乔治亚和南桑威奇群岛",
	"SS": "南苏丹",
	"NR": "瑙鲁",
	"NI": "尼加拉瓜",
	"NP": "尼泊尔",
	"NE": "尼日尔",
	"NG": "尼日利亚",
	"NU": "纽埃",
	"NO": "挪威",
	"NF": "诺福克岛",
	"PW": "帕劳",
	"PN": "皮特凯恩群岛",
	"PT": "葡萄牙",
	"JP": "日本",
	"SE": "瑞典",
	"CH": "瑞士",
	"SV": "萨尔瓦多",
	"WS": "萨摩亚",
	"RS": "塞尔维亚",
	"SL": "塞拉利昂",
	"SN": "塞内加尔",
	"CY": "塞浦路斯",
	"SC": "塞舌尔",
	"SA": "沙特阿拉伯",
	"BL": "圣巴泰勒米",
	"CX": "圣诞岛",
	"ST": "圣多美和普林西比",
	"SH": "圣赫勒拿",
	"KN": "圣基茨和尼维斯",
	"LC": "圣卢西亚",
	"SM": "圣马力诺",
	"PM": "圣皮埃尔和密克隆群岛",
	"VC": "圣文森特和格林纳丁斯",
	"LK": "斯里兰卡",
	"SK": "斯洛伐克",
	"SI": "斯洛文尼亚",
	"SJ": "斯瓦尔巴和扬马延",
	"SZ": "斯威士兰",
	"SD": "苏丹",
	"SR": "苏里南",
	"SB": "所罗门群岛",
	"SO": "索马里",
	"TJ": "塔吉克斯坦",
	"TW": "台湾",
	"TH": "泰国",
	"TZ": "坦桑尼亚",
	"TO": "汤加",
	"TC": "特克斯和凯科斯群岛",
	"TT": "特立尼达和多巴哥",
	"TN": "突尼斯",
	"TV": "图瓦卢",
	"TR": "土耳其",
	"TM": "土库曼斯坦",
	"TK": "托克劳",
	"WF": "瓦利斯和富图纳",
	"VU": "瓦努阿图",
	"GT": "危地马拉",
	"VE": "委内瑞拉",
	"BN": "文莱",
	"UG": "乌干达",
	"UA": "乌克兰",
	"UY": "乌拉圭",
	"UZ": "乌兹别克斯坦",
	"ES": "西班牙",
	"EH": "西撒哈拉",
	"GR": "希腊",
	"SG": "新加坡",
	"NC": "新喀里多尼亚",
	"NZ": "新西兰",
	"HU": "匈牙利",
	"SY": "叙利亚",
	"JM": "牙买加",
	"AM": "亚美尼亚",
	"YE": "也门",
	"IQ": "伊拉克",
	"IR": "伊朗",
	"IL": "以色列",
	"IT": "意大利",
	"IN": "印度",
	"ID": "印度尼西亚",
	"GB": "英国",
	"VG": "英属维尔京群岛",
	"IO": "英属印度洋领地",
	"JO": "约旦",
	"VN": "越南",
	"ZM": "赞比亚",
	"JE": "泽西岛",
	"TD": "乍得",
	"GI": "直布罗陀",
	"CL": "智利",
	"CF": "中非共和国",
	"CN": "中国",
	"MO": "中国澳门特别行政区",
	"HK": "中国香港特别行政区",
}

// 字符串包含关系，且大小写不敏感
func StrContains(s1, s2 string) bool {
	return strings.Contains(strings.ToLower(s1), strings.ToLower(s2))
}

var noRpt *ccache.Cache

type Config4scanAllModel struct {
	EsUlr           string `json:"EsUlr"`
	EnableSubfinder string `json:"EnableSubfinder"`
	UrlPrecise      string `json:"UrlPrecise"`
}

var Config4scanAll = Config4scanAllModel{}

// 配置缓存
var mData = map[string]interface{}{}
var (
	UrlPrecise      = "UrlPrecise"
	CacheName       = "CacheName"
	EnableSubfinder = "EnableSubfinder"
)

func GetAllConfigData() *map[string]interface{} {
	return &mData
}

// 判断对象是否为struct
func IsStruct(i interface{}) bool {
	return reflect.ValueOf(i).Type().Kind() == reflect.Struct
}

func GetPointVal(i interface{}) interface{} {
	if IsPointed(i) {
		return i
	} else {
		return &i
	}
}

func IsPointed(i interface{}) bool {
	return reflect.Indirect(reflect.ValueOf(i)).Kind() == reflect.Ptr
}

// 优先使用配置文件中的配置，否则从环境变量中读取
func GetVal(key string) string {
	key1 := os.Getenv(key)
	if "" != key1 {
		return fmt.Sprintf("%v", key1)
	}
	key1 = strings.ToLower(key)
	if s, ok := mData[key1]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", s))
	}
	return ""
}

// 获取interface
func GetAsAny(key string) interface{} {
	key1 := strings.ToLower(key)
	if s, ok := mData[key1]; ok {
		return s
	}
	return nil
}
func GetValByDefault(key, dftvl string) string {
	s := GetVal(key)
	if "" == s {
		return dftvl
	}
	return s
}

// 获取配置为bool
func GetValAsBool(key string) bool {
	return "true" == GetVal(key)
}

// 获取配置为int
func GetValAsInt(key string, nDefault int) int {
	s := GetAsAny(key)
	if reflect.ValueOf(s).Kind() == reflect.Int {
		return s.(int)
	} else if reflect.ValueOf(s).Kind() == reflect.Float64 {
		return int(s.(float64))
	}
	return nDefault
}

func GetValAsArrString(key string) []string {
	if o := GetAsAny(key); nil != o {
		var a []string
		if o1, ok := o.([]interface{}); ok {
			for _, x := range o1 {
				a = append(a, fmt.Sprintf("%v", x))
			}
		}
		return a
	}
	return nil
}

func GetValAsFloat64(key string, nDefault float64) float64 {
	s := GetAsAny(key)
	if reflect.ValueOf(s).Kind() == reflect.Float64 {
		return s.(float64)
	}
	return nDefault
}

func GetValAsInt64(key string, nDefault int64) int64 {
	s := GetAsAny(key)
	if reflect.ValueOf(s).Kind() == reflect.Int64 {
		return s.(int64)
	} else if reflect.ValueOf(s).Kind() == reflect.Float64 {
		return int64(s.(float64))
	}

	return nDefault
}

// 临时文件
var TmpFile = map[string][]*os.File{}

// 临时结果文件，例如 nmap
func GetTempFile(t string) *os.File {
	tempInput, err := ioutil.TempFile("", "scan4all-out*")
	if err != nil {
		log.Println(err)
		return nil
	} else {
		if t1, ok := TmpFile[t]; ok {
			t1 = append(t1, tempInput)
		} else {
			TmpFile[t] = []*os.File{tempInput}
		}
	}
	return tempInput
}

// 从配置json中读取naabu、httpx、nuclei等的细化配置
func ParseOption[T any](key string, opt *T) *T {
	m1 := GetVal4Any[map[string]interface{}](key)
	bA, err := Json.Marshal(m1)
	if nil == err && 0 < len(bA) {
		Json.Unmarshal(bA, opt)
	}
	return opt
}

// 其他类型
func GetVal4Any[T any](key string) T {
	var t1 T
	if s, ok := mData[key]; ok {
		t2, ok := s.(T)
		t1 = t2
		if ok {
			return t2
		}
	}
	return t1
}

// 判断文件是否存在
func FileExists(s string) bool {
	if _, err := os.Stat(s); err == nil {
		return true
	}
	return false
}

func ReadFile(s string) []byte {
	b, err := ioutil.ReadFile(s)
	if nil == err && 0 < len(b) {
		return b
	} else {
		log.Println("read config file error: ", err)
	}
	return nil
}

// 读区配置中的字典文件
func GetVal4File(key, szDefault string) string {
	s := GetVal(key)
	if "" != s && FileExists(s) {
		//log.Println("start read config file ", s)
		b := ReadFile(s)
		if nil == b && 0 < len(b) {
			return string(b)
		}
	}
	return szDefault
}

// 读区配置中的字典文件
func GetVal4Filedefault(key, szDefault string) string {
	s := GetVal4File(key, szDefault)
	if 2 == len(strings.Split(strings.Split(s, "\n")[0], ":")) {
		s = strings.ReplaceAll(s, ":", "\t")
	}
	return s
}

var SzPwd string

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var letterRunes = []rune(letterBytes)

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

var ConfigChangeCbk func()

// 加载配置文件
func LoadCoinfig(config *viper.Viper) {
	if nil == config {
		config = viper.New()
	}
	viper.Set("Verbose", true)
	pwd, _ := os.Getwd()
	SzPwd = pwd
	//var ConfigName = "config/config.json"
	config.SetConfigName("config") //name of config file (without extension)
	config.AddConfigPath("./config/")
	config.AddConfigPath("./")
	config.AddConfigPath("$HOME")
	config.AddConfigPath("$HOME/config/")
	config.AddConfigPath("$HOME/.config/")
	config.AddConfigPath("/etc/")

	// 显示调用
	config.SetConfigType("json")
	//if "" != ConfigName {
	//	config.SetConfigFile(ConfigName)
	//}
	err := config.ReadInConfig() // 查找并读取配置文件
	if err != nil {              // 处理读取配置文件的错误
		log.Println("config.ReadInConfig ", err)
		return
	}
	// 将读取的配置信息保存至全局变量Conf
	if err := config.Unmarshal(&Config4scanAll); err != nil {
		log.Println("config.Unmarshal ", err)
		return
	}
	config.Unmarshal(&mData)
	//config.OnConfigChange(func(e fsnotify.Event) {
	//	log.Println("Config file changed, now reLoad it: ", e.Name)
	//	LoadCoinfig(config)
	//	if nil != ConfigChangeCbk {
	//		ConfigChangeCbk()
	//	}
	//})
	// 避免 hold
	//go config.WatchConfig()
}

// 初始化配置文件信息，这个必须先执行
func InitConfigFile() {
	LoadCoinfig(nil)
	Fuzzthreads = GetValAsInt("Fuzzthreads", 32)
	EnableHoneyportDetection = GetValAsBool("EnableHoneyportDetection")
	noRpt = GetMemoryCache(5000, noRpt)
}

// 初始化配置文件信息，这个必须先执行
func Init2() {
	LoadCoinfig(nil)
	Fuzzthreads = GetValAsInt("Fuzzthreads", 32)
	EnableHoneyportDetection = GetValAsBool("EnableHoneyportDetection")

	noRpt = GetMemoryCache(5000, noRpt)
}

var G_Options interface{}

func GetNmap() string {
	nmap := "nmap"
	if runtime.GOOS == "windows" {
		nmap = "nmap.exe"
	}
	return nmap
}

var hvNmap = false

func CheckHvNmap() bool {
	if !GetValAsBool("priorityNmap") {
		return false
	}
	if hvNmap {
		return hvNmap
	}
	r, _ := regexp.Compile(`.*Starting Nmap \d\.\d+.*`)
	s, err := DoCmd(GetNmap(), "-v")
	if nil == err && r.Match([]byte(s)) {
		hvNmap = true
		return hvNmap
	}
	return false
}

func doReadBuff(buf *bytes.Buffer) string {
	var a = []string{}
	var data []byte = make([]byte, 1024)
	n, err := buf.Read(data)
	for nil == err && 0 < n {
		s1 := string(data[:n])
		fmt.Println(s1)
		a = append(a, s1)
		n, err = buf.Read(data)
	}
	return strings.Join(a, "")
}

// 最佳的方法是将命令写到临时文件，并通过bash进行执行
func DoCmd(args ...string) (string, error) {
	cmd := exec.Command(args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout // 标准输出
	cmd.Stderr = &stderr // 标准错误
	err := cmd.Run()
	outStr, errStr := doReadBuff(&stdout), doReadBuff(&stderr)
	// out, err := cmd.CombinedOutput()
	if nil != err {
		return "", err
	}
	return string(outStr + "\n" + errStr), err
}

func doFile(config *embed.FS, s fs.DirEntry, szPath string) {
	os.MkdirAll(szPath, os.ModePerm)
	szPath = szPath + "/" + s.Name()
	if FileExists(szPath) {
		return
	}
	if data, err := config.ReadFile(szPath); nil == err {
		if err := ioutil.WriteFile(szPath, data, os.ModePerm); nil == err {
			//log.Println("write ok: ", szPath)
		}
	}
}
func doDir(config *embed.FS, s fs.DirEntry, szPath string) {
	szPath = szPath + "/" + s.Name()
	if x1, err := config.ReadDir(szPath); nil == err {
		for _, x2 := range x1 {
			if x2.IsDir() {
				doDir(config, x2, szPath)
			} else {
				doFile(config, x2, szPath)
			}
		}
	} else {
		log.Println("doDir:", err)
	}
}

var UserHomeDir string = "./"

// 初始化到开头
func Init1(config *embed.FS) {
	dirname, err := os.UserHomeDir()
	if nil == err {
		UserHomeDir = dirname
		newpath := UserHomeDir + "/.config/nuclei"
		err := os.MkdirAll(newpath, os.ModePerm)
		szFile := newpath + "/.nuclei-ignore"
		if nil == err && !FileExists(szFile) {
			ioutil.WriteFile(szFile, []byte(`tags:
  - "dos"`), os.ModePerm)
		}
	}
	//szPath := "config"
	//log.Println("wait for init config files ... ")
	// 释放config目录到本地
	//if nil != config {
	//	if x1, err := config.ReadDir(szPath); nil == err {
	//		for _, x2 := range x1 {
	//			if x2.IsDir() {
	//				doDir(config, x2, szPath)
	//			} else {
	//				doFile(config, x2, szPath)
	//			}
	//		}
	//	} else {
	//		log.Println("Init1:", err)
	//	}
	//}
	InitConfigFile()
	Init2()
	log.Println("init config files is over .")
}

func Mkdirs(s string) {
	os.MkdirAll(s, os.ModePerm)
}

func isMap(a interface{}) bool {
	t := reflect.TypeOf(a)
	return t.Kind() == reflect.Map && t.Key().Kind() == reflect.String
}

// 获取 Sha1
func GetSha1(a ...interface{}) string {
	h := sha1.New()
	//if isMap(a[0]) { // map嵌套map 确保顺序，相同数据map得到相同的sha1
	if data, err := Json.Marshal(a); nil == err {
		h.Write(data)
	} else {
		for _, x := range a {
			h.Write([]byte(fmt.Sprintf("%v", x)))
		}
	}
	bs := h.Sum(nil)
	return hex.EncodeToString(bs) // fmt.Sprintf("%x", bs)
}

var Abs404 = "/scan4all404"
var defaultInteractionDuration time.Duration = 180 * time.Second

func TestRepeat(a ...interface{}) bool {
	if nil == noRpt {
		return false
	}
	k := GetSha1(a...)
	x1 := noRpt.Get(k)
	if nil == x1 {
		noRpt.Set(k, true, defaultInteractionDuration)
		return false
	}
	return true
}

func TestRepeat4Save(key string, a ...interface{}) (interface{}, bool) {
	if nil == noRpt {
		return nil, false
	}
	x1 := noRpt.Get(key)
	if nil == x1 {
		noRpt.Set(key, a, defaultInteractionDuration)
		return nil, false
	}
	return x1.Value(), true
}

// 关闭cache
func CloseCache() {
	if nil != noRpt {
		//log.Println("start clear noRpt cache")
		noRpt.Clear()
		noRpt.Stop()
		noRpt = nil
	}

	if nil != clientHttpCc {
		CloseAllHttpClient()
		clientHttpCc.Clear()
		clientHttpCc.Stop()
		clientHttpCc = nil
	}
}

// 绝对404检测
// 相同 url 本实例中只检测一次
func TestIs404(szUrl string) (r01 *Response, err error, ok bool) {
	key := "TestIs404" + szUrl
	x1 := noRpt.Get(key)
	if nil != x1 {
		if a1, ok := x1.Value().([]interface{}); ok {
			r01 = a1[0].(*Response)
			if nil == a1[1] {
				err = nil
			} else {
				err = a1[1].(error)
			}
			ok = a1[2].(bool)
			return r01, err, ok
		}
	}
	sz404 := szUrl + Abs404
	client := GetClient(sz404)
	if nil != client {
		client.Client.Timeout = 5
		//log.Printf("%v %s \n", client, sz404)
		var x05 *http.Transport = client.Client.Transport.(*http.Transport)
		if nil != x05 {
			x05.DisableKeepAlives = true
		}
	}

	log.Println("start test ", sz404)
	r01, err = HttpRequset(sz404, "GET", "", false, map[string]string{"Connection": "close"})
	ok = err == nil && nil != r01 && 404 == r01.StatusCode
	noRpt.Set(key, []interface{}{r01, err, ok}, defaultInteractionDuration)
	//client.Client.Timeout = 10
	log.Println("end test ", sz404)
	return r01, err, ok
}
func TestIs404Page(szUrl string) (page *Page, r01 *Response, err error, ok bool) {
	r01, err, ok = TestIs404(szUrl)
	page = &Page{Url: &szUrl, Resqonse: r01}
	if nil != r01 {
		szTitle := ""
		page.Is302 = r01.StatusCode == 302
		page.Is403 = r01.StatusCode == 403
		page.IsBackUpPage = false
		page.StatusCode = r01.StatusCode
		page.Resqonse = r01
		page.Title = &szTitle
		page.BodyLen = len([]byte(r01.Body))
		page.BodyStr = &r01.Body
		page.LocationUrl = &r01.Location
	}
	return
}

var fnInit []func()
var fnInitHd []func()

func RegInitFunc4Hd(cbk func()) {
	fnInitHd = append(fnInitHd, cbk)
}

func RegInitFunc(cbk func()) {
	fnInit = append(fnInit, cbk)
}

// 初始化
//
//	1、读取配置文件
//	2、驱动执行 其他初始化注册的func
func DoInit(config *embed.FS) {
	Init1(config)
	rand.Seed(time.Now().UnixNano())
	fnInit = append(fnInitHd, fnInit...)
	for _, x := range fnInit {
		x()
	}
	fnInit = nil
	//PrintCaller()
}

// 拷贝配置信息到o中
func CopyConfig(o interface{}) {
	data, err := Json.Marshal(mData)
	if nil == err {
		Json.Unmarshal(data, o)
	}
}

func RemoveDuplication_mapNoEmpy(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		_, ok := set[v]
		if ok {
			continue
		}
		set[v] = struct{}{}
		arr[j] = v
		j++
	}

	return arr[:j]
}

func RemoveDuplication_map(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		if _, ok := set[v]; ok || 0 == len(strings.TrimSpace(v)) {
			continue
		}
		set[v] = struct{}{}
		arr[j] = v
		j++
	}

	return arr[:j]
}

func RemoveDuplication_map4Any(arr []interface{}) []interface{} {
	set := make(map[string]struct{}, len(arr))
	j := 0
	var aR = make([]interface{}, len(arr))
	for _, v1 := range arr {
		v := fmt.Sprintf("%v", v1)
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		aR[j] = v1
		j++
	}

	return aR[:j]
}
