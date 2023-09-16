package util

import (
	"bytes"
	"crypto/sha1"
	"embed"
	"encoding/json"
	"fmt"
	util1 "github.com/hktalent/go-utils"
	"github.com/karlseguin/ccache"
	"github.com/spf13/viper"
	"io/fs"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 字符串包含关系，且大小写不敏感
func StrContains(s1, s2 string) bool {
	return strings.Contains(strings.ToLower(s1), strings.ToLower(s2))
}

var NoRpt *ccache.Cache

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
	s := GetValByDefault(key, fmt.Sprintf("%d", nDefault))
	n, err := strconv.Atoi(s)
	if err != nil {
		n = nDefault
	}
	return n
}

var TmpFile = map[string][]*os.File{}

// 临时结果文件，例如 nmap
func GetTempFile(t string) *os.File {
	tempInput, err := ioutil.TempFile("", "scan4all-out*")
	if err != nil {
		//log.Println(err)
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
	bA, err := json.Marshal(m1)
	if nil == err && 0 < len(bA) {
		json.Unmarshal(bA, opt)
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

// 读区配置中的字典文件
func GetVal4File(key, szDefault string) string {
	s := GetVal(key)
	if "" != s && FileExists(s) {
		//log.Println("start read config file ", s)
		b, err := ioutil.ReadFile(s)
		if nil == err && 0 < len(b) {
			//log.Println("read config file ok: ", s)
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
	//})
	// 避免 hold
	//go config.WatchConfig()
}

// 初始化配置文件信息，这个必须先执行
func Init2() {
	LoadCoinfig(nil)
	Fuzzthreads = GetValAsInt("Fuzzthreads", 32)
	EnableHoneyportDetection = GetValAsBool("EnableHoneyportDetection")
	initEs()

	NoRpt = GetMemoryCache(5000, NoRpt)
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
	log.Println("start run: " + strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout // 标准输出
	cmd.Stderr = &stderr // 标准错误
	err := cmd.Run()
	if nil != err {
		return "", err
	}
	outStr, _ := doReadBuff(&stdout), doReadBuff(&stderr)
	// out, err := cmd.CombinedOutput()

	return outStr, err
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
	szPath := "config"
	log.Println("wait for init config files ... ")
	if nil != config {
		if x1, err := config.ReadDir(szPath); nil == err {
			for _, x2 := range x1 {
				if x2.IsDir() {
					doDir(config, x2, szPath)
				} else {
					doFile(config, x2, szPath)
				}
			}
		} else {
			log.Println("Init2:", err)
		}
	}
	Init2()
	init3()
	log.Println("init config files is over .")
}

func Mkdirs(s string) {
	os.MkdirAll(s, os.ModePerm)
}

// 获取 Sha1
func GetSha1(a ...interface{}) string {
	h := sha1.New()
	for _, x := range a {
		h.Write([]byte(fmt.Sprintf("%v", x)))
	}
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

var Abs404 = "/scan4all404"
var defaultInteractionDuration time.Duration = 180 * time.Second
var LoRpt sync.Mutex

func TestRepeat(a ...interface{}) bool {
	LoRpt.Lock()
	defer LoRpt.Unlock()
	if nil == NoRpt {
		return false
	}
	k := GetSha1(a...)
	x1 := NoRpt.Get(k)
	if nil == x1 {
		NoRpt.Set(k, true, defaultInteractionDuration)
		return false
	}
	return true
}

func TestRepeat4Save(key string, a ...interface{}) (interface{}, bool) {
	if nil == NoRpt {
		return nil, false
	}
	x1 := NoRpt.Get(key)
	if nil == x1 {
		NoRpt.Set(key, a, defaultInteractionDuration)
		return nil, false
	}
	return x1.Value(), true
}

// 关闭cache
func CloseCache() {
	if nil != NoRpt {
		NoRpt.Clear()
		NoRpt.Stop()
		NoRpt = nil
	}

	if nil != clientHttpCc {
		CloseAllHttpClient()
		clientHttpCc.Clear()
		clientHttpCc.Stop()
		clientHttpCc = nil
	}
}

func GetObjFromNoRpt[T any](key string) T {
	x1 := NoRpt.Get(key)
	if nil != x1 {
		if a1, ok := x1.Value().(T); ok {
			return a1
		}
	}
	var x2 T
	return x2
}

func TestIs404(szUrl string) (r01 *Response, err error, ok bool) {
	r01, err, ok = TestIsWeb01(szUrl)
	ok = err == nil && nil != r01 && (404 == r01.StatusCode || 302 == r01.StatusCode)
	return r01, err, ok
}

// 绝对404检测
// 相同 url 本实例中只检测一次
func TestIsWeb01(szUrl string) (r01 *Response, err error, ok bool) {
	if "" == szUrl {
		return nil, nil, false
	}
	key := "TestIs404" + szUrl
	a1 := GetObjFromNoRpt[[]interface{}](key)
	if nil != a1 {
		r01 = a1[0].(*Response)
		if nil == a1[1] {
			err = nil
		} else {
			err = a1[1].(error)
		}
		ok = a1[2].(bool)
		return r01, err, ok
	}
	sz404 := szUrl + Abs404
	client1 := GetClient(sz404, map[string]interface{}{
		"Timeout":                    30 * 60,
		"MaxIdleConns":               100,
		"MaxIdleConnsPerHost":        2,
		"DefaultMaxIdleConnsPerHost": 2,
		"MaxConnsPerHost":            0,
	})
	PutClientCc(sz404, client1)

	//if nil != client {
	//	client.Client.Timeout = 500
	//	client.ErrCount = 0
	//	//client.ErrLimit = 9999
	//	//log.Printf("%v %s \n", client, sz404)
	//}

	//log.Println("start test ", sz404)
	var mh1 map[string]string
	//if strings.HasPrefix(sz404, "http://") {
	//	mh1 = map[string]string{
	//		//"Connection":   "close",
	//		"Content-Type": "",
	//	}
	//}
	r01, err = HttpRequset(sz404, "GET", "", false, mh1)
	ok = err == nil && nil != r01 && (200 <= r01.StatusCode)
	if nil != err {
		CloseHttpClient(sz404)
		log.Println(sz404, err)
	} else {
		//log.Printf("%d %s %s\n", r01.StatusCode, r01.Protocol, sz404)
	}
	SetNoRpt(key, []interface{}{r01, err, ok})
	//client.Client.Timeout = 10
	//log.Println("end test ", sz404)
	return r01, err, ok
}

func SetNoRpt(key string, data interface{}) {
	NoRpt.Set(key, data, defaultInteractionDuration)
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

// 注册解决初始化控制顺序问题
func RegInitFunc(cbk func()) {
	fnInit = append(fnInit, cbk)
}

func RegInitFunc4Hd(cbk func()) {
	fnInitHd = append(fnInitHd, cbk)
}

func upAllTools() {
	var wg sync.WaitGroup
	if "" == SzPwd {
		if s, err := os.Getwd(); nil == err {
			SzPwd = s
		}
	}
	if "" == SzPwd {
		SzPwd = "."
	}
	szPath := SzPwd + "/config/" + runtime.GOOS
	if err := os.MkdirAll(szPath, os.ModePerm); nil != err {
		log.Println(err, szPath)
	}
	/* $HOME/go/bin/

	ls config/darwin/ |xargs -I % rm -rf $HOME/go/bin/%
	ls config/darwin/ |xargs -I % ln -s $PWD/config/darwin/% $HOME/go/bin/%
	*/
	for _, x := range []string{"nuclei", "naabu", "httpx", "dnsx", "subfinder", "katana", "uncover", "tlsx"} {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			util1.UpdateScan4allVersionToLatest(true, "projectdiscovery", s, szPath)
			szF := fmt.Sprintf("%s%c%s", szPath, os.PathSeparator, s)
			szH, _ := os.UserHomeDir()
			szF1 := fmt.Sprintf("%s%c%s%s", szH, os.PathSeparator, "/go/bin/", s)
			if !FileExists(szF) && FileExists(szF1) {
				if runtime.GOOS == "windows" {
					DoCmd("mklink", "-/H", szF, szF1)
					//if srcFile, err := os.OpenFile(szF1, os.O_RDONLY, os.ModePerm); nil == err {
					//	defer srcFile.Close()
					//	if destFile, err := os.OpenFile(szF, os.O_CREATE, os.ModePerm); nil == err {
					//		defer destFile.Close()
					//		io.Copy(destFile, srcFile)
					//	}
					//}
				} else {
					DoCmd("ln", "-s", szF1, szF)
				}
			}
		}(x)
	}
	wg.Wait()
}

// 所有初始化的总入口
func DoInit(config *embed.FS) {
	Init1(config)
	rand.Seed(time.Now().UnixNano())

	fnInit = append(fnInitHd, fnInit...)
	for _, x := range fnInit {
		x()
	}
	fnInit = nil
	fnInitHd = nil

	//upAllTools()
}

func RemoveDuplication_map(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
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
