package util

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/hktalent/scan4all/lib"
	"github.com/spf13/viper"
	"io/fs"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// 字符串包含关系，且大小写不敏感
func StrContains(s1, s2 string) bool {
	return strings.Contains(strings.ToLower(s1), strings.ToLower(s2))
}

type Config4scanAllModel struct {
	EsUlr           string `json:"EsUlr"`
	EnableSubfinder string `json:"EnableSubfinder"`
	UrlPrecise      string `json:"UrlPrecise"`
}

var Config4scanAll = Config4scanAllModel{}
var mData = map[string]interface{}{}
var (
	UrlPrecise      = "UrlPrecise"
	CacheName       = "CacheName"
	EnableSubfinder = "EnableSubfinder"
)

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

func Init() {
	pwd, _ := os.Getwd()
	SzPwd = pwd
	var ConfigName = "config/config.json"
	config := viper.New()
	config.AddConfigPath("./")
	config.AddConfigPath("./config/")
	config.AddConfigPath("$HOME")
	config.AddConfigPath("/etc/")
	nT, err := strconv.Atoi(GetVal4File("Fuzzthreads", "32"))
	if nil != err {
		nT = 32
	}
	Fuzzthreads = nT
	// 显示调用
	config.SetConfigType("json")
	if "" != ConfigName {
		config.SetConfigFile(ConfigName)
	}
	err = config.ReadInConfig() // 查找并读取配置文件
	if err != nil {             // 处理读取配置文件的错误
		log.Println("config.ReadInConfig ", err)
		return
	}
	// 将读取的配置信息保存至全局变量Conf
	if err := config.Unmarshal(&Config4scanAll); err != nil {
		log.Println("config.Unmarshal ", err)
		return
	}
	config.Unmarshal(&mData)
	viper.Set("Verbose", false)
	initEs()
	lib.EnableHoneyportDetection = GetValAsBool("EnableHoneyportDetection")
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
func Init2(config *embed.FS) {
	dirname, err := os.UserHomeDir()
	if nil == err {
		UserHomeDir = dirname
	}
	szPath := "config"
	log.Println("wait for init config files ... ")
	if x1, err := config.ReadDir(szPath); nil == err {
		for _, x2 := range x1 {
			if x2.IsDir() {
				doDir(config, x2, szPath)
			} else {
				doFile(config, x2, szPath)
			}
		}
	} else {
		log.Println("Init:", err)
	}
	Init()
	log.Println("init config files is over .")
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
