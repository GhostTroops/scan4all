package pkg

import (
	"encoding/json"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"os"
)

type Config4scanAllModel struct {
	EsUlr           string `json:"EsUlr"`
	EnableSubfinder string `json:"EnableSubfinder"`
	UrlPrecise      string `json:"UrlPrecise"`
}

var Config4scanAll = Config4scanAllModel{}
var mData = map[string]interface{}{}

// 优先使用配置文件中的配置，否则从环境变量中读取
func GetVal(key string) string {
	if s, ok := mData[key]; ok {
		return s.(string)
	}
	return os.Getenv(key)
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

// 读区配置中的字典文件
func GetVal4File(key, szDefault string) string {
	s := GetVal(key)
	if "" != s {
		b, err := ioutil.ReadFile(s)
		if nil == err && 0 < len(b) {
			return string(b)
		}
	}
	return szDefault
}

func init() {
	var ConfigName = "config/config.json"
	config := viper.New()
	config.AddConfigPath("./")
	config.AddConfigPath("./config/")
	config.AddConfigPath("$HOME")
	config.AddConfigPath("/etc/")
	// 显示调用
	config.SetConfigType("json")
	if "" != ConfigName {
		config.SetConfigFile(ConfigName)
	}
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
	viper.Set("Verbose", false)
}

var G_Options interface{}
