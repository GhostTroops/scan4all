package pkg

import (
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

func GetVal(key string) string {
	if s, ok := mData[key]; ok {
		return s.(string)
	}
	return os.Getenv(key)
}
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
	var ConfigName = "config.json"
	config := viper.New()
	config.AddConfigPath("./")
	config.AddConfigPath("./config")
	config.AddConfigPath("$HOME")
	config.AddConfigPath("/etc/")
	// 显示调用
	//config.SetConfigType("json")
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
