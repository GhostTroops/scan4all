package lib

import (
	"encoding/json"
	util "github.com/hktalent/go-utils"
	"log"
)

// 服务配置
type ConfigServer struct {
	UseMysql      bool   `json:"usemysql"`
	DbUrl         string `json:"dburl"`
	DebugDbUrl    string `json:"debugdburl"`
	Debug         bool   `json:"debug"`
	MaxOpenConns  int    `json:"maxopenconns"`
	AutoRmOldData bool   `json:"autormolddata"` // 自动删除10小时前数据
	OnClient      bool   `json:"onclient"`      // api server 运行控制标志
}

// server 端全局配置
var GConfigServer = ConfigServer{MaxOpenConns: 200, UseMysql: true}

// 初始化配置文件信息，这个必须先执行
func init() {
	util.RegInitFunc(func() {
		x := util.GetAllConfigData()
		if data, err := json.Marshal(x); nil == err {
			if err = json.Unmarshal(data, &GConfigServer); nil != err {
				log.Println(err)
			}
		} else {
			log.Println(err)
		}
	})
	//pwd, _ := os.Getwd()
	//var ConfigName = pwd + "/config/config.json"
	//config := viper.New()
	////config.AddConfigPath("./")
	////config.AddConfigPath("./config/")
	////config.AddConfigPath("$HOME")
	////config.AddConfigPath("/etc/")
	//config.SetConfigType("json")
	//config.SetConfigFile(ConfigName)
	//err := config.ReadInConfig() // 查找并读取配置文件
	//if err != nil {              // 处理读取配置文件的错误
	//	log.Println("config.ReadInConfig ", err)
	//	return
	//}
	//// 将读取的配置信息保存至全局变量Conf
	//if err := config.Unmarshal(&GConfigServer); err != nil {
	//	log.Println("config.Unmarshal ", err)
	//	return
	//}
	//var mData = map[string]interface{}{}
	//config.Unmarshal(&mData)
	//viper.Set("Verbose", false)

}
