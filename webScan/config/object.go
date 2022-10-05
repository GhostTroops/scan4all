package Configs

import (
	"log"
	"strings"
)

var ExpJsonMap ExpJson       // 定义ExpJson文件对象
var ConfigJsonMap ConfigJson // 定义基础配置文件对象
var UserObject UserOption    // 定义用户输出flag标对象
var RespObject HttpResult    // 定义http返回结果对象

var ColorMistake *log.Logger // 定义错误日志输出
var ColorInfo *log.Logger    // 定义标准日志输出
var ColorSend *log.Logger    // 定义消息发送输出
var ColorSuccess *log.Logger // 定义成功日志输出
var FindResltAll []string    //存放所有的poc返回结果
var FindReslt []string
var ReqData *strings.Reader
var JudgeStatus = map[string]bool{`contains`: false, `code`: false}
var FlageStatus = false
