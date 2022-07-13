package fingerprint

import (
	_ "embed"
	"encoding/json"
)

type IdMethod int

const (
	Reg_idMethod       IdMethod = 11515 // 识别方式：正则表达式
	Text_idMethod      IdMethod = 11516 // 识别方式：文本
	Bin_idMethod       IdMethod = 11517 // 识别方式：bin，二进制
	Base64_idMethod    IdMethod = 11518 // 识别方式：base64
	Md5_idMethod       IdMethod = 11519 // 识别方式：md5
	Header_idPart      IdMethod = 11520 // 识别区域：header
	Body_idPart        IdMethod = 11521 // 识别区域：body
	Raw_idPart         IdMethod = 11522 // 识别区域：raw
	Status_code_idPart IdMethod = 8998  // 识别区域：状态吗
)

//go:embed db/fg.json
var FgData string
var FGDataMap = make(map[string]interface{})

func init() {
	json.Unmarshal([]byte(FgData), &FGDataMap)
}
