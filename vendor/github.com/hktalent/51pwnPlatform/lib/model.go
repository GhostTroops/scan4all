package lib

// 状态和消息，共用
type MSModle struct {
	Message string `json:"message"` // message字段在非200的时候，可以设置，来描述目前失败的主要原因是啥
	Status  string `json:"status"`  // 状态码, 200 成功受理该检测任务；300 签名验证失败；400 系统内部异常；检测活动没有结束; 500 系统内部异常
}

// -------------------------------------

// 阿里 蚂蚁金服 任务数据
type AlipayTask struct {
	UserId     string `json:"user_id" gorm:"type:varchar(30)"`
	ScanWeb    string `json:"scan_web"`    // 具体要扫描的站点base64 编码, 扫描目标
	DataSign   string `json:"data_sign"`   // 请求数据的签名，基于Rsa 私钥 （2048）签名，签名的数据内容格
	TaskId     string `json:"task_id"`     // 任务id
	ScanType   int    `json:"scan_type"`   // 扫描类型，math.MaxInt 表示所有扫描类型，至少：位为1的至少1个子任务
	ScanConfig string `json:"scan_config"` // 本次任务的若干细节配置，json格式的string
}

// 阿里 蚂蚁金服 任务 返回（状态码）
type AlipayTaskResponse struct {
	MSModle   `json:",inline"`
	FetchTime int `json:"fetch_time"` // 默认是10，单位为分钟，Status为200的时候，支付宝会读取fetchTime字段值，该字段表示希望支付宝间隔多久后来查询检测结果，如果该字段为空，支付宝会安装默认的时间间隔来提取
	Capacity  int `json:"capacity"`   // 任务剩余容量
}

// -------------------------------------

// 任务结果查询
type TastResult struct {
	DataSign string `json:"data_sign"` // 请求数据的签名，基于Rsa 私钥 （2048）签名，签名的数据内容格
	TaskId   string `json:"task_id"`   // 任务id
	Op       string `json:"op"`        // POST请求中携带op=1的参数表示停止task_id对应的任务，且先校验签名
}

// 漏洞信息
type VulsInfo struct {
	TemplateId     string   `json:"template_id"`      // 检测该漏洞的POC id
	BugSummary     string   `json:"bug_summary"`      // 漏洞概要
	BugDescription string   `json:"bug_description"`  // 漏洞描述
	BugLevel       string   `json:"bug_level"`        // 漏洞等级
	FixDetail      string   `json:"fix_detail"`       // 修复方案
	RiskType       string   `json:"risk_type"`        // 风险类型，字符串"0","1"，定义如下: NORMAL("0", "普通漏洞"), PAYMENT("1", "支付相关漏洞")
	BugHazard      string   `json:"bug_hazard"`       // 2017年11月20日 新增，危害描述
	Targets        []Target `json:"targets" gorm:"-"` // 该漏洞对应的目标
}

// 更新签名key
type UpdateKeyModel struct {
	UserId   string `json:"user_id" gorm:"type:varchar(30)"`
	Key      string `json:"key"`       // 更新的key
	DataSign string `json:"data_sign"` // 请求数据的签名，基于Rsa 私钥 （2048）签名，签名的数据内容格
}

// bug记录
type Target struct {
	VulUrl     string `json:"vul_url"`    // 存在漏洞的url
	BugDetail  string `json:"bug_detail"` // 漏洞攻击证明
	StartScan  string `json:"start_scan"` // 开始扫描时间
	FinishTime string `json:"finishTime"` // 扫描结束时间
}

// 执行结果
type TastResultResponse struct {
	Bugs    []VulsInfo `json:"bugs"`
	MSModle `json:",inline"`
}

// -------------------------------------

// 容量
type Limit struct {
	DataSign          string `json:"data_sign"`           // 请求数据的签名，基于Rsa 私钥 （2048）签名，签名的数据内容格
	QueryCapacityOnly string `json:"query_capacity_only"` // true 表示获取容量, 并先验证签名
}

// 容量返回
// 200	成功受理该请求
// 300	签名验证失败
// 400	系统内部异常
type LimitResponse struct {
	MSModle      `json:",inline"`
	Capcity      int `json:"capcity"`      // 任务剩余容量
	TotalCapcity int `json:"totalCapcity"` // 任务总容量
}
