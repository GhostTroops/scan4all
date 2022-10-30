package lib

import "gorm.io/gorm"

// regist user info
type RegUser struct {
	gorm.Model
	UserId string `json:"user_id" gorm:"type:varchar(30);uniqueIndex:su01"`
	Pswd   string `json:"pswd" gorm:"type:varchar(30);"`
	Email  string `json:"email" gorm:"type:varchar(60);"`
}

// 辅助分析
type MzInfoMod struct {
	gorm.Model
	AlipayTask      `json:",inline"` // 任务id相关信息
	NetError        string           `json:"net_error"`        // 网络异常时的信息
	FingerprintInfo string           `json:"fingerprint_info"` // 命中指纹信息
	Pocs            string           `json:"pocs"`             // 关联的poc列表
	PocCount        int              `json:"poc_count"`        // 命中poc统计
}

// 任务数据库模型
type AlipayTaskDb struct {
	AlipayTask `json:",inline"`
	RunStatus  int `json:"run_status"` // 整体任务执行的状态：1、未执行 ； 2、执行中 ； 3、执行结束 ；4、主动要求停止
}

// 存储
type AlipayTaskDbSave struct {
	gorm.Model
	AlipayTaskDb `json:",inline"`
	ScanTask     []*ScanTaskChild `gorm:"foreignKey:ParentTaskId;references:ID"` // 若干个子任务
}

// 扫描任务的子目标
// UNIQUE KEY `scan_task_children_scan_type_status_IDX` (`scan_type_status`,`parent_task_id`,`child_target`) USING BTREE,
type ScanTaskChild struct {
	gorm.Model
	ScanTypeStatus int    `json:"scan_type_status"`                                                           // 1、未执行 ； 2、执行中 ； 3、执行结束 ；4、主动要求停止
	ParentTaskId   int    `json:"parent_task_id" gorm:"uniqueIndex:ss1,type:btree;not null;"`                 // 父任务的id
	ChildTarget    string `json:"child_target" gorm:"uniqueIndex:ss1,type:btree;type:varchar(200);NOT NULL;"` // 子任务目标，例如 ssl中得到的域名，
	ScanType       int    `json:"scan_type" gorm:"uniqueIndex:ss1,type:btree;not null;"`                      // 任务类型：子域名、nmap，这里只能时单一的类型，那么唯一索引，ChildTarget + ScanType,避免重复做
}

// 子任务 任务状态
type SaveTaskStatus struct {
	TaskIds string `json:"task_ids"` // 逗号、分号、换行分隔; 执行结束，需要更新状态为 3的任务列表
	TaskNum int    `json:"task_num"` // 当前节点任务并发数，总任务容量计算
	NodeId  string `json:"node_id"`  // 节点唯一id，可以用Mac地址
}

// 漏洞结果列表
type VulResults struct {
	gorm.Model
	Target     `json:",inline"`
	VulsInfo   `json:",inline"`
	AlipayTask `json:",inline"`
}
