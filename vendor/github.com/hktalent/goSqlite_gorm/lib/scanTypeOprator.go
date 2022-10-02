package lib

// 扫描目标，非存储，chan时用
type Target4Chan struct {
	TaskId     string `json:"task_id"`     // 任务id
	ScanWeb    string `json:"scan_web"`    // base64解码后
	ScanType   int    `json:"scan_type"`   // 扫描类型
	ScanConfig string `json:"scan_config"` // 本次任务的若干细节配置，json格式的string
}

// 判断 scanType中是否包含了checkType扫描
func HasScanType(scanType int, checkType int) bool {
	return scanType&checkType == checkType
}

// 判断 scanType中是否包含了checkType扫描
func HasScanTypes(scanType int, checkType ...int) bool {
	return HasScanType(scanType, MergeScanType(checkType...))
}

// 合并所有扫描类型
func MergeScanType(args ...int) int {
	var i int = 0
	for j := range args {
		i = i | j
	}

	return i
}
