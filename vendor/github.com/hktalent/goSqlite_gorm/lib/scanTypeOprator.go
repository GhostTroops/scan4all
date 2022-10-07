package lib

// 判断 scanType中是否包含了checkType扫描
func HasScanType(scanType int64, checkType int64) bool {
	return scanType&checkType == checkType
}

// 判断 scanType中是否包含了checkType扫描
func HasScanTypes(scanType int64, checkType ...int64) bool {
	return HasScanType(scanType, MergeScanType(checkType...))
}

// 合并所有扫描类型
func MergeScanType(args ...int64) int64 {
	var i int64 = 0
	for _, j := range args {
		i = i | j
	}

	return i
}
