package lib

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
