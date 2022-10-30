package util

import "time"

func GetDate(arg ...string) string {
	var currentTime = time.Now()
	if 1 < len(arg) {
		t1, err1 := time.Parse(arg[0], arg[1])
		if nil == err1 {
			currentTime = t1
		}
	}
	l, err := time.LoadLocation("Asia/Shanghai")
	if nil == err {
		currentTime = time.Now().In(l)
	}
	return currentTime.Format("2006-01-02 15:04:05")
}
