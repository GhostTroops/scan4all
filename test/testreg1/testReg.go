package main

import (
	_ "embed"
	"log"
	"regexp"
	"strings"
)

// 备份、敏感文件 http头类型 ContentType 检测
//go:embed ../../brute/dicts/fuzzContentType1.txt
var fuzzct1 string

// 测试正则表达式是否正确
func main() {
	a := strings.Split(fuzzct1, "\n")
	for _, reg := range a {
		r1, err := regexp.Compile(reg)
		if nil != err {
			log.Println(reg, " regexp.Compile error: ", err)
		} else {
			if 0 < len(r1.Find([]byte("application/wordxxxdownload"))) {
				log.Println(reg, " is ok ")
			}
		}
	}

}
