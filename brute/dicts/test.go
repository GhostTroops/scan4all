package main

import (
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"
)

// 追加到文件中
func AppendFile(szOut string) {
	szFile := "xx.txt"
	f, err := os.OpenFile(szFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	if _, err := f.WriteString(szOut + "\n"); err != nil {
		log.Println(err)
	}
}

// 测试 fuzz 字典 的有效性
func main() {
	if data, err := ioutil.ReadFile("brute/dicts/filedic.txt"); nil == err {
		a := strings.Split(string(data), "\n")
		for _, i := range a {
			s1 := "http://127.0.0.1/" + i
			if _, err := url.Parse(s1); nil == err {
				AppendFile(i)
			}
		}
	}
}
