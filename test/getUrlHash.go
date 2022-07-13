package main

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

//func InsertInto(s string, interval int, sep rune) string {
//	var buffer bytes.Buffer
//	before := interval - 1
//	last := len(s) - 1
//	for i, char := range s {
//		buffer.WriteRune(char)
//		if i%interval == before && i != last {
//			buffer.WriteRune(sep)
//		}
//	}
//	buffer.WriteRune(sep)
//	return buffer.String()
//}

//func FaviconHash(data []byte) int32 {
//	stdBase64 := base64.StdEncoding.EncodeToString(data)
//	stdBase64 = InsertInto(stdBase64, 76, '\n')
//	hasher := murmur3.New32WithSeed(0)
//	hasher.Write([]byte(stdBase64))
//	return int32(hasher.Sum32())
//}

//func favicohash(host string) string {
//	timeout := time.Duration(8 * time.Second)
//	var tr *http.Transport
//
//	tr = &http.Transport{
//		MaxIdleConnsPerHost: -1,
//		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
//		DisableKeepAlives:   true,
//	}
//	client := http.Client{
//		Timeout:   timeout,
//		Transport: tr,
//		CheckRedirect: func(req *http.Request, via []*http.Request) error {
//			return http.ErrUseLastResponse /* 不进入重定向 */
//		},
//	}
//	resp, err := client.Get(host)
//	if err != nil {
//		//log.Println("favicon client error:", err)
//		return "0"
//	}
//	defer resp.Body.Close()
//	if resp.StatusCode == 200 {
//		body, err := ioutil.ReadAll(resp.Body)
//		if err != nil {
//			//log.Println("favicon file read error: ", err)
//			return "0"
//		}
//		faviconMMH3 := fmt.Sprintf("%d", FaviconHash(body))
//		return faviconMMH3
//	} else {
//		return "0"
//	}
//}

func favicohashMd5(host string) string {
	timeout := time.Duration(8 * time.Second)
	var tr *http.Transport

	tr = &http.Transport{
		MaxIdleConnsPerHost: -1,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
	}
	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse /* 不进入重定向 */
		},
	}
	resp, err := client.Get(host)
	if err != nil {
		//log.Println("favicon client error:", err)
		return "0"
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			//log.Println("favicon file read error: ", err)
			return "0"
		}
		srcCode := md5.Sum(body)
		faviconMMH3 := strings.ToLower(fmt.Sprintf("%x", srcCode))
		return faviconMMH3
	} else {
		return "0"
	}
}
func main() {
	url := os.Args[1]
	s1 := favicohashMd5(url)
	fmt.Println(s1)

	//var xN uint16 = 534
	//data, err := json.Marshal(&xN)
	//fmt.Printf("%+v", (*[2]byte)(unsafe.Pointer(&xN)))

	//url := os.Args[1]
	//resp, err := http.Get(url)
	//if err != nil {
	//	fmt.Println(fmt.Sprintf("url访问出错：%s", err))
	//	os.Exit(1)
	//}
	//body, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	fmt.Println(fmt.Sprintf("读取body数据出错：%s", err))
	//	os.Exit(1)
	//}
	//// 进行md5加密，因为Sum函数接受的是字节数组，因此需要注意类型转换
	//srcCode := md5.Sum(body)
	//// md5.Sum函数加密后返回的是字节数组，转换成16进制形式，并全小写
	//fmt.Println(strings.ToLower(fmt.Sprintf("%x", srcCode)))
}
