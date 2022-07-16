package pkg

import "regexp"

// 多次使用，一次性编译效率更高
var DeleteMe = regexp.MustCompile("rememberMe=deleteMe")

// 检查 cookie
// Shiro CVE_2016_4437 cookie
// 其他POC cookie同一检查入口
func CheckShiroCookie(req *Response) int {
	var SetCookieAll string
	if nil != req {
		//if hd, ok := header["Set-Cookie"]; ok {
		for i := range (*req.Header)["Set-Cookie"] {
			SetCookieAll += (*req.Header)["Set-Cookie"][i]
		}
		return len(DeleteMe.FindAllStringIndex(SetCookieAll, -1))
	}
	return 0
}

// 关闭chan
func CloseChan(c chan struct{}) {
	if _, ok := <-c; ok {
		close(c)
	}
}
