package go_utils

import "net/http"

// fuzz 响应对象封装
type Response struct {
	Status        string
	StatusCode    int
	Body          string
	Header        *http.Header // 不用负责对象，引用，节约内存开销
	ContentLength int
	RequestUrl    string
	Location      string
}

// fuzz请求返回的结果
// 尽可能使用指针，节约内存开销
type Page struct {
	IsBackUpPath bool         // 备份、敏感泄露文件检测请求url
	IsBackUpPage bool         // 发现备份、敏感泄露文件
	Title        *string      // 标题
	LocationUrl  *string      // 跳转页面
	Is302        bool         // 是302页面
	Is403        bool         // 403页面
	Url          *string      // 作为本地永久缓存key，提高执行效率
	BodyStr      *string      // body = trim() + ToLower
	BodyLen      int          // body 长度
	Header       *http.Header // 基于指针，节约内存空间
	StatusCode   int          // 状态码
	Resqonse     *Response    // 基于指针，节约内存空间
}
