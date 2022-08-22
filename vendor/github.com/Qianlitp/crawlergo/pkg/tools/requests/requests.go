package requests

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Qianlitp/crawlergo/pkg/logger"
	"github.com/pkg/errors"
)

const DefaultUa = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)" +
	" Chrome/76.0.3809.132 Safari/537.36 C845D9D38B3A68F4F74057DB542AD252 tx/2.0"

const defaultTimeout int = 15

// 最大获取100K的响应，适用于绝大部分场景
const defaultResponseLength = 10240
const defaultRetry = 0

var ContentTypes = map[string]string{
	"json":      "application/json",
	"xml":       "application/xml",
	"soap":      "application/soap+xml",
	"multipart": "multipart/form-data",
	"form":      "application/x-www-form-urlencoded; charset=utf-8",
}

// ReqInfo 是一个HTTP请求元素的封装，可以快速进行简单的http请求
type ReqInfo struct {
	Verb    string
	Url     string
	Headers map[string]string
	Body    []byte
}

type ReqOptions struct {
	Timeout       int    // in seconds
	Retry         int    // 0为默认值，-1 代表关闭不retry
	VerifySSL     bool   // default false
	AllowRedirect bool   // default false
	Proxy         string // proxy settings, support http/https proxy only, e.g. http://127.0.0.1:8080
}

type session struct {
	ReqOptions
	client *http.Client
}

// getSessionByOptions 根据配置获取一个session
func getSessionByOptions(options *ReqOptions) *session {
	if options == nil {
		options = &ReqOptions{}
	}
	// 设置client的超时与ssl验证
	timeout := time.Duration(options.Timeout) * time.Second
	if options.Timeout == 0 {
		timeout = time.Duration(defaultTimeout) * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !options.VerifySSL},
	}
	if options.Proxy != "" {
		proxyUrl, err := url.Parse(options.Proxy)
		if err == nil {
			tr.Proxy = http.ProxyURL(proxyUrl)
		}
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr}
	// 设置是否跟踪跳转
	if !options.AllowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	// options内容同步到session中
	return &session{
		ReqOptions: ReqOptions{
			options.Timeout,
			options.Retry,
			options.VerifySSL,
			options.AllowRedirect,
			options.Proxy,
		},
		client: client,
	}
}

// Get GET请求
func Get(url string, headers map[string]string, options *ReqOptions) (*Response, error) {
	sess := getSessionByOptions(options)
	return sess.doRequest("GET", url, headers, nil)
}

// Request 自定义请求类型
func Request(verb string, url string, headers map[string]string, body []byte, options *ReqOptions) (*Response, error) {
	sess := getSessionByOptions(options)
	return sess.doRequest(verb, url, headers, body)
}

// session functions

// Get Session的GET请求
func (sess *session) Get(url string, headers map[string]string) (*Response, error) {
	return sess.doRequest("GET", url, headers, nil)
}

// Post Session的POST请求
func (sess *session) Post(url string, headers map[string]string, body []byte) (*Response, error) {
	return sess.doRequest("POST", url, headers, body)
}

// Request Session的自定义请求类型
func (sess *session) Request(verb string, url string, headers map[string]string, body []byte) (*Response, error) {
	return sess.doRequest(verb, url, headers, body)
}

// Request reqInfo的快速调用
func (r *ReqInfo) Request() (*Response, error) {
	return Request(r.Verb, r.Url, r.Headers, r.Body, nil)
}

func (r *ReqInfo) RequestWithOptions(options *ReqOptions) (*Response, error) {
	return Request(r.Verb, r.Url, r.Headers, r.Body, options)
}

func (r *ReqInfo) Clone() *ReqInfo {
	return &ReqInfo{
		Verb:    r.Verb,
		Url:     r.Url,
		Headers: r.Headers,
		Body:    r.Body,
	}
}

func (r *ReqInfo) SetHeader(name, value string) {
	if r.Headers == nil {
		r.Headers = make(map[string]string)
	}
	r.Headers[name] = value
}

// doRequest 实际请求的函数
func (sess *session) doRequest(verb string, url string, headers map[string]string, body []byte) (*Response, error) {
	logger.Logger.Debug("do request to ", url)
	verb = strings.ToUpper(verb)
	bodyReader := bytes.NewReader(body)
	req, err := http.NewRequest(verb, url, bodyReader)
	if err != nil {
		// 多数情况下是url中包含%
		url = escapePercentSign(url)
		req, err = http.NewRequest(verb, url, bodyReader)
	}
	if err != nil {
		return nil, errors.Wrap(err, "build request error")
	}

	// 设置headers头
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	// 设置默认的headers头
	defaultHeaders := map[string]string{
		"User-Agent": DefaultUa,
		"Range":      fmt.Sprintf("bytes=0-%d", defaultResponseLength),
		"Connection": "close",
	}
	for key, value := range defaultHeaders {
		if _, ok := headers[key]; !ok {
			req.Header.Set(key, value)
		}
	}
	// 设置Host头
	if host, ok := headers["Host"]; ok {
		req.Host = host
	}
	// 设置默认的Content-Type头
	if verb == "POST" && headers["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		// 应该手动设置Referer、Origin、和X-Requested-With字段
	}
	// 覆盖Connection头
	req.Header.Set("Connection", "close")

	// 设置重试次数
	retry := sess.Retry
	if retry == 0 {
		retry = defaultRetry
	} else if retry == -1 {
		retry = 0
	}

	// 请求
	var resp *http.Response
	for i := 0; i <= retry; i++ {
		resp, err = sess.client.Do(req)
		if err != nil {
			// sleep 0.1s
			time.Sleep(100 * time.Microsecond)
			continue
		} else {
			break
		}
	}

	if err != nil {
		return nil, errors.Wrap(err, "error occurred during request")
	}
	// 带Range头后一般webserver响应都是206 PARTIAL CONTENT，修正为200 OK
	if resp.StatusCode == 206 {
		resp.StatusCode = 200
		resp.Status = "200 OK"
	}

	return NewResponse(resp), nil
}
