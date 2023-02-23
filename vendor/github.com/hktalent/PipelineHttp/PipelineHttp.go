package PipelineHttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

/*
MaxConnsPerHost 控制单个Host的最大连接总数,该值默认是0，也就是不限制，连接池里的连接能用就用，不能用创建新连接
MaxIdleConnsPerHost：优先设置这个，决定了对于单个Host需要维持的连接池大小。该值的合理确定，应该根据性能测试的结果调整。
MaxIdleConns：客户端连接单个Host，不少于MaxIdleConnsPerHost大小，不然影响MaxIdleConnsPerHost控制的连接池；客户端连接 n 个Host，少于 n X MaxIdleConnsPerHost 会影响MaxIdleConnsPerHost控制的连接池（导致连接重建）。嫌麻烦，建议设置为0，不限制。
MaxConnsPerHost：对于单个Host允许的最大连接数，包含IdleConns，所以一般大于等于MaxIdleConnsPerHost。设置为等于MaxIdleConnsPerHost，也就是尽可能复用连接池中的连接。另外设置过小，可能会导致并发下降，超过这个值会 block 请求，直到有空闲连接。（所以默认值是不限制的）
*/
type PipelineHttp struct {
	Timeout               time.Duration            `json:"timeout"`
	KeepAlive             time.Duration            `json:"keep_alive"`
	MaxIdleConns          int                      `json:"max_idle_conns"`
	MaxIdleConnsPerHost   int                      `json:"max_idle_conns_per_host"`
	MaxConnsPerHost       int                      `json:"max_conns_per_host"`
	IdleConnTimeout       time.Duration            `json:"idle_conn_timeout"`
	TLSHandshakeTimeout   time.Duration            `json:"tls_handshake_timeout"`
	ExpectContinueTimeout time.Duration            `json:"expect_continue_timeout"`
	ResponseHeaderTimeout time.Duration            `json:"response_header_timeout"`
	Client                *http.Client             `json:"client"`
	Ctx                   context.Context          `json:"ctx"`
	StopAll               context.CancelFunc       `json:"stop_all"`
	IsClosed              bool                     `json:"is_closed"`
	ErrLimit              int                      `json:"err_limit"` // 错误次数统计，失败就停止
	ErrCount              int                      `json:"err_count"` // 错误次数统计，失败就停止
	SetHeader             func() map[string]string `json:"set_header"`
	Buf                   *bytes.Buffer            `json:"buf"` // http2 client framer message
	UseHttp2              bool                     `json:"use_http_2"`
	TestHttp              bool                     `json:"test_http"`
	ReTry                 int                      `json:"re_try"` // 连接超时重试
	ver                   int
}

func NewPipelineHttp(args ...map[string]interface{}) *PipelineHttp {
	nTimeout := 60
	nIdle := 500
	x1 := &PipelineHttp{
		ver:                   1,
		UseHttp2:              false,
		TestHttp:              false,
		Buf:                   &bytes.Buffer{},
		Timeout:               time.Duration(nTimeout) * time.Second, // 拨号、连接
		KeepAlive:             time.Duration(nTimeout) * time.Second, // 默认值（当前为 15 秒）发送保持活动探测。
		MaxIdleConns:          nIdle,                                 // MaxIdleConns controls the maximum number of idle (keep-alive) connections across all hosts. Zero means no limit.
		IdleConnTimeout:       180,                                   // 不限制
		ResponseHeaderTimeout: time.Duration(nTimeout) * time.Second, // response
		TLSHandshakeTimeout:   time.Duration(nTimeout) * time.Second, // TLSHandshakeTimeout specifies the maximum amount of time waiting to wait for a TLS handshake. Zero means no timeout.
		ExpectContinueTimeout: 0,                                     // 零表示没有超时，并导致正文立即发送，无需等待服务器批准
		MaxIdleConnsPerHost:   nIdle,                                 // MaxIdleConnsPerHost, if non-zero, controls the maximum idle (keep-alive) connections to keep per-host. If zero, DefaultMaxIdleConnsPerHost is used.
		MaxConnsPerHost:       0,                                     // 控制单个Host的最大连接总数,该值默认是0，也就是不限制，连接池里的连接能用就用，不能用创建新连接
		ErrLimit:              10,                                    // 相同目标，累计错误10次就退出
		ErrCount:              0,
		IsClosed:              false,
		SetHeader:             nil,
		ReTry:                 3,
	}
	if x1.UseHttp2 {
		x1.Client = x1.GetClient4Http2()
	} else {
		x1.Client = x1.GetClient(nil)
	}
	x1.SetCtx(context.Background())
	if nil != args && 0 < len(args) {
		for _, x := range args {
			if data, err := json.Marshal(x); nil == err {
				json.Unmarshal(data, x1)
			}
		}
	}
	//http.DefaultTransport.(*http.Transport).MaxIdleConns = x1.MaxIdleConns
	//http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = x1.MaxIdleConnsPerHost
	return x1
}

// https://cloud.tencent.com/developer/article/1529840
// https://zhuanlan.zhihu.com/p/451642373
func (r *PipelineHttp) Dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	for i := 0; i < r.ReTry; i++ {
		conn, err = (&net.Dialer{
			//Timeout:   r.Timeout, // 不能打开，否则： dial tcp 127.0.0.1:1389: i/o timeout
			KeepAlive: r.KeepAlive,
			//Control:   r.Control,
			DualStack: true,
		}).DialContext(ctx, network, addr)

		if err == nil {
			//conn.SetReadDeadline(time.Now().Add(r.Timeout))// 不能打开，否则： dial tcp 127.0.0.1:5900: i/o timeout
			//one := make([]byte, 0)
			//conn.SetReadDeadline(time.Now())
			//if _, err := conn.Read(one); err != io.EOF {
			break
			//}else{
			//	conn.SetReadDeadline(time.Now().Add(r.Timeout * 10))
			//}
		}
	}
	return conn, err
}
func (r *PipelineHttp) SetCtx(ctx context.Context) {
	r.Ctx, r.StopAll = context.WithCancel(ctx)
}

// https://github.com/golang/go/issues/23427
// https://cloud.tencent.com/developer/article/1529840
// https://romatic.net/post/go_net_errors/
// https://www.jianshu.com/p/2e5a7317be38
func (r *PipelineHttp) GetTransport() http.RoundTripper {
	var tr http.RoundTripper = &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		DialContext:     r.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, Renegotiation: tls.RenegotiateOnceAsClient},
		//ForceAttemptHTTP2:      true,                    // 不能加
		//MaxResponseHeaderBytes: 4096,  //net/http default is 10Mb
		DisableKeepAlives:     false,                   // false 才会复用连接 https://blog.csdn.net/qq_21514303/article/details/87794750
		MaxIdleConns:          r.MaxIdleConns,          // 是长连接在关闭之前，连接池对所有host的最大链接数量
		IdleConnTimeout:       r.IdleConnTimeout,       // 连接最大空闲时间，超过这个时间就会被关闭
		TLSHandshakeTimeout:   r.TLSHandshakeTimeout,   // 限制TLS握手使用的时间
		ExpectContinueTimeout: r.ExpectContinueTimeout, // 限制客户端在发送一个包含：100-continue的http报文头后，等待收到一个go-ahead响应报文所用的时间。在1.6中，此设置对HTTP/2无效。（在1.6.2中提供了一个特定的封装DefaultTransport）
		MaxIdleConnsPerHost:   r.MaxIdleConnsPerHost,   // 连接池对每个host的最大链接数量(MaxIdleConnsPerHost <= MaxIdleConns,如果客户端只需要访问一个host，那么最好将MaxIdleConnsPerHost与MaxIdleConns设置为相同，这样逻辑更加清晰)
		MaxConnsPerHost:       r.MaxConnsPerHost,
		ResponseHeaderTimeout: r.ResponseHeaderTimeout, // 限制读取响应报文头使用的时间
	}
	return tr
}

func (r *PipelineHttp) GetClient(tr http.RoundTripper) *http.Client {
	if nil == tr {
		tr = r.GetTransport()
	}
	//c := &fasthttp.Client{
	//	ReadTimeout:                   readTimeout,
	//	WriteTimeout:                  writeTimeout,
	//	MaxIdleConnDuration:           maxIdleConnDuration,
	//	NoDefaultUserAgentHeader:      true, // Don't send: User-Agent: fasthttp
	//	DisableHeaderNamesNormalizing: true, // If you set the case on your headers correctly you can enable this
	//	DisablePathNormalizing:        true,
	//	// increase DNS cache time to an hour instead of default minute
	//	Dial: (&fasthttp.TCPDialer{
	//		Concurrency:      4096,
	//		DNSCacheDuration: time.Hour,
	//	}).Dial,
	//}
	c := &http.Client{
		Transport: tr,
		//Timeout:   r.Timeout, // 超时为零表示没有超时,  context canceled (Client.Timeout exceeded while awaiting headers)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse /* 不进入重定向 */
		},
	}
	return c
}

func (r *PipelineHttp) DoGet(szUrl string, fnCbk func(resp *http.Response, err error, szU string)) {
	r.DoGetWithClient(nil, szUrl, "GET", nil, fnCbk)
}

func (r *PipelineHttp) DoGetWithClient(client *http.Client, szUrl string, method string, postBody io.Reader, fnCbk func(resp *http.Response, err error, szU string)) {
	r.DoGetWithClient4SetHd(client, szUrl, method, postBody, fnCbk, nil, true)
}

func (r *PipelineHttp) DoGetWithClient4SetHdNoCloseBody(client *http.Client, szUrl string, method string, postBody io.Reader, fnCbk func(resp *http.Response, err error, szU string), setHd func() map[string]string) {
	r.DoGetWithClient4SetHd(client, szUrl, method, postBody, fnCbk, nil, false)
}

func (r *PipelineHttp) CloseResponse(resp *http.Response) {
	if nil != resp {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// application/x-www-form-urlencoded
// multipart/form-data
// text/plain
func (r *PipelineHttp) DoGetWithClient4SetHd(client *http.Client, szUrl string, method string, postBody io.Reader, fnCbk func(resp *http.Response, err error, szU string), setHd func() map[string]string, bCloseBody bool) {
	//r.testHttp2(szUrl)
	if client == nil {
		if nil != r.Client {
			client = r.Client
		} else {
			client = r.GetClient(nil)
		}
	}
	req, err := http.NewRequest(method, szUrl, postBody)
	if nil == err {
		if 1 == r.ver && !r.UseHttp2 && !r.TestHttp && strings.HasPrefix(szUrl, "https://") {
			req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
			req.Header.Set("Upgrade", "h2c")
			req.Header.Set("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")
		} else {
			req.Header.Set("Connection", "keep-alive")
		}
		//req.Close = true // 避免 Read返回EOF error
		var fnShk func() map[string]string
		if nil != setHd {
			fnShk = setHd
		} else {
			fnShk = r.SetHeader
		}
		if nil != fnShk {
			m1 := fnShk()
			for k09, v09 := range m1 {
				req.Header.Set(k09, v09)
			}
		}
	} else {
		log.Println("http.NewRequest is error ", err)
		return
	}
	n1 := client.Timeout
	if 0 == n1 {
		n1 = 50
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36")
	}
	//if 0 < r.Timeout {
	//	ctx, cc := context.WithTimeout(r.Ctx, n1*r.Timeout)
	//	defer cc()
	//	req = req.WithContext(ctx)
	//} else {
	// req = req.WithContext(r.Ctx) // context canceled
	//}

	resp, err := client.Do(req)
	if bCloseBody && resp != nil {
		defer r.CloseResponse(resp) // resp 可能为 nil，不能读取 Body
	}
	if nil != err {
		r.ErrCount++
	}
	if r.ErrCount >= r.ErrLimit {
		log.Printf("PipelineHttp %d >= %d not close\n", r.ErrCount, r.ErrLimit)
		r.Close()
	}
	if nil != err && rNohost.MatchString(err.Error()) {
		log.Println(szUrl, err)
		r.Close()
		return
	}
	if !r.UseHttp2 && nil != resp && 200 != resp.StatusCode {
		r.UseHttp2 = true
		if a1 := resp.Header["Alt-Svc"]; 0 < len(a1) && strings.Contains(a1[0], "h3=\"") || strings.HasPrefix(resp.Proto, "HTTP/3") {
			r.Client = r.GetClient4Http3()
		} else if resp.StatusCode == http.StatusSwitchingProtocols {
			r.Client = r.GetRawClient4Http2()
		}
		oU7, _ := url.Parse(szUrl)
		szUrl09 := "https://" + oU7.Host + oU7.Path
		r.ErrLimit = 99999999
		r.CloseResponse(resp)
		r.DoGetWithClient4SetHd(r.Client, szUrl09, method, postBody, fnCbk, setHd, bCloseBody)
		return
	}
	fnCbk(resp, err, szUrl)
}

var rNohost = regexp.MustCompile(`.*dial tcp: [^:]+: no such host.*`)

func (r *PipelineHttp) Close() {
	r.IsClosed = true
	r.StopAll()
	r.Client = nil
}

func (r *PipelineHttp) DoDirs4Http2(szUrl string, dirs []string, nThread int, fnCbk func(resp *http.Response, err error, szU string)) {
	r.UseHttp2 = true
	r.doDirsPrivate(szUrl, dirs, nThread, fnCbk)
}

func (r *PipelineHttp) DoDirs(szUrl string, dirs []string, nThread int, fnCbk func(resp *http.Response, err error, szU string)) {
	r.doDirsPrivate(szUrl, dirs, nThread, fnCbk)
}

func (r *PipelineHttp) testHttp2(szUrl001 string) {
	if !r.UseHttp2 && !r.TestHttp {
		r.TestHttp = true
		r.UseHttp2 = true
		c1 := r.GetRawClient4Http2()
		oU7, _ := url.Parse(szUrl001)
		if "" == oU7.Path {
			oU7.Path = "/"
		}
		szUrl09 := "https://" + oU7.Host + oU7.Path
		r.DoGetWithClient(c1, szUrl09, "GET", nil, func(resp *http.Response, err error, szU string) {
			if nil != resp {
				if resp.StatusCode == http.StatusSwitchingProtocols {
					r.CloseResponse(resp)
					if nil != r.Client {
						r.Client.CloseIdleConnections()
					}
					if strings.HasPrefix(resp.Proto, "HTTP/2") {
						r.Client = c1
					}
				} else if a1 := resp.Header["Alt-Svc"]; 0 < len(a1) && strings.Contains(a1[0], "h3=\"") {
					r.Client = r.GetClient4Http3()
				}
				r.ErrLimit = 99999999
			} else {
				r.UseHttp2 = false
			}
		})
	}
}

// more see test/main.go
func (r *PipelineHttp) doDirsPrivate(szUrl string, dirs []string, nThread int, fnCbk func(resp *http.Response, err error, szU string)) {
	c02 := make(chan struct{}, nThread)
	defer close(c02)
	oUrl, err := url.Parse(szUrl)
	if nil != err {
		log.Printf("url.Parse is error: %v %s", err, szUrl)
		return
	}
	if "" == oUrl.Scheme {
		oUrl.Scheme = "http"
	}
	szUrl = oUrl.Scheme + "://" + oUrl.Host
	var wg sync.WaitGroup
	var client *http.Client
	r.testHttp2(szUrl)
	if r.UseHttp2 {
		client = r.GetClient4Http2()
	} else {
		client = r.GetClient(nil)
		client = r.Client
	}
	for _, j := range dirs {
		if r.IsClosed {
			return
		}
		select {
		case <-r.Ctx.Done():
			return
		default:
			{
				c02 <- struct{}{}
				wg.Add(1)
				go func(s2 string) {
					defer func() {
						<-c02
						wg.Done()
					}()
					select {
					case <-r.Ctx.Done():
						return
					default:
						{
							s2 = strings.TrimSpace(s2)
							if !strings.HasPrefix(s2, "/") {
								s2 = "/" + s2
							}
							szUrl001 := szUrl + s2
							r.DoGetWithClient(client, szUrl001, "GET", nil, fnCbk)
							//r.DoGet(szUrl001, fnCbk)
							return
						}
					}
				}(j)
				continue
			}
		}
	}
	wg.Wait()
}
