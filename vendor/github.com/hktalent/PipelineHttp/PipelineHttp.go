package PipelineHttp

import (
	"bytes"
	"context"
	"crypto/tls"
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

type PipelineHttp struct {
	Timeout               time.Duration
	KeepAlive             time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	Client                *http.Client
	Ctx                   context.Context
	StopAll               context.CancelFunc
	IsClosed              bool
	ErrLimit              int // 错误次数统计，失败就停止
	ErrCount              int // 错误次数统计，失败就停止
	SetHeader             func() map[string]string
	Buf                   *bytes.Buffer // http2 client framer message
	UseHttp2              bool
	TestHttp              bool
}

func NewPipelineHttp() *PipelineHttp {
	x1 := &PipelineHttp{
		UseHttp2:              false,
		TestHttp:              false,
		Buf:                   &bytes.Buffer{},
		Timeout:               30 * time.Second, // 拨号、连接
		KeepAlive:             10 * time.Second, // 默认值（当前为 15 秒）发送保持活动探测。
		MaxIdleConns:          0,                // MaxIdleConns controls the maximum number of idle (keep-alive) connections across all hosts. Zero means no limit.
		IdleConnTimeout:       0,                // 不限制
		TLSHandshakeTimeout:   20 * time.Second, // TLSHandshakeTimeout specifies the maximum amount of time waiting to wait for a TLS handshake. Zero means no timeout.
		ExpectContinueTimeout: 0,                // 零表示没有超时，并导致正文立即发送，无需等待服务器批准
		MaxIdleConnsPerHost:   3000,             // MaxIdleConnsPerHost, if non-zero, controls the maximum idle (keep-alive) connections to keep per-host. If zero, DefaultMaxIdleConnsPerHost is used.
		ErrLimit:              10,               // 相同目标，累计错误10次就退出
		ErrCount:              0,
		IsClosed:              false,
		SetHeader:             nil,
	}
	if x1.UseHttp2 {
		x1.Client = x1.GetClient4Http2()
	} else {
		x1.Client = x1.GetClient(nil)
	}
	x1.SetCtx(context.Background())
	//http.DefaultTransport.(*http.Transport).MaxIdleConns = x1.MaxIdleConns
	//http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = x1.MaxIdleConnsPerHost
	return x1
}

/*
	if err != nil {
	    return nil, err
	}

	sa := &syscall.SockaddrInet4{
	    Port: tcpAddr.Port,
	    Addr: [4]byte{tcpAddr.IP[0], tcpAddr.IP[1], tcpAddr.IP[2], tcpAddr.IP[3]},
	}

fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)

	if err != nil {
	    return nil, err
	}

err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 128)

	if err != nil {
	    return nil, err
	}

err = syscall.Connect(fd, sa)

	if err != nil {
	    return nil, err
	}

file := os.NewFile(uintptr(fd), "")
conn, err := net.FileConn(file)

	if err != nil {
	    return nil, err
	}

return conn, nil
*/
func (r *PipelineHttp) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{
		Timeout:   r.Timeout,
		KeepAlive: r.KeepAlive,
		//Control:   r.Control,
		//DualStack: true,
	}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	//tcpConn, ok := conn.(*net.TCPConn)
	//if !ok {
	//	err = errors.New("conn is not tcp")
	//	return nil, err
	//}
	//
	//f, err := tcpConn.File()
	//if err != nil {
	//	return nil, err
	//}
	//internet.ApplyInboundSocketOptions("tcp", f.Fd())

	return conn, nil
}
func (r *PipelineHttp) SetCtx(ctx context.Context) {
	r.Ctx, r.StopAll = context.WithCancel(ctx)
}

// https://github.com/golang/go/issues/23427
func (r *PipelineHttp) GetTransport() http.RoundTripper {
	var tr http.RoundTripper = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           r.Dial,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		DisableKeepAlives:     false,
		MaxIdleConns:          r.MaxIdleConns,
		IdleConnTimeout:       r.IdleConnTimeout,
		TLSHandshakeTimeout:   r.TLSHandshakeTimeout,
		ExpectContinueTimeout: r.ExpectContinueTimeout,
		MaxIdleConnsPerHost:   r.MaxIdleConnsPerHost,
	}
	return tr
}

func (r *PipelineHttp) GetClient(tr http.RoundTripper) *http.Client {
	if nil == tr {
		tr = r.GetTransport()
	}
	c := &http.Client{
		Transport: tr,
		//Timeout:   0, // 超时为零表示没有超时
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
		if !r.UseHttp2 && !r.TestHttp {
			req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
			req.Header.Set("Upgrade", "h2c")
			req.Header.Set("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA")
		} else {
			req.Header.Set("Connection", "keep-alive")
		}
		req.Close = true // 避免 Read返回EOF error
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
		n1 = 10
	}
	ctx, cc := context.WithTimeout(r.Ctx, n1*r.Timeout)
	defer cc()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if bCloseBody && resp != nil {
		defer resp.Body.Close() // resp 可能为 nil，不能读取 Body
	}
	if nil != err {
		r.ErrCount++
	}
	if r.ErrCount >= r.ErrLimit {
		log.Printf("PipelineHttp %d >= %d not close\n", r.ErrCount, r.ErrLimit)
		r.Close()
	}
	if nil != err && rNohost.MatchString(err.Error()) {
		log.Println(err)
		r.Close()
		return
	}
	if !r.UseHttp2 && nil != resp && resp.StatusCode == http.StatusSwitchingProtocols {
		if resp != nil {
			resp.Body.Close() // resp 可能为 nil，不能读取 Body
		}
		r.UseHttp2 = true
		r.Client = r.GetRawClient4Http2()
		r.DoGetWithClient4SetHd(r.Client, szUrl, method, postBody, fnCbk, setHd, bCloseBody)
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
		szUrl09 := "https://" + oU7.Host + oU7.Path
		r.DoGetWithClient(c1, szUrl09, "GET", nil, func(resp *http.Response, err error, szU string) {
			if nil != resp && (resp.Proto == "HTTP/2.0" || resp.StatusCode == http.StatusSwitchingProtocols) {
				if nil != r.Client {
					r.Client.CloseIdleConnections()
				}
				r.Client = c1
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
