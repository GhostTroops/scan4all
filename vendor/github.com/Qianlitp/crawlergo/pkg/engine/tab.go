package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/js"
	"github.com/Qianlitp/crawlergo/pkg/logger"
	model2 "github.com/Qianlitp/crawlergo/pkg/model"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/gogf/gf/encoding/gcharset"
)

type Tab struct {
	Ctx              *context.Context
	Cancel           context.CancelFunc
	NavigateReq      model2.Request
	ExtraHeaders     map[string]interface{}
	ResultList       []*model2.Request
	TopFrameId       string
	LoaderID         string
	NavNetworkID     string
	PageCharset      string
	PageBindings     map[string]interface{}
	FoundRedirection bool
	DocBodyNodeId    cdp.NodeID
	config           TabConfig

	lock sync.Mutex

	WG            sync.WaitGroup //当前Tab页的等待同步计数
	collectLinkWG sync.WaitGroup
	loadedWG      sync.WaitGroup //Loaded之后的等待计数
	formSubmitWG  sync.WaitGroup //表单提交完毕的等待计数
	removeLis     sync.WaitGroup //移除事件监听
	domWG         sync.WaitGroup //DOMContentLoaded 的等待计数
	fillFormWG    sync.WaitGroup //填充表单任务
}

type TabConfig struct {
	TabRunTimeout           time.Duration
	DomContentLoadedTimeout time.Duration
	EventTriggerMode        string        // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration // 事件触发的间隔 单位毫秒
	BeforeExitDelay         time.Duration // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool
	IgnoreKeywords          []string //
	Proxy                   string
	CustomFormValues        map[string]string
	CustomFormKeywordValues map[string]string
}

type bindingCallPayload struct {
	Name string   `json:"name"`
	Seq  int      `json:"seq"`
	Args []string `json:"args"`
}

func NewTab(browser *Browser, navigateReq model2.Request, config TabConfig) *Tab {
	var tab Tab
	tab.ExtraHeaders = map[string]interface{}{}
	var DOMContentLoadedRun = false
	tab.Ctx, tab.Cancel = browser.NewTab(config.TabRunTimeout)
	for key, value := range browser.ExtraHeaders {
		navigateReq.Headers[key] = value
		if key != "Host" {
			tab.ExtraHeaders[key] = value
		}
	}
	tab.NavigateReq = navigateReq
	tab.config = config
	tab.DocBodyNodeId = 0

	// 设置请求拦截监听
	chromedp.ListenTarget(*tab.Ctx, func(v interface{}) {
		switch v := v.(type) {
		// 根据不同的事件 选择执行对应的动作
		case *network.EventRequestWillBeSent:
			if string(v.RequestID) == string(v.LoaderID) && v.Type == "Document" && tab.TopFrameId == "" {
				tab.LoaderID = string(v.LoaderID)
				tab.TopFrameId = string(v.FrameID)
			}

		// 请求发出时暂停 即 请求拦截
		case *fetch.EventRequestPaused:
			tab.WG.Add(1)
			go tab.InterceptRequest(v)

		// 解析所有JS文件中的URL并添加到结果中
		// 解析HTML文档中的URL
		// 查找当前页面的编码
		case *network.EventResponseReceived:
			if v.Response.MimeType == "application/javascript" || v.Response.MimeType == "text/html" || v.Response.MimeType == "application/json" {
				tab.WG.Add(1)
				go tab.ParseResponseURL(v)
			}
			if v.RequestID.String() == tab.NavNetworkID {
				tab.WG.Add(1)
				go tab.GetContentCharset(v)
			}
		// 处理后端重定向 3XX
		case *network.EventResponseReceivedExtraInfo:
			if v.RequestID.String() == tab.NavNetworkID {
				tab.WG.Add(1)
				go tab.HandleRedirectionResp(v)
			}
		//case *network.EventLoadingFailed:
		//	logger.Logger.Error("EventLoadingFailed ", v.ErrorText)
		// 401 407 要求认证 此时会阻塞当前页面 需要处理解决
		case *fetch.EventAuthRequired:
			tab.WG.Add(1)
			go tab.HandleAuthRequired(v)

		// DOMContentLoaded
		// 开始执行表单填充 和 执行DOM节点观察函数
		// 只执行一次
		case *page.EventDomContentEventFired:
			if DOMContentLoadedRun {
				return
			}
			DOMContentLoadedRun = true
			tab.WG.Add(1)
			go tab.AfterDOMRun()
		// Loaded
		case *page.EventLoadEventFired:
			if DOMContentLoadedRun {
				return
			}
			DOMContentLoadedRun = true
			tab.WG.Add(1)
			go tab.AfterDOMRun()

		// close Dialog
		case *page.EventJavascriptDialogOpening:
			tab.WG.Add(1)
			go tab.dismissDialog()

		// handle expose function
		case *runtime.EventBindingCalled:
			tab.WG.Add(1)
			go tab.HandleBindingCalled(v)
		}
	})

	return &tab
}

func (tab *Tab) Start() {
	logger.Logger.Info("Crawling " + tab.NavigateReq.Method + " " + tab.NavigateReq.URL.String())
	defer tab.Cancel()
	if err := chromedp.Run(*tab.Ctx,
		RunWithTimeOut(tab.Ctx, tab.config.DomContentLoadedTimeout, chromedp.Tasks{
			//
			runtime.Enable(),
			// 开启网络层API
			network.Enable(),
			// 开启请求拦截API
			fetch.Enable().WithHandleAuthRequests(true),
			// 添加回调函数绑定
			// XSS-Scan 使用的回调
			runtime.AddBinding("addLink"),
			runtime.AddBinding("Test"),
			// 初始化执行JS
			chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				_, err = page.AddScriptToEvaluateOnNewDocument(js.TabInitJS).Do(ctx)
				if err != nil {
					return err
				}
				return nil
			}),
			network.SetExtraHTTPHeaders(tab.ExtraHeaders),
			// 执行导航
			chromedp.Navigate(tab.NavigateReq.URL.String()),
		}),
	); err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Logger.Debug("Crawling Canceled")
			return
		}
		logger.Logger.Warn("navigate timeout ", tab.NavigateReq.URL.String())
	}

	waitDone := func() <-chan struct{} {
		tab.WG.Wait()
		ch := make(chan struct{})
		defer close(ch)
		return ch
	}

	select {
	case <-waitDone():
		logger.Logger.Debug("all navigation tasks done.")
	case <-time.After(tab.config.DomContentLoadedTimeout + time.Second*10):
		logger.Logger.Warn("navigation tasks TIMEOUT.")
	}

	// 等待收集所有链接
	logger.Logger.Debug("collectLinks start.")
	tab.collectLinkWG.Add(3)
	go tab.collectLinks()
	tab.collectLinkWG.Wait()
	logger.Logger.Debug("collectLinks end.")

	// 识别页面编码 并编码所有URL
	if tab.config.EncodeURLWithCharset {
		tab.DetectCharset()
		tab.EncodeAllURLWithCharset()
	}

	//fmt.Println(tab.NavigateReq.URL.String(), len(tab.ResultList))
	//for _, v := range tab.ResultList {
	//	v.SimplePrint()
	//}
	// fmt.Println("Finished " + tab.NavigateReq.Method + " " + tab.NavigateReq.URL.String())
}

func RunWithTimeOut(ctx *context.Context, timeout time.Duration, tasks chromedp.Tasks) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		timeoutContext, _ := context.WithTimeout(ctx, timeout)
		//defer cancel()
		return tasks.Do(timeoutContext)
	}
}

/**
添加收集到的URL到结果列表，需要处理Host绑定
*/
func (tab *Tab) AddResultUrl(method string, _url string, source string) {
	navUrl := tab.NavigateReq.URL
	url, err := model2.GetUrl(_url, *navUrl)
	if err != nil {
		return
	}
	option := model2.Options{
		Headers:  map[string]interface{}{},
		PostData: "",
	}
	referer := navUrl.String()

	// 处理Host绑定
	if host, ok := tab.NavigateReq.Headers["Host"]; ok {
		if host != navUrl.Hostname() && url.Hostname() == host {
			url, _ = model2.GetUrl(strings.Replace(url.String(), "://"+url.Hostname(), "://"+navUrl.Hostname(), -1), *navUrl)
			option.Headers["Host"] = host
			referer = strings.Replace(navUrl.String(), navUrl.Host, host.(string), -1)
		}
	}
	// 添加Cookie
	if cookie, ok := tab.NavigateReq.Headers["Cookie"]; ok {
		option.Headers["Cookie"] = cookie
	}

	// 修正Referer
	option.Headers["Referer"] = referer
	for key, value := range tab.ExtraHeaders {
		option.Headers[key] = value
	}
	req := model2.GetRequest(method, url, option)
	req.Source = source

	tab.lock.Lock()
	tab.ResultList = append(tab.ResultList, &req)
	tab.lock.Unlock()
}

/**
添加请求到结果列表，拦截请求时处理了Host绑定，此处无需处理
*/
func (tab *Tab) AddResultRequest(req model2.Request) {
	for key, value := range tab.ExtraHeaders {
		req.Headers[key] = value
	}
	tab.lock.Lock()
	tab.ResultList = append(tab.ResultList, &req)
	tab.lock.Unlock()
}

/**
获取当前标签页CDP的执行上下文
*/
func (tab *Tab) GetExecutor() context.Context {
	c := chromedp.FromContext(*tab.Ctx)
	ctx := cdp.WithExecutor(*tab.Ctx, c.Target)
	return ctx
}

/**
关闭弹窗
*/
func (tab *Tab) dismissDialog() {
	defer tab.WG.Done()
	ctx := tab.GetExecutor()
	_ = page.HandleJavaScriptDialog(false).Do(ctx)
}

/**
处理回调
*/
func (tab *Tab) HandleBindingCalled(event *runtime.EventBindingCalled) {
	defer tab.WG.Done()
	payload := []byte(event.Payload)
	var bcPayload bindingCallPayload
	_ = json.Unmarshal(payload, &bcPayload)
	if bcPayload.Name == "addLink" && len(bcPayload.Args) > 1 {
		tab.AddResultUrl(config.GET, bcPayload.Args[0], bcPayload.Args[1])
	}
	if bcPayload.Name == "Test" {
		fmt.Println(bcPayload.Args)
	}
	tab.Evaluate(fmt.Sprintf(js.DeliverResultJS, bcPayload.Name, bcPayload.Seq, "s"))
}

/**
执行JS
*/
func (tab *Tab) Evaluate(expression string) {
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	_, exception, err := runtime.Evaluate(expression).Do(tCtx)
	if exception != nil {
		logger.Logger.Debug("tab Evaluate: ", exception.Text)
	}
	if err != nil {
		logger.Logger.Debug("tab Evaluate: ", err)
	}
}

/**
立即根据条件获取Nodes的ID，不等待
*/
func (tab *Tab) GetNodeIDs(sel string) ([]cdp.NodeID, error) {
	ctx := tab.GetExecutor()
	return dom.QuerySelectorAll(tab.DocBodyNodeId, sel).Do(ctx)
}

/**
根据给的Node执行JS
*/
func (tab *Tab) EvaluateWithNode(expression string, node *cdp.Node) error {
	ctx := tab.GetExecutor()
	var res bool
	err := chromedp.EvaluateAsDevTools(js.Snippet(expression, js.CashX(true), "", node), &res).Do(ctx)
	if err != nil {
		return err
	}
	return nil
}

/**
识别页面的编码
*/
func (tab *Tab) DetectCharset() {
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Millisecond*500)
	defer cancel()
	var content string
	var ok bool
	var getCharsetRegex = regexp.MustCompile("charset=(.+)$")
	err := chromedp.AttributeValue(`meta[http-equiv=Content-Type]`, "content", &content, &ok, chromedp.ByQuery).Do(tCtx)
	if err != nil || !ok {
		return
	}
	if strings.Contains(content, "charset=") {
		charset := getCharsetRegex.FindString(content)
		if charset != "" {
			tab.PageCharset = strings.ToUpper(strings.Replace(charset, "charset=", "", -1))
			tab.PageCharset = strings.TrimSpace(tab.PageCharset)
		}
	}
}

func (tab *Tab) EncodeAllURLWithCharset() {
	if tab.PageCharset == "" || tab.PageCharset == "UTF-8" {
		return
	}
	for _, req := range tab.ResultList {
		newRawQuery, err := gcharset.UTF8To(tab.PageCharset, req.URL.RawQuery)
		if err == nil {
			req.URL.RawQuery = newRawQuery
		}
		newRawPath, err := gcharset.UTF8To(tab.PageCharset, req.URL.RawPath)
		if err == nil {
			req.URL.RawPath = newRawPath
		}
	}
}

func IsIgnoredByKeywordMatch(req model2.Request, IgnoreKeywords []string) bool {
	for _, _str := range IgnoreKeywords {
		if strings.Contains(req.URL.String(), _str) {
			logger.Logger.Info("ignore request: ", req.SimpleFormat())
			return true
		}
	}
	return false
}
