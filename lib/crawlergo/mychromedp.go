package crawlergo

import (
	"context"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
	"io/ioutil"
	"log"
	"os"
	"time"
)

type MyChromedp struct {
	TmpDir   string
	Ctx      *context.Context
	cancel   context.CancelFunc
	allocCtx context.Context
}

// 获取实例
func GetChromedpInstace(ctx *context.Context) *MyChromedp {
	x1 := &MyChromedp{Ctx: ctx}
	x1.fnInit()

	return x1
}
func (r *MyChromedp) Close() {
	os.RemoveAll(r.TmpDir)
	r.cancel()
}

func (r *MyChromedp) DisableImageLoad(ctx context.Context) func(event interface{}) {
	return func(event interface{}) {
		switch ev := event.(type) {
		case *fetch.EventRequestPaused:
			go func() {
				c := chromedp.FromContext(ctx)
				ctx := cdp.WithExecutor(ctx, c.Target)

				if ev.ResourceType == network.ResourceTypeImage || ev.ResourceType == network.ResourceTypeStylesheet {
					fetch.FailRequest(ev.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
				} else {
					fetch.ContinueRequest(ev.RequestID).Do(ctx)
				}
			}()
		}
	}
}

// 获取值
//  输入框最后追加值
//  发送键盘
//  download: https://github.com/chromedp/examples/blob/2f7adc7ded326214db81cc6c13d48ecd31af8d31/download_file/main.go
func (r *MyChromedp) sendkeys(host string, val1, val2, val3, val4 *string) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(host),
		chromedp.Click(`//get-repo//summary`, chromedp.NodeReady),
		chromedp.WaitVisible(`#input1`, chromedp.ByID),
		chromedp.WaitVisible(`#textarea1`, chromedp.ByID),
		chromedp.SendKeys(`#textarea1`, kb.End+"\b\b\n\naoeu\n\ntest1\n\nblah2\n\n\t\t\t\b\bother box!\t\ntest4", chromedp.ByID),
		chromedp.Value(`#input1`, val1, chromedp.ByID),
		chromedp.Value(`#textarea1`, val2, chromedp.ByID),
		chromedp.SetValue(`#input2`, "test3", chromedp.ByID),
		chromedp.Value(`#input2`, val3, chromedp.ByID),
		chromedp.SendKeys(`#select1`, kb.ArrowDown+kb.ArrowDown, chromedp.ByID),
		chromedp.Value(`#select1`, val4, chromedp.ByID),
	}
}

// 初始化，内部运行
func (r *MyChromedp) fnInit() {
	dir, err := ioutil.TempDir("", "PowerBy-51pwn")
	if err != nil {
		panic(err)
	}
	r.TmpDir = dir

	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.NoSandbox,
		//chromedp.Headless,
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("user-data-dir", dir),
		chromedp.Flag("blink-settings", true),
		chromedp.Flag("enable-quic", "imagesEnabled=false"),
		chromedp.Flag("quic-version", "h3-23"),
		chromedp.DisableGPU,
		chromedp.UserDataDir(dir),
	}

	r.allocCtx, r.cancel = chromedp.NewExecAllocator(*r.Ctx, opts...)
}

// setheaders returns a task list that sets the passed headers.
func (r *MyChromedp) Setheaders(headers *map[string]interface{}) *[]chromedp.Action {
	a := []chromedp.Action{network.Enable()}

	if nil != headers {
		a = append(a, network.SetExtraHTTPHeaders(network.Headers(*headers)))
	}
	//a = append(a, chromedp.Navigate(host))
	return &a
	//chromedp.Text(`#result`, res, chromedp.ByID, chromedp.NodeVisible),
}

func (r *MyChromedp) DoUrl(szUrl string, head *map[string]interface{}, timeout *time.Duration, fnSend func() *chromedp.Tasks) error {
	err, _ := r.DoUrlWithFlg(szUrl, head, timeout, true, fnSend)
	return err
}

// 启动一个tab运行url
func (r *MyChromedp) DoUrlWithFlg(szUrl string, head *map[string]interface{}, timeout *time.Duration, bAutoClose bool, fnSend func() *chromedp.Tasks) (err error, cancel context.CancelFunc) {
	if nil == timeout {
		n9 := 15 * time.Second
		timeout = &n9
	}
	ctx := r.allocCtx
	if bAutoClose {
		ctx, cancel = context.WithTimeout(r.allocCtx, *timeout)
		defer cancel()
	}
	taskCtx, cancel := chromedp.NewContext(ctx)
	if bAutoClose {
		defer cancel()
	}

	chromedp.ListenTarget(taskCtx, r.DisableImageLoad(taskCtx))

	var title string
	//var b1, b2 []byte
	// chromedp.Emulate(device.IPadMini), fetch.Enable()
	a := []chromedp.Action{chromedp.Navigate(szUrl)}
	if nil != fnSend {
		a = append(a, *fnSend()...)
	}
	a = append(a, *r.Setheaders(head)...)
	a = append(a,
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Title(&title),
		//chromedp.Evaluate(`Object.keys(window);`, &res),
		//chromedp.CaptureScreenshot(&b1),
		//chromedp.Emulate(device.Reset),
	)
	if err := chromedp.Run(taskCtx, a...); err != nil {
		log.Println("chromedp.Run: ", err)
		return err, cancel
	}

	//if err := ioutil.WriteFile("screenshot1.png", b1, 0o644); err != nil {
	//	log.Fatal(err)
	//}
	//log.Println(title)
	//c1 := chromedp.FromContext(taskCtx)
	return nil, cancel
}
