package sender

import (
	"context"
	"fmt"
	"github.com/hktalent/jaeles/utils"
	"log"
	"time"

	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/hktalent/jaeles/libs"
)

// SendWithChrome send request with real browser
func SendWithChrome(options libs.Options, req libs.Request) (libs.Response, error) {
	// parsing some stuff
	url := req.URL
	// @TODO: parse more request component later
	// method := req.Method
	// body := req.Body
	// headers := GetHeaders(req)
	if options.Verbose {
		fmt.Printf("[Sent][Chrome] %v \n", url)
	}
	var res libs.Response

	isHeadless := true
	if options.Debug {
		isHeadless = false
	}
	// prepare the chrome options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", isHeadless),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("enable-automation", true),
		chromedp.Flag("disable-extensions", false),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("single-process", true),
		chromedp.Flag("no-zygote", true),
		chromedp.Flag("no-sandbox", true),
	)

	// proxy chrome headless
	if options.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(options.Proxy))
	}

	allocCtx, bcancel := chromedp.NewExecAllocator(context.Background(), opts...)
	allocCtx, bcancel = context.WithTimeout(allocCtx, time.Duration(options.Timeout*2)*time.Second)
	defer bcancel()
	chromeContext, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	// catch the pop up
	chromedp.ListenTarget(chromeContext, func(event interface{}) {
		if _, ok := event.(*page.EventJavascriptDialogOpening); ok {
			// fmt.Println("closing alert:", ev.Message)
			utils.DebugF("Detecting Pop-up: %v", url)
			res.HasPopUp = true
			go func() {
				if err := chromedp.Run(chromeContext,
					page.HandleJavaScriptDialog(true),
				); err != nil {
					res.HasPopUp = false
				}
			}()
		}
	})
	timeStart := time.Now()
	// waiting time for the page to load
	waiting := time.Duration(1)
	if req.Timeout != 0 {
		waiting = time.Duration(req.Timeout)
	}
	// start Chrome and run given tasks
	err := chromedp.Run(
		chromeContext,
		chromeTask(chromeContext, url,
			// @TODO: add header here
			map[string]interface{}{},
			&res),
		// wait for the page to load
		chromedp.Sleep(waiting*time.Second),
		chromedp.ActionFunc(func(ctx context.Context) error {
			node, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			res.Body, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
			return err
		}),
	)
	res.ResponseTime = time.Since(timeStart).Seconds()
	if err != nil {
		utils.ErrorF("%v", err)
		return res, err
	}

	res.Beautify = fmt.Sprintf("%v\n%v\n", res.StatusCode, res.Body)
	return res, err
}

// chrome debug protocol tasks to run
func chromeTask(chromeContext context.Context, url string, requestHeaders map[string]interface{}, res *libs.Response) chromedp.Tasks {
	// setup a listener for events
	chromedp.ListenTarget(chromeContext, func(event interface{}) {
		// get which type of event it is
		switch msg := event.(type) {
		// just before request sent
		case *network.EventRequestWillBeSent:
			request := msg.Request
			// see if we have been redirected
			// if so, change the URL that we are tracking
			if msg.RedirectResponse != nil {
				url = request.URL
			}

		// once we have the full response
		case *network.EventResponseReceived:
			response := msg.Response
			// is the request we want the status/headers on?
			if response.URL == url {
				res.StatusCode = int(response.Status)
				// fmt.Printf(" url: %s\n", response.URL)
				// fmt.Printf(" status code: %d\n", res.StatusCode)
				for k, v := range response.Headers {
					header := make(map[string]string)
					// fmt.Println(k, v)
					header[k] = v.(string)
					res.Headers = append(res.Headers, header)
				}
			}
		}

	})

	return chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(requestHeaders)),
		chromedp.Navigate(url),
	}
}
