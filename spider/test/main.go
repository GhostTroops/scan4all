package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"log"
	"net/http"
)

const indexHTML = `<!doctype html>
<html>
<body>
  <div id="result">%s</div>
</body>
</html>`

// headerServer is a simple HTTP server that displays the passed headers in the html.
func headerServer(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		buf, err := json.MarshalIndent(req.Header, "", "  ")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(res, indexHTML, string(buf))
	})
	return http.ListenAndServe(addr, mux)
}

// chromedp.Text(`#result`, res, chromedp.ByID, chromedp.NodeVisible),
// setheaders returns a task list that sets the passed headers.
func setheaders(host string, headers map[string]interface{}, res *string) chromedp.Tasks {
	return chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(headers)),
		chromedp.Navigate(host),
		chromedp.ActionFunc(func(ctx context.Context) error {
			aHrefs, exp, err := runtime.Evaluate(`(function(){var a=[];$("div.companyList2 a").each(function(){a.push(this.href)});return a})()`).Do(ctx)
			if err != nil {
				return err
			}
			if exp != nil {
				return exp
			}
			log.Printf("%+v", aHrefs)
			return nil
		}),
	}
}

/*
chromedp.Text(`.Documentation-overview`, &res, chromedp.NodeVisible),
--blink-settings=imagesEnabled=false

How to disable images and CSS in Puppeteer to speed up web scraping
https://www.scrapehero.com/how-to-increase-web-scraping-speed-using-puppeteer/

*/
func main() {
	var szUrl = "https://www.butian.net/Reward/plan/2"

	// 参数设置
	options := []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", false),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-extensions", true),
		chromedp.UserAgent(`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15`),
	}
	options = append(chromedp.DefaultExecAllocatorOptions[:], options...)
	ctx, cancel := chromedp.NewExecAllocator(context.Background(), options...)
	defer cancel()

	// run task list
	var res []string
	var res1, body *string
	//
	err := chromedp.Run(ctx,
		// $("div.companyList2 a").attr("href")
		//chromedp.Evaluate(`Object.keys(window);`, &res),
		//chromedp.Navigate(szUrl),
		setheaders(
			szUrl,
			map[string]interface{}{
				"Cookie":  "__btc__=62afaa6b125f5d4fc36222503604bb13d46498a5; __btu__=3fa4ad1bf25a68db2b6a69db3547107bd69341ce; __btuc__=da130fcb560ecddcb42215ade762d77762644ac5; notice=0; PHPSESSID=oarurhc25ood8nosd1dv1j4953",
				"Referer": "https://www.butian.net/Reward/plan/2",
			},
			res1,
		), // chromedp.OuterHTML("html", body)
	)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println(body, res1)

	log.Printf("window object keys: %v", res)
}
