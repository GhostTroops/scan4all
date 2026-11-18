package spider

import (
	"context"
	"fmt"
	"github.com/chromedp/cdproto/storage"
	"log"
	"os"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// https://github.com/chromedp/examples
func Test_Name(t *testing.T) {
	// 需要本机 Chrome 与公网访问，默认跳过
	if "" == os.Getenv("SCAN4ALL_TEST_CHROME") {
		t.Skip("需要本机 Chrome 与公网，设置 SCAN4ALL_TEST_CHROME=1 后再运行")
	}
	// create chrome instance
	ctx, cancel := chromedp.NewContext(
		context.Background(),
		chromedp.WithLogf(log.Printf),
	)
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// navigate to a page, wait for an element, click
	var example string
	err := chromedp.Run(ctx,
		chromedp.Navigate(`https://www.baidu.com/`),
		// // wait for footer element is visible (ie, page is loaded)
		chromedp.WaitVisible(`body`),
		// // find and click "Expand All" link
		// chromedp.Click(`#pkg-examples > div`, chromedp.NodeVisible),
		// // retrieve the value of the textarea
		// chromedp.Value(`document.cookies`, &example),
		chromedp.ActionFunc(func(ctx context.Context) error {
			cookies, err := storage.GetCookies().Do(ctx)
			if err != nil {
				return err
			}
			for _, cookie := range cookies {
				example += fmt.Sprintf("%v", cookie) + ";"
			}
			return nil
		}),
	)
	if err != nil {
		t.Errorf("chromedp run failed: %v", err)
		return
	}
	fmt.Printf("Go's time.After example:\n%s", example)
}
