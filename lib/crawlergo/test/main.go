package main

import (
	"context"
	pkg "github.com/GhostTroops/scan4all/lib/crawlergo"
	"github.com/chromedp/chromedp"
	"log"
	"time"
)

func main() {
	ctx := context.Background()
	x1 := pkg.GetChromedpInstace(&ctx)
	//n1 := 15 * time.Second
	n1 := 10000 * time.Second

	// Username already used
	//x1.DoUrl("https://google.com", &map[string]interface{}{"cookie": "xxx"}, nil)
	if err := x1.DoUrl("https://127.0.0.1:8081", &map[string]interface{}{}, &n1, func() *chromedp.Tasks {
		szPswd := ""
		return &chromedp.Tasks{
			chromedp.SetValue(`#email`, "hk_994", chromedp.ByID),
			chromedp.SetValue(`#password`, szPswd, chromedp.ByID),
			chromedp.SetValue(`#repeat-password`, szPswd, chromedp.ByID),
			chromedp.Click("main > div.sign-layout-main-content > form > button", chromedp.NodeReady),
			chromedp.Click("#html_element", chromedp.ByID),
		}
		// next:hk_994
		// main > div.sign-layout-main-content > form > button
		// 跳过手机号码
		// /html/body/div[1]/div[3]/div/div/main/div[2]/form/button[2]
	}); err != nil {
		log.Println(err)
	}
	////defer x1.Close()

	//RegGithub()
}

// https://github.com/signup?ref_cta=Sign+up&ref_loc=header+logged+out&ref_page=%2F&source=header-home
func RegGithub() {
	ctx := context.Background()
	x1 := pkg.GetChromedpInstace(&ctx)
	//n1 := 15 * time.Second
	n1 := 1000 * time.Second

	if err := x1.DoUrl("https://github.com/signup?ref_cta=Sign+up&ref_loc=header+logged+out&ref_page=%2F&source=header-home", &map[string]interface{}{}, &n1, func() *chromedp.Tasks {
		szPswd := ""
		return &chromedp.Tasks{
			chromedp.SetValue(`#email`, "hk_994@proton.me", chromedp.ByID),
			chromedp.Sleep(2 * time.Second),
			chromedp.Click("//*[@id=\"email-container\"]/div[2]/button", chromedp.NodeReady),
			chromedp.Sleep(2 * time.Second),
			chromedp.SetValue(`#password`, szPswd, chromedp.ByID),
			chromedp.Sleep(2 * time.Second),
			chromedp.Click(`document.querySelector("#password-container > div.d-flex.flex-items-center.flex-column.flex-sm-row > button")`, chromedp.ByJSPath),
			chromedp.Sleep(2 * time.Second),
			chromedp.SetValue(`#login`, "hk999999", chromedp.ByID),
			chromedp.Sleep(2 * time.Second),
			chromedp.SetValue(`#opt_in`, "n", chromedp.ByID),
			chromedp.Sleep(2 * time.Second),
			chromedp.Click(`document.querySelector("#opt-in-container > div.d-flex.flex-items-center.flex-column.flex-sm-row > button")`, chromedp.ByJSPath),
		}
		// next:hk_994
		// main > div.sign-layout-main-content > form > button
		// 跳过手机号码
		// /html/body/div[1]/div[3]/div/div/main/div[2]/form/button[2]
	}); err != nil {
		log.Println(err)
	}
	//defer x1.Close()
}
