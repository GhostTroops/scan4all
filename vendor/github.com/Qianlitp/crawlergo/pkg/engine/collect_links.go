package engine

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/logger"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
)

/**
最后收集所有的链接
*/
func (tab *Tab) collectLinks() {
	go tab.collectHrefLinks()
	go tab.collectObjectLinks()
	go tab.collectCommentLinks()
}

func (tab *Tab) collectHrefLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集 src href data-url 属性值
	attrNameList := []string{"src", "href", "data-url", "data-href"}
	for _, attrName := range attrNameList {
		tCtx, cancel := context.WithTimeout(ctx, time.Second*1)
		var attrs []map[string]string
		_ = chromedp.AttributesAll(fmt.Sprintf(`[%s]`, attrName), &attrs, chromedp.ByQueryAll).Do(tCtx)
		cancel()
		for _, attrMap := range attrs {
			tab.AddResultUrl(config.GET, attrMap[attrName], config.FromDOM)
		}
	}
}

func (tab *Tab) collectObjectLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集 object[data] links
	tCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	var attrs []map[string]string
	_ = chromedp.AttributesAll(`object[data]`, &attrs, chromedp.ByQueryAll).Do(tCtx)
	for _, attrMap := range attrs {
		tab.AddResultUrl(config.GET, attrMap["data"], config.FromDOM)
	}
}

func (tab *Tab) collectCommentLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集注释中的链接
	var nodes []*cdp.Node
	tCtxComment, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	commentErr := chromedp.Nodes(`//comment()`, &nodes, chromedp.BySearch).Do(tCtxComment)
	if commentErr != nil {
		logger.Logger.Debug("get comment nodes err")
		logger.Logger.Debug(commentErr)
		return
	}
	urlRegex := regexp.MustCompile(config.URLRegex)
	for _, node := range nodes {
		content := node.NodeValue
		urlList := urlRegex.FindAllString(content, -1)
		for _, url := range urlList {
			tab.AddResultUrl(config.GET, url, config.FromComment)
		}
	}
}
