package engine

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/js"
	"github.com/Qianlitp/crawlergo/pkg/logger"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
)

/**
在DOMContentLoaded完成后执行
*/
func (tab *Tab) AfterDOMRun() {
	defer tab.WG.Done()

	logger.Logger.Debug("afterDOMRun start")

	// 获取当前body节点的nodeId 用于之后查找子节点
	if !tab.getBodyNodeId() {
		logger.Logger.Debug("no body document NodeID, exit.")
		return
	}

	tab.domWG.Add(2)
	go tab.fillForm()
	go tab.setObserverJS()
	tab.domWG.Wait()
	logger.Logger.Debug("afterDOMRun end")
	tab.WG.Add(1)
	go tab.AfterLoadedRun()
}

/**
获取的Body的NodeId 用于之后子节点无等待查询
最多等待3秒 如果DOM依旧没有渲染完成，则退出
*/
func (tab *Tab) getBodyNodeId() bool {
	var docNodeIDs []cdp.NodeID
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	// 获取 Frame document root
	err := chromedp.NodeIDs(`body`, &docNodeIDs, chromedp.ByQuery).Do(tCtx)
	if len(docNodeIDs) == 0 || err != nil {
		// not root node yet?
		logger.Logger.Debug("getBodyNodeId failed, maybe DOM not ready?")
		if err != nil {
			logger.Logger.Debug(err)
		}
		return false
	}
	tab.DocBodyNodeId = docNodeIDs[0]
	return true
}

/**
自动化填充表单
*/
func (tab *Tab) fillForm() {
	defer tab.domWG.Done()
	logger.Logger.Debug("fillForm start")
	tab.fillFormWG.Add(3)
	f := FillForm{
		tab: tab,
	}

	go f.fillInput()
	go f.fillMultiSelect()
	go f.fillTextarea()

	tab.fillFormWG.Wait()
	logger.Logger.Debug("fillForm end")
}

/**
设置Dom节点变化的观察函数
*/
func (tab *Tab) setObserverJS() {
	defer tab.domWG.Done()
	logger.Logger.Debug("setObserverJS start")
	// 设置Dom节点变化的观察函数
	go tab.Evaluate(js.ObserverJS)
	logger.Logger.Debug("setObserverJS end")
}

type FillForm struct {
	tab *Tab
}

/**
填充所有 input 标签
*/
func (f *FillForm) fillInput() {
	defer f.tab.fillFormWG.Done()
	var nodes []*cdp.Node
	ctx := f.tab.GetExecutor()

	tCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	// 首先判断input标签是否存在，减少等待时间 提前退出
	inputNodes, inputErr := f.tab.GetNodeIDs(`input`)
	if inputErr != nil || len(inputNodes) == 0 {
		logger.Logger.Debug("fillInput: get form input element err")
		if inputErr != nil {
			logger.Logger.Debug(inputErr)
		}
		return
	}
	// 获取所有的input标签
	err := chromedp.Nodes(`input`, &nodes, chromedp.ByQueryAll).Do(tCtx)

	if err != nil {
		logger.Logger.Debug("get all input element err")
		logger.Logger.Debug(err)
		return
	}

	// 找出 type 为空 或者 type=text
	for _, node := range nodes {
		// 兜底超时
		tCtxN, cancelN := context.WithTimeout(ctx, time.Second*5)
		attrType := node.AttributeValue("type")
		if attrType == "text" || attrType == "" {
			inputName := node.AttributeValue("id") + node.AttributeValue("class") + node.AttributeValue("name")
			value := f.GetMatchInputText(inputName)
			var nodeIds = []cdp.NodeID{node.NodeID}
			// 先使用模拟输入
			_ = chromedp.SendKeys(nodeIds, value, chromedp.ByNodeID).Do(tCtxN)
			// 再直接赋值JS属性
			_ = chromedp.SetAttributeValue(nodeIds, "value", value, chromedp.ByNodeID).Do(tCtxN)
		} else if attrType == "email" || attrType == "password" || attrType == "tel" {
			value := f.GetMatchInputText(attrType)
			var nodeIds = []cdp.NodeID{node.NodeID}
			// 先使用模拟输入
			_ = chromedp.SendKeys(nodeIds, value, chromedp.ByNodeID).Do(tCtxN)
			// 再直接赋值JS属性
			_ = chromedp.SetAttributeValue(nodeIds, "value", value, chromedp.ByNodeID).Do(tCtxN)
		} else if attrType == "radio" || attrType == "checkbox" {
			var nodeIds = []cdp.NodeID{node.NodeID}
			_ = chromedp.SetAttributeValue(nodeIds, "checked", "true", chromedp.ByNodeID).Do(tCtxN)
		} else if attrType == "file" || attrType == "image" {
			var nodeIds = []cdp.NodeID{node.NodeID}
			wd, _ := os.Getwd()
			filePath := wd + "/upload/image.png"
			_ = chromedp.RemoveAttribute(nodeIds, "accept", chromedp.ByNodeID).Do(tCtxN)
			_ = chromedp.RemoveAttribute(nodeIds, "required", chromedp.ByNodeID).Do(tCtxN)
			_ = chromedp.SendKeys(nodeIds, filePath, chromedp.ByNodeID).Do(tCtxN)
		}
		cancelN()
	}
}

func (f *FillForm) fillTextarea() {
	defer f.tab.fillFormWG.Done()
	ctx := f.tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	value := f.GetMatchInputText("other")

	textareaNodes, textareaErr := f.tab.GetNodeIDs(`textarea`)
	if textareaErr != nil || len(textareaNodes) == 0 {
		logger.Logger.Debug("fillTextarea: get textarea element err")
		if textareaErr != nil {
			logger.Logger.Debug(textareaErr)
		}
		return
	}

	_ = chromedp.SendKeys(textareaNodes, value, chromedp.ByNodeID).Do(tCtx)
}

func (f *FillForm) fillMultiSelect() {
	defer f.tab.fillFormWG.Done()
	ctx := f.tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	optionNodes, optionErr := f.tab.GetNodeIDs(`select option:first-child`)
	if optionErr != nil || len(optionNodes) == 0 {
		logger.Logger.Debug("fillMultiSelect: get select option element err")
		if optionErr != nil {
			logger.Logger.Debug(optionErr)
		}
		return
	}
	_ = chromedp.SetAttributeValue(optionNodes, "selected", "true", chromedp.ByNodeID).Do(tCtx)
	_ = chromedp.SetJavascriptAttribute(optionNodes, "selected", "true", chromedp.ByNodeID).Do(tCtx)
}

func (f *FillForm) GetMatchInputText(name string) string {
	// 如果自定义了关键词，模糊匹配
	for key, value := range f.tab.config.CustomFormKeywordValues {
		if strings.Contains(name, key) {
			return value
		}
	}

	name = strings.ToLower(name)
	for key, item := range config.InputTextMap {
		for _, keyword := range item["keyword"].([]string) {
			if strings.Contains(name, keyword) {
				if customValue, ok := f.tab.config.CustomFormValues[key]; ok {
					return customValue
				} else {
					return item["value"].(string)
				}
			}
		}
	}
	return f.tab.config.CustomFormValues["default"]
}
