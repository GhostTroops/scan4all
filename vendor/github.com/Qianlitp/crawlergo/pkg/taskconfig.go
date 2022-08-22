package pkg

import "time"

type TaskConfig struct {
	MaxCrawlCount           int    // 最大爬取的数量
	FilterMode              string // simple、smart、strict
	ExtraHeaders            map[string]interface{}
	ExtraHeadersString      string
	AllDomainReturn         bool // 全部域名收集
	SubDomainReturn         bool // 子域名收集
	NoHeadless              bool // headless模式
	DomContentLoadedTimeout time.Duration
	TabRunTimeout           time.Duration     // 单个标签页超时
	PathByFuzz              bool              // 通过字典进行Path Fuzz
	FuzzDictPath            string            //Fuzz目录字典
	PathFromRobots          bool              // 解析Robots文件找出路径
	MaxTabsCount            int               // 允许开启的最大标签页数量 即同时爬取的数量
	ChromiumPath            string            // Chromium的程序路径  `/home/zhusiyu1/chrome-linux/chrome`
	EventTriggerMode        string            // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration     // 事件触发的间隔
	BeforeExitDelay         time.Duration     // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool              // 使用检测到的字符集自动编码URL
	IgnoreKeywords          []string          // 忽略的关键字，匹配上之后将不再扫描且不发送请求
	Proxy                   string            // 请求代理
	CustomFormValues        map[string]string // 自定义表单填充参数
	CustomFormKeywordValues map[string]string // 自定义表单关键词填充内容
}

type TaskConfigOptFunc func(*TaskConfig)

func NewTaskConfig(optFuncs ...TaskConfigOptFunc) *TaskConfig {
	conf := &TaskConfig{}
	for _, fn := range optFuncs {
		fn(conf)
	}
	return conf
}

func WithMaxCrawlCount(maxCrawlCount int) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.MaxCrawlCount == 0 {
			tc.MaxCrawlCount = maxCrawlCount
		}
	}
}

func WithFilterMode(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.FilterMode == "" {
			tc.FilterMode = gen
		}
	}
}

func WithExtraHeaders(gen map[string]interface{}) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.ExtraHeaders == nil {
			tc.ExtraHeaders = gen
		}
	}
}

func WithExtraHeadersString(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.ExtraHeadersString == "" {
			tc.ExtraHeadersString = gen
		}
	}
}

func WithAllDomainReturn(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.AllDomainReturn {
			tc.AllDomainReturn = gen
		}
	}
}
func WithSubDomainReturn(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.SubDomainReturn {
			tc.SubDomainReturn = gen
		}
	}
}

func WithNoHeadless(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.NoHeadless {
			tc.NoHeadless = gen
		}
	}
}

func WithDomContentLoadedTimeout(gen time.Duration) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.DomContentLoadedTimeout == 0 {
			tc.DomContentLoadedTimeout = gen
		}
	}
}

func WithTabRunTimeout(gen time.Duration) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.TabRunTimeout == 0 {
			tc.TabRunTimeout = gen
		}
	}
}
func WithPathByFuzz(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.PathByFuzz {
			tc.PathByFuzz = gen
		}
	}
}
func WithFuzzDictPath(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.FuzzDictPath == "" {
			tc.FuzzDictPath = gen
		}
	}
}
func WithPathFromRobots(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.PathFromRobots {
			tc.PathFromRobots = gen
		}
	}
}
func WithMaxTabsCount(gen int) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.MaxTabsCount == 0 {
			tc.MaxTabsCount = gen
		}
	}
}
func WithChromiumPath(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.ChromiumPath == "" {
			tc.ChromiumPath = gen
		}
	}
}
func WithEventTriggerMode(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.EventTriggerMode == "" {
			tc.EventTriggerMode = gen
		}
	}
}
func WithEventTriggerInterval(gen time.Duration) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.EventTriggerInterval == 0 {
			tc.EventTriggerInterval = gen
		}
	}
}
func WithBeforeExitDelay(gen time.Duration) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.BeforeExitDelay == 0 {
			tc.BeforeExitDelay = gen
		}
	}
}
func WithEncodeURLWithCharset(gen bool) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if !tc.EncodeURLWithCharset {
			tc.EncodeURLWithCharset = gen
		}
	}
}
func WithIgnoreKeywords(gen []string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.IgnoreKeywords == nil || len(tc.IgnoreKeywords) == 0 {
			tc.IgnoreKeywords = gen
		}
	}
}
func WithProxy(gen string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.Proxy == "" {
			tc.Proxy = gen
		}
	}
}
func WithCustomFormValues(gen map[string]string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.CustomFormValues == nil || len(tc.CustomFormValues) == 0 {
			tc.CustomFormValues = gen
		}
	}
}
func WithCustomFormKeywordValues(gen map[string]string) TaskConfigOptFunc {
	return func(tc *TaskConfig) {
		if tc.CustomFormKeywordValues == nil || len(tc.CustomFormKeywordValues) == 0 {
			tc.CustomFormKeywordValues = gen
		}
	}
}
