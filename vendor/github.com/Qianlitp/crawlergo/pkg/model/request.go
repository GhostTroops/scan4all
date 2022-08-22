package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/tools"
)

type Filter struct {
	MarkedQueryMap    map[string]interface{}
	QueryKeysId       string
	QueryMapId        string
	MarkedPostDataMap map[string]interface{}
	PostDataId        string
	MarkedPath        string
	FragmentID        string
	PathId            string
	UniqueId          string
}

type Options struct {
	Headers  map[string]interface{}
	PostData string
}

type Request struct {
	URL             *URL
	Method          string
	Headers         map[string]interface{}
	PostData        string
	Filter          Filter
	Source          string
	RedirectionFlag bool
	Proxy           string
}

var supportContentType = []string{config.JSON, config.URLENCODED}

/**
获取Request对象
可选设置headers和postData
*/
func GetRequest(method string, URL *URL, options ...Options) Request {
	var req Request
	req.URL = URL
	req.Method = strings.ToUpper(method)
	if len(options) != 0 {
		option := options[0]
		if option.Headers != nil {
			req.Headers = option.Headers
		}

		if option.PostData != "" {
			req.PostData = option.PostData
		}
	} else {
		req.Headers = map[string]interface{}{}
	}

	return req
}

/**
完整格式化输出
*/
func (req *Request) FormatPrint() {
	var tempStr = req.Method
	tempStr += " " + req.URL.String() + " HTTP/1.1\r\n"
	for k, v := range req.Headers {
		tempStr += k + ": " + v.(string) + "\r\n"
	}
	tempStr += "\r\n"
	if req.Method == config.POST {
		tempStr += req.PostData
	}
	fmt.Println(tempStr)
}

/**
简要输出
*/
func (req *Request) SimplePrint() {
	var tempStr = req.Method
	tempStr += " " + req.URL.String() + " "
	if req.Method == config.POST {
		tempStr += req.PostData
	}
	fmt.Println(tempStr)
}

func (req *Request) SimpleFormat() string {
	var tempStr = req.Method
	tempStr += " " + req.URL.String() + " "
	if req.Method == config.POST {
		tempStr += req.PostData
	}
	return tempStr
}

/**
不加入Header的请求ID
*/
func (req *Request) NoHeaderId() string {
	return tools.StrMd5(req.Method + req.URL.String() + req.PostData)
}

func (req *Request) UniqueId() string {
	if req.RedirectionFlag {
		return tools.StrMd5(req.NoHeaderId() + "Redirection")
	} else {
		return req.NoHeaderId()
	}
}

/**
返回POST请求数据解析后的map结构

支持 application/x-www-form-urlencoded 、application/json

如果解析失败，则返回 key: postDataStr 的map结构
*/
func (req *Request) PostDataMap() map[string]interface{} {
	contentType, err := req.getContentType()
	if err != nil {
		return map[string]interface{}{
			"key": req.PostData,
		}
	}

	if strings.HasPrefix(contentType, config.JSON) {
		var result map[string]interface{}
		err = json.Unmarshal([]byte(req.PostData), &result)
		if err != nil {
			return map[string]interface{}{
				"key": req.PostData,
			}
		} else {
			return result
		}
	} else if strings.HasPrefix(contentType, config.URLENCODED) {
		var result = map[string]interface{}{}
		r, err := url.ParseQuery(req.PostData)
		if err != nil {
			return map[string]interface{}{
				"key": req.PostData,
			}
		} else {
			for key, value := range r {
				if len(value) == 1 {
					result[key] = value[0]
				} else {
					result[key] = value
				}
			}
			return result
		}
	} else {
		return map[string]interface{}{
			"key": req.PostData,
		}
	}
}

/**
返回GET请求参数解析后的map结构
*/
func (req *Request) QueryMap() map[string][]string {
	return req.URL.Query()
}

/**
获取content-type
*/
func (req *Request) getContentType() (string, error) {
	headers := req.Headers
	var contentType string
	if ct, ok := headers["Content-Type"]; ok {
		contentType = ct.(string)
	} else if ct, ok := headers["Content-type"]; ok {
		contentType = ct.(string)
	} else if ct, ok := headers["content-type"]; ok {
		contentType = ct.(string)
	} else {
		return "", errors.New("no content-type")
	}

	for _, ct := range supportContentType {
		if strings.HasPrefix(contentType, ct) {
			return contentType, nil
		}
	}
	return "", errors.New("dont support such content-type:" + contentType)
}
