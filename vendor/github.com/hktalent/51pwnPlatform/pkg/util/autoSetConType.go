package util

import (
	"fmt"
	"github.com/gin-gonic/gin"
	util "github.com/hktalent/go-utils"
	"net/http"
	"strings"
	"sync"
)

var AuthHandler func(c *gin.Context)

var auPath sync.Map

// 注册哪些 url path必须通过认证
func RegPaths4Auth(s ...string) {
	for _, a := range s {
		auPath.Store(a, true)
	}
}

var ExpMap = map[string]bool{
	"/api/auth/login":   true,
	"/api/auth/captcha": true,
	"/api/auth/info":    true,
	"/api/auth/logout":  true,
}

// 只处理注册过的路径进行认证
func MyAuthHandler(c *gin.Context) {
	if util.GetValAsBool("devDebug") {
		return
	}
	szPath := c.Request.URL.Path
	// 表示处理过了
	if v, ok := c.Request.Context().Value(szPath).(bool); ok && v == true {
		return
	}
	if nil != AuthHandler {

		bAuth := false
		auPath.Range(func(key, value any) bool {
			if bAuth {
				return false
			}
			k := fmt.Sprintf("%v", key)
			if strings.HasPrefix(szPath, k) {
				bAuth = true
			}
			return true
		})
		if _, ok := ExpMap[szPath]; ok {
			return
		}
		if bAuth {
			AuthHandler(c)
		}
	}
}

func AutoSetCT(p string, i interface{}, g *gin.Context) {
	var hd http.Header
	if o, ok := i.(*gin.Context); ok {
		hd = o.Writer.Header()
	} else if o, ok := i.(*http.PushOptions); ok {
		hd = o.Header
	}
	hd.Set("Accept-Encoding", g.Request.Header.Get("Accept-Encoding"))
	if strings.HasSuffix(p, ".js") {
		hd.Set("Content-Type", "application/javascript; charset=utf-8")
	} else {
		if strings.HasSuffix(p, ".css") {
			hd.Set("Content-Type", "text/css; charset=utf-8")
		}
	}
}
