package check

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/cel"
	"github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/requests"
	xray_structs "github.com/GhostTroops/scan4all/pocs_yml/pkg/xray/structs"
	"github.com/google/cel-go/checker/decls"
	"gopkg.in/yaml.v2"
)

var (
	BodyBufPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1024)
		},
	}
	BodyPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 4096)
		},
	}
	VariableMapPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]interface{})
		},
	}
)

type RequestFuncType func(ruleName string, rule xray_structs.Rule) error

func Start(target string, pocs []*xray_structs.Poc) []string {
	var Vullist []string
	for _, poc := range pocs {
		// 需优化：这里性能考虑，共用其他 POC已经发过的请求的的状态、结果
		if req, err := http.NewRequest("GET", target, nil); err == nil {
			isVul, err := executeXrayPoc(req, target, poc)
			if err != nil {
				gologger.Error().Msgf("Execute Poc (%v) error: %v", poc.Name, err.Error())
			}
			if isVul {
				util.SendLog(target, poc.Name, "", poc.Name)
				Vullist = append(Vullist, poc.Name)
			}
		}
	}
	return Vullist
}

func executeXrayPoc(oReq *http.Request, target string, poc *xray_structs.Poc) (isVul bool, err error) {
	isVul = false

	var (
		milliseconds int64
		tcpudpType   = ""

		request       *http.Request
		response      *http.Response
		oProtoRequest *xray_structs.Request
		protoRequest  *xray_structs.Request
		protoResponse *xray_structs.Response
		variableMap   = VariableMapPool.Get().(map[string]interface{})
		requestFunc   cel.RequestFuncType
	)

	// 异常处理
	defer func() {
		if r := recover(); r != nil {
			err = errors.Wrapf(r.(error), "Run Xray Poc[%s] error", poc.Name)
			isVul = false
		}
	}()
	// 回收
	defer func() {
		if protoRequest != nil {
			requests.PutUrlType(protoRequest.Url)
			requests.PutRequest(protoRequest)

		}
		if oProtoRequest != nil {
			requests.PutUrlType(oProtoRequest.Url)
			requests.PutRequest(oProtoRequest)

		}
		if protoResponse != nil {
			requests.PutUrlType(protoResponse.Url)
			if protoResponse.Conn != nil {
				requests.PutAddrType(protoResponse.Conn.Source)
				requests.PutAddrType(protoResponse.Conn.Destination)
				requests.PutConnectInfo(protoResponse.Conn)
			}
			requests.PutResponse(protoResponse)
		}

		for _, v := range variableMap {
			switch v.(type) {
			case *xray_structs.Reverse:
				cel.PutReverse(v)
			}
		}
		VariableMapPool.Put(variableMap)
	}()

	// 初始赋值
	// 设置原始请求变量
	oProtoRequest, _ = requests.ParseHttpRequest(oReq)
	variableMap["request"] = oProtoRequest

	// 判断transport，如果不合法则跳过
	transport := poc.Transport
	if transport == "tcp" || transport == "udp" {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			return
		}
	} else {
		_, err = url.ParseRequestURI(strings.TrimSpace(target))
		if err != nil {
			return
		}
	}

	// 初始化cel-go环境，并在函数返回时回收
	c := cel.NewEnvOption()
	defer cel.PutCustomLib(c)

	env, err := cel.NewEnv(&c)
	if err != nil {
		return false, err
	}

	// 请求中的全局变量

	// 定义渲染函数
	render := func(v string) string {
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			v1Value := fmt.Sprintf("%v", v1)
			t := "{{" + k1 + "}}"
			if !strings.Contains(v, t) {
				continue
			}
			v = strings.ReplaceAll(v, t, v1Value)
		}
		return v
	}
	ReCreateEnv := func() error {
		env, err = cel.NewEnv(&c)
		if err != nil {
			return err
		}
		return nil
	}

	// 定义evaluateUpdateVariableMap
	evaluateUpdateVariableMap := func(set yaml.MapSlice) {
		for _, item := range set {
			k, expression := item.Key.(string), item.Value.(string)
			// ? 需要重新生成一遍环境，否则之前增加的变量定义不生效
			if err := ReCreateEnv(); err != nil {

			}

			out, err := cel.Evaluate(env, expression, variableMap)
			if err != nil {
				continue
			}

			// 设置variableMap并且更新CompileOption
			switch value := out.Value().(type) {
			case *xray_structs.UrlType:
				variableMap[k] = cel.UrlTypeToString(value)
				c.UpdateCompileOption(k, cel.UrlTypeType)
			case *xray_structs.Reverse:
				variableMap[k] = value
				c.UpdateCompileOption(k, cel.ReverseType)
			case int64:
				variableMap[k] = int(value)
				c.UpdateCompileOption(k, decls.Int)
			case map[string]string:
				variableMap[k] = value
				c.UpdateCompileOption(k, cel.StrStrMapType)
			default:
				variableMap[k] = value
				c.UpdateCompileOption(k, decls.String)
			}
		}
		// ? 最后再生成一遍环境，否则之前增加的变量定义不生效
		if err := ReCreateEnv(); err != nil {

		}
	}

	// 处理set
	evaluateUpdateVariableMap(poc.Set)

	// 处理payload
	for _, setMapVal := range poc.Payloads.Payloads {
		setMap := setMapVal.Value.(yaml.MapSlice)
		evaluateUpdateVariableMap(setMap)
	}
	// 渲染detail
	detail := &poc.Detail
	detail.Author = render(detail.Author)
	for k, v := range poc.Detail.Links {
		detail.Links[k] = render(v)
	}
	fingerPrint := &detail.FingerPrint
	for _, info := range fingerPrint.Infos {
		info.ID = render(info.ID)
		info.Name = render(info.Name)
		info.Version = render(info.Version)
		info.Type = render(info.Type)
	}
	fingerPrint.HostInfo.Hostname = render(fingerPrint.HostInfo.Hostname)
	vulnerability := &detail.Vulnerability
	vulnerability.ID = render(vulnerability.ID)
	vulnerability.Match = render(vulnerability.Match)

	// transport=http: request处理
	HttpRequestInvoke := func(rule xray_structs.Rule) error {
		var (
			ok               bool
			err              error
			ruleReq          = rule.Request
			rawHeaderBuilder strings.Builder
		)

		// 渲染请求头，请求路径和请求体
		for k, v := range ruleReq.Headers {
			ruleReq.Headers[k] = render(v)
		}
		ruleReq.Path = render(strings.TrimSpace(ruleReq.Path))
		ruleReq.Body = render(strings.TrimSpace(ruleReq.Body))

		// 尝试获取缓存
		if request, protoRequest, protoResponse, ok = requests.XrayGetHttpRequestCache(&ruleReq); !ok || !rule.Request.Cache {
			// 获取protoRequest
			protoRequest, err = requests.ParseHttpRequest(oReq)
			if err != nil {
				return err
			}

			// 处理Path
			if strings.HasPrefix(ruleReq.Path, "/") {
				protoRequest.Url.Path = strings.Trim(oReq.URL.Path, "/") + "/" + ruleReq.Path[1:]
			} else if strings.HasPrefix(ruleReq.Path, "^") {
				protoRequest.Url.Path = "/" + ruleReq.Path[1:]
			}

			if !strings.HasPrefix(protoRequest.Url.Path, "/") {
				protoRequest.Url.Path = "/" + protoRequest.Url.Path
			}

			// 某些poc没有区分path和query，需要处理
			protoRequest.Url.Path = strings.ReplaceAll(protoRequest.Url.Path, " ", "%20")
			protoRequest.Url.Path = strings.ReplaceAll(protoRequest.Url.Path, "+", "%20")

			// 克隆请求对象
			request, err = http.NewRequest(ruleReq.Method, fmt.Sprintf("%s://%s%s", protoRequest.Url.Scheme, protoRequest.Url.Host, protoRequest.Url.Path), strings.NewReader(ruleReq.Body))
			if err != nil {
				return err
			}

			// 处理请求头
			request.Header = oReq.Header.Clone()
			for k, v := range ruleReq.Headers {
				request.Header.Set(k, v)
				rawHeaderBuilder.WriteString(k)
				rawHeaderBuilder.WriteString(": ")
				rawHeaderBuilder.WriteString(v)
				rawHeaderBuilder.WriteString("\n")
			}

			protoRequest.RawHeader = []byte(strings.Trim(rawHeaderBuilder.String(), "\n"))

			// 额外处理protoRequest.Raw
			protoRequest.Raw, _ = httputil.DumpRequestOut(request, true)

			// 发起请求
			response, milliseconds, err = requests.DoRequest(request, ruleReq.FollowRedirects)
			if err != nil {
				return err
			}

			// 获取protoResponse
			protoResponse, err = requests.ParseHttpResponse(response, milliseconds)
			if err != nil {
				return err
			}

			// 设置缓存
			requests.XraySetHttpRequestCache(&ruleReq, request, protoRequest, protoResponse)

		} else {
		}

		return nil
	}

	// transport=tcp/udp: request处理
	TCPUDPRequestInvoke := func(rule xray_structs.Rule) error {
		var (
			buffer = BodyBufPool.Get().([]byte)

			content      = rule.Request.Content
			connectionID = rule.Request.ConnectionID
			conn         net.Conn
			connCache    *net.Conn
			responseRaw  []byte
			readTimeout  int

			ok  bool
			err error
		)
		defer BodyBufPool.Put(buffer)

		// 获取response缓存
		if responseRaw, protoResponse, ok = requests.XrayGetTcpUdpResponseCache(rule.Request.Content); !ok || !rule.Request.Cache {
			responseRaw = BodyPool.Get().([]byte)
			defer BodyPool.Put(responseRaw)

			// 获取connectionID缓存
			if connCache, ok = requests.XrayGetTcpUdpConnectionCache(connectionID); !ok {
				// 处理timeout
				readTimeout, err = strconv.Atoi(rule.Request.ReadTimeout)
				if err != nil {
					return err
				}

				// 发起连接
				conn, err = net.Dial(tcpudpType, target)
				if err != nil {
					return err
				}

				// 设置读取超时
				err := conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeout) * time.Second))
				if err != nil {
					return err
				}

				// 设置连接缓存
				requests.XraySetTcpUdpConnectionCache(connectionID, &conn)
			} else {
				conn = *connCache
			}

			// 获取protoRequest
			protoRequest, _ = requests.ParseTCPUDPRequest([]byte(content))

			// 发送数据
			_, err = conn.Write([]byte(content))
			if err != nil {
				return err
			}

			// 接收数据
			for {
				n, err := conn.Read(buffer)
				if err != nil {
					if err == io.EOF {
					} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					} else {
						return err
					}
					break
				}
				responseRaw = append(responseRaw, buffer[:n]...)
			}

			// 获取protoResponse
			protoResponse, _ = requests.ParseTCPUDPResponse(responseRaw, &conn, tcpudpType)

			// 设置响应缓存
			requests.XraySetTcpUdpResponseCache(content, responseRaw, protoResponse)

		}
		return nil
	}

	// reqeusts总处理
	RequestInvoke := func(requestFunc cel.RequestFuncType, ruleName string, rule xray_structs.Rule) (bool, error) {
		var (
			flag bool
			ok   bool
			err  error
		)
		err = requestFunc(rule)
		if err != nil {
			return false, err
		}

		variableMap["request"] = protoRequest
		variableMap["response"] = protoResponse

		// 执行表达式
		out, err := cel.Evaluate(env, rule.Expression, variableMap)

		if err != nil {
			return false, err
		}

		// 判断表达式结果
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}

		// 处理output
		evaluateUpdateVariableMap(rule.Output)

		return flag, nil
	}

	// 判断transport类型，设置requestInvoke
	if poc.Transport == "tcp" {
		tcpudpType = "tcp"
		requestFunc = TCPUDPRequestInvoke
	} else if poc.Transport == "udp" {
		tcpudpType = "udp"
		requestFunc = TCPUDPRequestInvoke
	} else {
		requestFunc = HttpRequestInvoke
	}

	ruleSlice := poc.Rules
	// 提前定义名为ruleName的函数
	for _, ruleItem := range ruleSlice {
		c.DefineRuleFunction(requestFunc, ruleItem.Key, ruleItem.Value, RequestInvoke)
	}

	// ? 最后再生成一遍环境，否则之前增加的变量定义不生效
	if err := ReCreateEnv(); err != nil {

	}

	// 执行rule 并判断poc总体表达式结果
	successVal, err := cel.Evaluate(env, poc.Expression, variableMap)
	if err != nil {
		return false, err
	}

	isVul, ok := successVal.Value().(bool)
	if !ok {
		isVul = false
	}

	return isVul, nil
}
