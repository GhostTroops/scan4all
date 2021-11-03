package check

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/veo/vscan/pkg"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	common_structs "github.com/veo/vscan/pocs_yml/pkg/common/structs"
	"github.com/veo/vscan/pocs_yml/pkg/xray/cel"
	"github.com/veo/vscan/pocs_yml/pkg/xray/requests"
	"github.com/veo/vscan/pocs_yml/pkg/xray/structs"
	"github.com/veo/vscan/pocs_yml/utils"
)

func Start(target string, pocs []*structs.Poc) {
	for _, poc := range pocs {
		if req, err := http.NewRequest("GET", target, nil); err == nil {
			isVul, err := executePoc(req, poc)
			if err != nil {
				gologger.Error().Msgf("Execute Poc (%v) error: %v", poc.Name, err.Error())
			}
			if isVul {
				pkg.YmlPocLog(fmt.Sprintf("%s (%s)\n", target, poc.Name))
			}
		}
	}
}

func executePoc(oReq *http.Request, p *structs.Poc) (bool, error) {
	//utils.DebugF("Check Poc [%#v] (%#v)", oReq.URL.String(), p.Name)

	c := cel.NewEnvOption()

	set := make(map[string]string, 0)
	for _, item := range p.Set {
		set[item.Key.(string)] = item.Value.(string)
	}

	c.UpdateCompileOptions(set)
	env, err := cel.NewEnv(&c)

	if err != nil {
		//utils.ErrorF("Environment creation error: %s\n", err.Error())
		return false, err
	}

	variableMap := make(map[string]interface{})
	req, err := requests.ParseRequest(oReq)
	if err != nil {
		//utils.Error(err)
		return false, err
	}
	variableMap["request"] = req

	// 现在假定set中payload作为最后产出，那么先解析其他的自定义变量，更新map[string]interface{}后再来解析payload
	for k, expression := range set {
		if k != "payload" {
			if expression == "newReverse()" {
				variableMap[k] = newReverse()
				continue
			}
			out, err := cel.Evaluate(env, expression, variableMap)
			if err != nil {
				fmt.Println(err)
				continue
			}
			switch value := out.Value().(type) {
			case *structs.UrlType:
				variableMap[k] = cel.UrlTypeToString(value)
			case int64:
				variableMap[k] = int(value)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}

	// 执行payload
	if set["payload"] != "" {
		out, err := cel.Evaluate(env, set["payload"], variableMap)
		if err != nil {
			return false, err
		}
		variableMap["payload"] = fmt.Sprintf("%v", out)
	}

	success := false

	// 处理单条Rule
	DealWithRule := func(rule structs.Rule) (bool, error) {
		var (
			flag, ok bool
		)

		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		if oReq.URL.Path != "" && oReq.URL.Path != "/" {
			req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
		} else {
			req.Url.Path = rule.Path
		}
		// 某些poc没有区分path和query，需要处理
		req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
		req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

		newRequest, _ := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))

		newRequest.Header = oReq.Header.Clone()
		for k, v := range rule.Headers {
			newRequest.Header.Set(k, v)
		}

		resp, err := requests.DoRequest(newRequest, rule.FollowRedirects)
		if err != nil {
			return false, err
		}

		variableMap["response"] = resp

		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := doSearch(strings.TrimSpace(rule.Search), string(resp.Body))
			if result != nil && len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap[k] = v
				}
			} else {
				return false, nil
			}
		}

		// 执行表达式
		out, err := cel.Evaluate(env, rule.Expression, variableMap)
		if err != nil {
			return false, err
		}

		// 判断最后执行表达式结果
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}
		return flag, nil
	}

	DealWithRules := func(rules []structs.Rule) bool {
		successFlag := false
		for _, rule := range rules {
			flag, err := DealWithRule(rule)
			if err != nil {
				gologger.Error().Msgf("Execute Rule error: %#v", err.Error())
			}

			if err != nil || !flag { //如果false不继续执行后续rule
				successFlag = false // 如果其中一步为flag，则直接break
				break
			}
			successFlag = true
		}
		return successFlag
	}

	// Rules
	if len(p.Rules) > 0 {
		success = DealWithRules(p.Rules)
	} else { // Groups
		for _, rules := range p.Groups {
			success = DealWithRules(rules)
			if success {
				break
			}
		}
	}

	return success, nil
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	//fmt.Sprintf("Regexp compile error: %v", err.Error())
	if err != nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				paramsMap[name] = result[i]
			}
		}
		return paramsMap
	}
	return nil
}

func newReverse() *structs.Reverse {
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	sub := utils.RandomStr(randSource, letters, 8)
	if common_structs.CeyeDomain == "" {
		return &structs.Reverse{}
	}
	urlStr := fmt.Sprintf("http://%s.%s", sub, common_structs.CeyeDomain)
	u, _ := url.Parse(urlStr)
	return &structs.Reverse{
		Url:                requests.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}
