package brute

import (
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

// 这里后期优化：
// 1、基于字典
// 2、相同url，相同 body.len只做一次匹配
// 3、支持多地方调用
// 4、所有异常页面 > 400 > 500都做异常页面fuzz指纹
func Addfingerprints404(technologies []string, req *util.Response, oPage *util.Page) []string {
	var szKey string
	if nil != oPage {
		szKey = fmt.Sprintf("Addfingerprints404:%s_%d", *oPage.Url, oPage.BodyLen)
		data := util.Cache1.GetKeyForData(szKey)
		var rst []string
		if 0 < len(data) {
			err := json.Unmarshal(data, &rst)
			if nil == err {
				return rst
			}
		}
	}
	if 0 < util.CheckShiroCookie(req.Header) {
		technologies = append(technologies, "Shiro")
	}
	// StatusCode 404，这里会有误报，当请求当路径中包含了ThinkPHP，有些site返回当结果会看包涵全路径信息
	if util.StrContains(req.Body, "thinkphp") || -1 < strings.Index(strings.ToLower(*oPage.Url), strings.ToLower("/Runtime/Logs/")) {
		technologies = append(technologies, "ThinkPHP")
	}
	// 这里需要斟酌
	if util.StrContains(req.Body, "Hypertext Transfer Protocol") {
		technologies = append(technologies, "Weblogic")
	}
	if util.StrContains(req.Body, "font-family:Tahoma,Arial,sans-serif") {
		technologies = append(technologies, "Apache Tomcat")
	}
	if util.StrContains(req.Body, "Whitelabel Error Page") {
		technologies = append(technologies, "Spring")
	}

	if nil != oPage && 0 < len(szKey) && 0 < len(technologies) {
		util.PutAny[[]string](szKey, technologies)
	}

	return technologies
}

func Addfingerprintsnormal(payload string, technologies []string, req *util.Response, fuzzPage *util.Page) []string {
	a := Addfingerprintsnormal1(payload, []string{}, req, fuzzPage)
	if 0 < len(a) {
		util.PocCheck_pipe <- &util.PocCheck{Wappalyzertechnologies: &a, URL: req.RequestUrl, FinalURL: req.RequestUrl, Checklog4j: false}
	}
	return append(technologies, a...)
}

// 正常页面指纹处理
func Addfingerprintsnormal1(payload string, technologies []string, req *util.Response, fuzzPage *util.Page) []string {
	// StatusCode 200, 301, 302, 401, 500
	switch payload {
	case "/manager/html":
		if req.StatusCode == 401 && req.Header.Get("Www-Authenticate") != "" {
			technologies = append(technologies, "Apache Tomcat")
		}
	case "/console/login/LoginForm.jsp":
		if req.StatusCode == 200 && util.StrContains(req.Body, "Oracle") {
			technologies = append(technologies, "Weblogic")
		}
	case "/wls-wsat", "/wls-wsat/CoordinatorPortType", "/wls-wsat/CoordinatorPortType11", "/_async/AsyncResponseService", "/_async/AsyncResponseServiceSoap12", "/uddiexplorer/SearchPublicRegistries.jsp", "/ws_utc/config.do", "/bea_wls_internal/classes/mejb@/org/omg/stub/javax/management/j2ee/_ManagementHome_Stub.class":
		if req.StatusCode == 200 && (util.StrContains(req.Body, "weblogic") || strings.Contains(req.Body, "www.bea.com")) {
			technologies = append(technologies, "Weblogic")
		}
	case "/jmx-console/":
		if req.StatusCode == 200 && util.StrContains(req.Body, "jboss.css") {
			technologies = append(technologies, "Jboss")
		}
	case "/seeyon/":
		if util.StrContains(req.Body, "/seeyon/common/") {
			technologies = append(technologies, "seeyon")
		}
	case "/admin", "/admin-console", "/admin.asp", "/admin.aspx", "/admin.do", "/admin.html", "/admin.jsp", "/admin.php", "/admin/", "/admin/admin", "/admin/adminLogin.do", "/admin/checkLogin.do", "/admin/index.do", "/Admin/Login", "/admin/Login.aspx", "/admin/login.do", "/admin/menu", "/Adminer", "/adminer.php", "/administrator", "/adminLogin.do", "/checkLogin.do", "/doc/Page/login.asp", "/login", "/Login.aspx", "/login/login", "/login/Login.jsp", "/Login.jsp", "/manage", "/manage/login.htm", "/management", "/manager", "/manager.aspx", "/manager.do", "/manager.jsp", "/manager.jspx", "/manager.php", "/memadmin/index.php", "/myadmin/login.php", "/Systems/", "/user-login.html", "/wp-login.php":
		if reqlogin, err := util.HttpRequset(req.RequestUrl, "GET", "", true, nil); err == nil {
			if util.StrContains(reqlogin.Body, "<input") && (util.StrContains(reqlogin.Body, "pass") || util.StrContains(reqlogin.Body, "type=\"password\"") || strings.Contains(reqlogin.Body, "Pass") || strings.Contains(reqlogin.Body, "PASS")) {
				technologies = append(technologies, "AdminLoginPage")
				username, password, loginurl := Admin_brute(req.RequestUrl)
				if loginurl != "" {
					technologies = append(technologies, fmt.Sprintf("brute-admin|%s:%s", username, password))
				}
			}
		}
	case "/zabbix/":
		if util.StrContains(req.Body, "www.zabbix.com") {
			technologies = append(technologies, "zabbix")
		}
	case "/grafana/":
		if util.StrContains(req.Body, "grafana-app") {
			technologies = append(technologies, "Grafana")
		}
	case "/zentao/":
		if util.StrContains(req.Body, "zentao/theme") {
			technologies = append(technologies, "zentao")
		}
	case "/actuator", "/actuator/archaius", "/actuator/auditevents", "/actuator/autoconfig", "/actuator/bindings", "/actuator/caches", "/actuator/channels", "/actuator/conditions", "/actuator/configprops", "/actuator/env", "/actuator/env.json", "/actuator/health", "/actuator/health.json", "/actuator/heapdump", "/actuator/hystrix.stream", "/actuator/integrationgraph", "/actuator/mappings", "/actuator/metrics", "/actuator/routes", "/actuator/scheduledtasks", "/actuator/service-registry":
		technologies = append(technologies, "Spring env")
	case "/actuator/gateway/routes", "/actuator/gateway/globalfilters", "/actuator/gateway/routefilters":
		technologies = append(technologies, "Spring")
		technologies = append(technologies, "SpringGateway")
	case "/vendor/phpunit/phpunit/LICENSE", "/vendor/phpunit/phpunit/README_CN.md":
		technologies = append(technologies, "phpunit")
	case "/wp-config.php.bak", "/wp-content/debug.log", "/wp-content/uploads/dump.sql", "/wp-json/", "/wp-json/wp/v2/users", "/.wp-config.php.swp":
		technologies = append(technologies, "WordPress")
	}
	return technologies
}
