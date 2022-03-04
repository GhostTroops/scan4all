package brute

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func addfingerprints404(technologies []string, req *pkg.Response) []string {
	// StatusCode 404
	if strings.Contains(req.Body, "thinkphp") {
		technologies = append(technologies, "ThinkPHP")
	}
	if strings.Contains(req.Body, "Hypertext Transfer Protocol") {
		technologies = append(technologies, "WebLogic")
	}
	if strings.Contains(req.Body, "font-family:Tahoma,Arial,sans-serif") {
		technologies = append(technologies, "Apache Tomcat")
	}
	if strings.Contains(req.Body, "Whitelabel Error Page") {
		technologies = append(technologies, "Spring")
	}
	return technologies
}

func addfingerprints403(payload string, technologies []string) []string {
	// StatusCode 403
	switch payload {
	case "/Runtime/Logs/":
		technologies = append(technologies, "ThinkPHP")
	}
	return technologies
}

func addfingerprintsnormal(payload string, technologies []string, req *pkg.Response) []string {
	// StatusCode 200, 301, 302, 401, 500
	switch payload {
	case "/manager/html":
		if req.StatusCode == 401 && req.Header.Get("Www-Authenticate") != "" {
			technologies = append(technologies, "Apache Tomcat")
		}
	case "/console/login/LoginForm.jsp":
		if req.StatusCode == 200 && strings.Contains(req.Body, "Oracle") {
			technologies = append(technologies, "WebLogic")
		}
	case "/wls-wsat", "/wls-wsat/CoordinatorPortType", "/wls-wsat/CoordinatorPortType11", "/_async/AsyncResponseService", "/_async/AsyncResponseServiceSoap12", "/uddiexplorer/SearchPublicRegistries.jsp", "/ws_utc/config.do":
		if req.StatusCode == 200 && (strings.Contains(req.Body, "weblogic") || strings.Contains(req.Body, "www.bea.com")) {
			technologies = append(technologies, "WebLogic")
		}
	case "/jmx-console/":
		if req.StatusCode == 200 && strings.Contains(req.Body, "jboss.css") {
			technologies = append(technologies, "Jboss")
		}
	case "/seeyon/":
		if strings.Contains(req.Body, "/seeyon/common/") {
			technologies = append(technologies, "seeyon")
		}
	case "/admin", "/admin-console", "/admin.asp", "/admin.aspx", "/admin.do", "/admin.html", "/admin.jsp", "/admin.php", "/admin/", "/admin/admin", "/admin/adminLogin.do", "/admin/checkLogin.do", "/admin/index.do", "/Admin/Login", "/admin/Login.aspx", "/admin/login.do", "/admin/menu", "/Adminer", "/adminer.php", "/administrator", "/adminLogin.do", "/checkLogin.do", "/doc/page/login.asp", "/login", "/Login.aspx", "/login/login", "/login/Login.jsp", "/manage", "/manage/login.htm", "/management", "/manager", "/manager.aspx", "/manager.do", "/manager.jsp", "/manager.jspx", "/manager.php", "/memadmin/index.php", "/myadmin/login.php", "/Systems/", "/user-login.html", "/wp-login.php":
		if reqlogin, err := pkg.HttpRequset(req.RequestUrl, "GET", "", true, nil); err == nil {
			if strings.Contains(reqlogin.Body, "<input") && (strings.Contains(reqlogin.Body, "pass") || strings.Contains(reqlogin.Body, "Pass") || strings.Contains(reqlogin.Body, "PASS")) {
				technologies = append(technologies, "AdminLoginPage")
				username, password, loginurl := Admin_brute(req.RequestUrl)
				if loginurl != "" {
					technologies = append(technologies, fmt.Sprintf("brute-admin|%s:%s", username, password))
				}
			}
		}
	case "/zabbix/":
		if strings.Contains(req.Body, "www.zabbix.com") {
			technologies = append(technologies, "zabbix")
		}
	case "/grafana/":
		if strings.Contains(req.Body, "grafana-app") {
			technologies = append(technologies, "Grafana")
		}
	case "/zentao/":
		if strings.Contains(req.Body, "zentao/theme") {
			technologies = append(technologies, "zentao")
		}
	case "/actuator", "/actuator/archaius", "/actuator/auditevents", "/actuator/autoconfig", "/actuator/bindings", "/actuator/caches", "/actuator/channels", "/actuator/conditions", "/actuator/configprops", "/actuator/env", "/actuator/env.json", "/actuator/health", "/actuator/health.json", "/actuator/heapdump", "/actuator/hystrix.stream", "/actuator/integrationgraph", "/actuator/mappings", "/actuator/metrics", "/actuator/routes", "/actuator/scheduledtasks", "/actuator/service-registry":
		technologies = append(technologies, "Spring")
	case "/actuator/gateway/routes", "/actuator/gateway/globalfilters", "/actuator/gateway/routefilters":
		technologies = append(technologies, "Spring")
		technologies = append(technologies, "SpringGateway")
	case "/vendor/phpunit/phpunit/LICENSE", "/vendor/phpunit/phpunit/README.md":
		technologies = append(technologies, "phpunit")
	case "/wp-config.php.bak", "/wp-content/debug.log", "/wp-content/uploads/dump.sql", "/wp-json/", "/wp-json/wp/v2/users", "/.wp-config.php.swp":
		technologies = append(technologies, "WordPress")
	}
	return technologies
}
