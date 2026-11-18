package fingerprint

import (
	"regexp"
	"strings"
)

// rule is one entry of the built-in fingerprint database. All configured
// criteria must match the selected probe (root or deep path). Header entries
// are ANDed; list entries (Server/Body/Title/Cookies) are ORed.
type rule struct {
	Name      string
	Weak      bool
	Shiro     bool
	Path      string
	Status    []int
	VersionRe string
	Headers   map[string][]string
	Server    []string
	Body      []string
	Title     []string
	Cookies   []string
}

func (r *rule) match(p *Probe) (string, bool) {
	if p == nil || p.Err != "" {
		return "", false
	}
	if len(r.Status) > 0 && !containsInt(r.Status, p.Status) {
		return "", false
	}
	evidence := ""
	for name, subs := range r.Headers {
		v := p.Header.Get(name)
		hit := ""
		for _, s := range subs {
			if containsFold(v, s) {
				hit = name + ": " + s
				break
			}
		}
		if hit == "" {
			return "", false
		}
		if evidence == "" {
			evidence = hit
		}
	}
	if len(r.Server) > 0 {
		tok, ok := containsAnyFold(p.Header.Get("Server"), r.Server)
		if !ok {
			return "", false
		}
		if evidence == "" {
			evidence = "Server: " + tok
		}
	}
	if len(r.Body) > 0 {
		body := p.Body
		// deep-path 探测时剔除路径本身的回显：Struts2 showcase 等 catch-all
		// 应用会把请求路径原样写回页面（200 + 含 "/solr/" 字样），仅凭
		// "Solr" 这类短特征必然误判。
		if r.Path != "" {
			body = strings.ReplaceAll(body, r.Path, "")
			body = strings.ReplaceAll(body, strings.TrimSuffix(r.Path, "/"), "")
		}
		tok, ok := containsAnyFold(body, r.Body)
		if !ok {
			return "", false
		}
		if evidence == "" {
			evidence = "body: " + tok
		}
	}
	if len(r.Title) > 0 {
		tok, ok := containsAnyFold(p.Title, r.Title)
		if !ok {
			return "", false
		}
		if evidence == "" {
			evidence = "title: " + tok
		}
	}
	if len(r.Cookies) > 0 {
		joined := strings.Join(p.Header.Values("Set-Cookie"), "\n")
		tok, ok := containsAnyFold(joined, r.Cookies)
		if !ok {
			return "", false
		}
		if evidence == "" {
			evidence = "cookie: " + tok
		}
	}
	return evidence, true
}

func (r *rule) version(p *Probe) string {
	if r.VersionRe == "" || p == nil {
		return ""
	}
	re, err := regexp.Compile(r.VersionRe)
	if err != nil {
		return ""
	}
	body := p.Body
	if len(body) > 2048 {
		body = body[:2048]
	}
	src := p.Header.Get("Server") + " " + p.Header.Get("X-Powered-By") + " " + p.Title + " " + body
	if m := re.FindStringSubmatch(src); len(m) > 1 {
		return m[1]
	}
	return ""
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func containsAnyFold(haystack string, needles []string) (string, bool) {
	h := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(h, strings.ToLower(n)) {
			return n, true
		}
	}
	return "", false
}

// rules is the built-in technology database. It focuses on components that
// have at least one exploit implemented by this scanner (plus a few common
// web stacks used by the bug-bounty probes).
var rules = []rule{
	// --- Java middleware -------------------------------------------------
	// Deep-path rules require a real component response: a 404 page that merely
	// echoes the requested path must not be treated as a fingerprint.
	{Name: "WebLogic", Path: "/console/login/LoginForm.jsp", Status: []int{200},
		Body: []string{"LoginForm"}, VersionRe: `WebLogic Server\s*([\d.]+)`},
	{Name: "WebLogic", Body: []string{"WebLogic Server"},
		VersionRe: `WebLogic Server\s*([\d.]+)`},

	{Name: "Tomcat", Server: []string{"Apache-Coyote", "Tomcat"},
		VersionRe: `Tomcat/([\d.]+)`},
	{Name: "Tomcat", Path: "/manager/html", Status: []int{200, 401, 403},
		Body: []string{"Tomcat Manager"}, VersionRe: `Tomcat/([\d.]+)`},
	// Server 头常被禁用（server="..." 置空），以默认首页文本识别
	{Name: "Tomcat", Body: []string{"Apache Tomcat/"}, VersionRe: `Apache Tomcat/([\d.]+)`},

	{Name: "Struts2", Body: []string{"struts2", "struts-tags", "com.opensymphony.xwork2", "Struts REST Showcase", "s2-0", "Struts2 Showcase"}},

	{Name: "Spring", Body: []string{"Whitelabel Error Page", "Spring Boot"}},
	{Name: "Spring", Path: "/actuator", Status: []int{200}, Body: []string{"_links"}},

	{Name: "Shiro", Shiro: true},

	{Name: "ActiveMQ", Status: []int{401}, Headers: map[string][]string{"WWW-Authenticate": {"ActiveMQRealm"}}},
	{Name: "ActiveMQ", Body: []string{"ActiveMQ"}},

	{Name: "Fastjson", Body: []string{"fastjson", "com.alibaba.fastjson"}},

	{Name: "Dubbo", Body: []string{"dubbo", "Dubbo"}},

	{Name: "Jenkins", Headers: map[string][]string{"X-Jenkins": {"."}}, VersionRe: `(?:X-Jenkins|Jenkins)\s*[:/ ]\s*([\d.]+)`},
	{Name: "Jenkins", Body: []string{"Jenkins"}},

	{Name: "Solr", Path: "/solr/", Status: []int{200, 302}, Body: []string{"Solr"}},
	{Name: "Solr", Body: []string{"Solr Admin", "Solr"}},
	{Name: "GeoServer", Path: "/geoserver/web/", Status: []int{200, 302}, Body: []string{"GeoServer"}},
	{Name: "GeoServer", Body: []string{"GeoServer"}},
	{Name: "OFBiz", Path: "/webtools/control/main", Status: []int{200, 302}, Body: []string{"OFBiz", "ofbiz"}},
	{Name: "OFBiz", Body: []string{"OFBiz"}},

	// --- Web frameworks / apps ------------------------------------------
	{Name: "ThinkPHP", Headers: map[string][]string{"X-Powered-By": {"ThinkPHP"}}, Body: []string{"ThinkPHP"}},
	{Name: "Laravel", Cookies: []string{"laravel_session"}, Body: []string{"Laravel"}},
	{Name: "Laravel", Body: []string{"Laravel"}},
	// 裸 "Confluence" 会误命中 Tomcat 默认页中的 cwiki.apache.org/confluence 链接，必须带 Atlassian 前缀
	{Name: "Confluence", Body: []string{"Atlassian Confluence"}},
	{Name: "Metabase", Body: []string{"Metabase"}},
	{Name: "Metabase", Path: "/api/session/properties", Status: []int{200},
		Body: []string{"setup-token", "metabase"}},
	{Name: "GitLab", Body: []string{"GitLab"}},
	{Name: "Gitea", Body: []string{"Gitea"}},
	{Name: "Nacos", Path: "/nacos/", Status: []int{200}, Body: []string{"nacos"}},
	{Name: "Kibana", Body: []string{"kibana", "Kibana"}},
	{Name: "Elasticsearch", Body: []string{"cluster_name", "You Know, for Search"}},
	{Name: "PaperCut", Body: []string{"PaperCut"}},
	{Name: "Rails", Headers: map[string][]string{"X-Runtime": {"."}}, Body: []string{"Rails"}},
	{Name: "Langroid", Body: []string{"Langroid", "TableChatAgent"}},
	{Name: "Langflow", Body: []string{"Langflow"}},
	{Name: "Chartbrew", Body: []string{"Chartbrew"}},
	{Name: "DataEase", Body: []string{"DataEase"}},
	{Name: "CraftCMS", Body: []string{"Craft CMS", "craftcms"}},
	{Name: "Cacti", Body: []string{"Cacti"}},
	{Name: "ComfyUI", Body: []string{"ComfyUI"}},
	{Name: "HertzBeat", Body: []string{"HertzBeat"}},
	{Name: "Cockpit", Title: []string{"Cockpit"}, Body: []string{"cockpit"}},
	{Name: "HugeGraph", Body: []string{"HugeGraph"}},
	{Name: "Gotenberg", Body: []string{"Gotenberg"}, Headers: map[string][]string{"X-Gotenberg": {"."}}},
	{Name: "NetScaler", Body: []string{"NetScaler"}, Cookies: []string{"NSC_"}},
	{Name: "vCenter", Body: []string{"vCenter", "vSphere Client"}},
	{Name: "SkyWalking", Body: []string{"SkyWalking", "skywalking"}},

	// --- Web servers / stacks (weak: never narrow the scan alone) --------
	{Name: "nginx", Weak: true, Server: []string{"nginx"}, VersionRe: `nginx/([\d.]+)`},
	{Name: "Apache", Weak: true, Server: []string{"Apache/", "httpd"},
		VersionRe: `(?:Apache|httpd)/([\d.]+)`},
	{Name: "Node.js", Weak: true, Headers: map[string][]string{"X-Powered-By": {"Express", "Node"}},
		Server: []string{"Node.js"}, VersionRe: `Node\.js/([\d.]+)`},
	{Name: "PHP", Weak: true, Headers: map[string][]string{"X-Powered-By": {"PHP"}},
		Body: []string{"PHP Version"}, Cookies: []string{"PHPSESSID"},
		VersionRe: `PHP/([\d.]+)`},
	{Name: "PHP", Weak: true, Body: []string{"PHP Version"}, VersionRe: `PHP ([\d.]+)`},
	{Name: "WordPress", Weak: true, Body: []string{"wp-content", "wp-includes"}},
}
