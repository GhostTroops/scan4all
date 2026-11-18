package fingerprint

// componentCVEs maps a detected component to the CVEs this scanner can
// blind-test. Keep this table in sync with the exploit implementations and
// with the CVE matrix in README.md.
var componentCVEs = map[string][]string{
	"WebLogic": {
		"CVE-2026-70748", "CVE-2026-60672", "CVE-2026-35301", "CVE-2023-21839",
		"CVE-2020-14882", "CVE-2020-2883", "CVE-2017-10271", "CVE-2019-2725",
		"CVE-2019-2729", "CVE-2015-4852", "CVE-2016-0638", "CVE-2016-3510",
		"CVE-2018-2894",
	},
	"Tomcat": {"CVE-2017-12615", "CVE-2025-24813"},
	"Struts2": {
		"CVE-2024-53677", "CVE-2023-50164", "CVE-2020-17530", "CVE-2019-0230", "CVE-2018-11776",
		"CVE-2017-12611", "CVE-2017-9791", "CVE-2017-5638", "CVE-2017-9805",
		"CVE-2016-3081", "CVE-2013-2251",
		"CVE-2013-2134", "CVE-2013-2135", "CVE-2013-1966", "CVE-2013-1965",
		"CVE-2012-0391", "CVE-2011-3923", "CVE-2010-1870",
	},
	"Spring":        {"CVE-2022-22963", "CVE-2022-22947", "CVE-2022-22965", "CVE-2021-44228"},
	"Shiro":         {"CVE-2016-4437", "CVE-2020-1957", "CVE-2010-3863"},
	"ActiveMQ":      {"CVE-2026-34197", "CVE-2023-46604"},
	"Fastjson":      {"CVE-2017-18349", "Fastjson-1.2.45"},
	"ThinkPHP":      {"CVE-2018-20062"},
	"Laravel":       {"CVE-2021-3129"},
	"PHP":           {"CVE-2017-9841", "CVE-2012-1823", "CVE-2024-4577", "CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"},
	"PHPUnit":       {"CVE-2017-9841"},
	"Webmin":        {"CVE-2019-15107"},
	"Shellshock":    {"CVE-2014-6271"},
	"Jenkins":       {"CVE-2018-1000861", "CVE-2024-23897"},
	"Drupal":        {"CVE-2018-7600"},
	"GitList":       {"CVE-2018-1000533"},
	"OpenTSDB":      {"CVE-2020-35476"},
	"H2Console":     {"CVE-2022-23221"},
	"MongoExpress":  {"CVE-2019-10758"},
	"Nexus":         {"CVE-2019-7238"},
	"JimuReport":    {"CVE-2023-4450"},
	"Solr":          {"CVE-2017-12629", "CVE-2021-44228"},
	"Kibana":        {"CVE-2019-7609", "CVE-2018-17246"},
	"nginx":         {"CVE-2026-42945", "CVE-2026-42533", "CVE-2026-15176", "CVE-2026-93479"},
	"Apache":        {"CVE-2021-41773", "CVE-2021-42013", "CVE-2026-23918", "CVE-2024-38475", "CVE-2024-38476"},
	"Nacos":         {"CVE-2021-29441"},
	"Node.js":       {"CVE-2026-111497"},
	"GitLab":        {"CVE-2021-22205", "CVE-2026-97229"},
	"Confluence":    {"CVE-2023-22527", "CVE-2022-26134", "CVE-2021-26084"},
	"Metabase":      {"CVE-2023-38646"},
	"Dubbo":         {"CVE-2019-17564"},
	"GeoServer":     {"CVE-2024-36401"},
	"OFBiz":         {"CVE-2023-51467", "CVE-2024-45195"},
	"PaperCut":      {"CVE-2023-27350"},
	"Rails":         {"CVE-2026-66066"},
	"Langroid":      {"CVE-2026-54769"},
	"NetScaler":     {"CVE-2026-88771", "CVE-2026-88772"},
	"vCenter":       {"CVE-2026-59310"},
	"HugeGraph":     {"CVE-2024-27348"},
	"Langflow":      {"CVE-2026-33017"},
	"Chartbrew":     {"CVE-2026-25887"},
	"WordPress":     {"CVE-2026-63030", "CVE-2026-60137"},
	"Gotenberg":     {"CVE-2026-40281"},
	"DataEase":      {"CVE-2025-32966"},
	"CraftCMS":      {"CVE-2025-32432", "CVE-2024-56145"},
	"ingress-nginx": {"CVE-2025-1974"},
	"Cacti":         {"CVE-2025-24367"},
	"ComfyUI":       {"CVE-2025-67303"},
	"HertzBeat":     {"CVE-2024-42323"},
	"Redis":         {"CVE-2022-0543"},
	"OpenSSH":       {"CVE-2024-6387"},
	"Cockpit":       {"CVE-2026-4631"},
	"Next.js":       {"CVE-2025-55182", "CVE-2025-29927"},
	"nginxWebUI":    {"CVE-2024-3737"},
}

// ComponentCVEs returns a copy of the CVE list mapped to a component.
func ComponentCVEs(name string) []string {
	src := componentCVEs[name]
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}
