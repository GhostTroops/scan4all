package structs

import "strings"

var (
	CeyeApi    string
	CeyeDomain string
)

func InitCeyeApi(api, domain string) bool {
	if api == "" || domain == "" || !strings.HasSuffix(domain, ".ceye.io") {
		return false
	}
	CeyeApi = api
	CeyeDomain = domain
	return true
}
