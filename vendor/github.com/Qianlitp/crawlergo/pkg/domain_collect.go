package pkg

import (
	"strings"

	"github.com/Qianlitp/crawlergo/pkg/model"
	mapset "github.com/deckarep/golang-set"
)

func SubDomainCollect(reqList []*model.Request, HostLimit string) []string {
	var subDomainList []string
	uniqueSet := mapset.NewSet()
	for _, req := range reqList {
		domain := req.URL.Hostname()
		if uniqueSet.Contains(domain) {
			continue
		}
		uniqueSet.Add(domain)
		if strings.HasSuffix(domain, "."+HostLimit) {
			subDomainList = append(subDomainList, domain)
		}
	}
	return subDomainList
}

func AllDomainCollect(reqList []*model.Request) []string {
	uniqueSet := mapset.NewSet()
	var allDomainList []string
	for _, req := range reqList {
		domain := req.URL.Hostname()
		if uniqueSet.Contains(domain) {
			continue
		}
		uniqueSet.Add(domain)
		allDomainList = append(allDomainList, req.URL.Hostname())
	}
	return allDomainList
}
