package apache

import (
	"github.com/GhostTroops/scan4all/lib/socket"
	"strings"
)

// ZookeeperUnauthority zookeeper 未授权
//
//	addr := args.Host + ":2181"
func ZookeeperUnauthority(szUrl string) bool {
	payload := "envidddfdsfsafafaerwrwerqwe"
	x1 := socket.NewCheckTarget(szUrl, "tcp", 10)
	defer x1.Close()
	_, err := x1.ConnTarget()
	if err != nil {
		return false
	}
	x1.WriteWithFlush(payload)
	s1 := *x1.ReadAll2Str()
	if "" != s1 && -1 < strings.Index(s1, "Environment") {
		return true
	}
	return false
}
