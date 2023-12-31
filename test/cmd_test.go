package test

import (
	"github.com/GhostTroops/scan4all/pkg/common"
	"github.com/GhostTroops/scan4all/pkg/tools"
	"github.com/GhostTroops/scan4all/pkg/utils"
	util "github.com/hktalent/go-utils"
	"log"
	"strings"
	"testing"
)

func TestDoCmdNode(t *testing.T) {
	util.InitConfigFile()
	var i = make(chan *string)
	s := "www.sina.com.cn"
	go func() {
		i <- &s
	}()

	common.DoCmd4Cbk("/usr/local/bin/ipgs -r", func(s *string) {
		if nil == s {
			return
		}
		var m = map[string]interface{}{}
		if err := util.Json.Unmarshal([]byte(*s), &m); nil == err {
			for _, x := range strings.Split("subject_an,subject_cn,subject_dn", ",") {
				tools.DoAorS(m[x], i, utils.TrimXx, "ipgs")
			}
		}
		log.Println(*s)
	}, i)
}
