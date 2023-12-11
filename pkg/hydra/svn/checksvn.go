package svn

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
)

func Check(Host, Username, Password string, Port int) (bool, error) {
	szUlr := fmt.Sprintf("https://%s:%s@%s:%d", Username, Password, Host, Port)
	util.PocCheck_pipe <- &util.PocCheck{
		Wappalyzertechnologies: &[]string{"basic"},
		URL:                    szUlr,
		FinalURL:               szUlr,
		Checklog4j:             false,
	}
	return false, nil
}
