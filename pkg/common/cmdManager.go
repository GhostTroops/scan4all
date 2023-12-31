package common

import util "github.com/hktalent/go-utils"

var cmdMg = map[string]chan *string{}

func GetCmd(szCmd string) chan *string {
	var lk = util.GetLock(szCmd + "_GetCmd").Lock()
	defer lk.Unlock()
	return cmdMg[szCmd]
}

func RegCmd(szCmd string, cmd chan *string) {
	var lk = util.GetLock(szCmd + "_RegCmd").Lock()
	defer lk.Unlock()
	if nil == cmd {
		delete(cmdMg, szCmd)
	} else {
		cmdMg[szCmd] = cmd
	}
}
