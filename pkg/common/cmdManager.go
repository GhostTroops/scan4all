package common

import (
	util "github.com/hktalent/go-utils"
	"os"
	"sync"
)

var cmdMg = map[string]chan *string{}

// 获取临时的输出文件名
func GetOutTmpFile(ext string) string {
	if fs, err := os.CreateTemp("", "51pwn.*."+ext); nil == err {
		fs.Close()
		return fs.Name()
	}
	return ""
}

/*
从 chan 流中创建临时文件
问题：临时文件允许一遍写入、一遍读取吗？
*/
func GetTmpFile(i chan *string, ext string) string {
	if fs, err := os.CreateTemp("", "51pwn.*."+ext); nil == err {
		defer fs.Close()
		for s := range i {
			if nil != s && "" != *s {
				fs.WriteString(*s + "\n")
			}
		}
		return fs.Name()
	}
	return ""
}

// 片段 重用
func WriteOne(Nrp *map[string]bool, y string, fs *os.File) {
	if !(*Nrp)[y] {
		(*Nrp)[y] = true
		fs.WriteString(y + "\n")
	}
}
func GetIpTmpFile(i chan *string, ext string) string {
	if fs, err := os.CreateTemp("", "51pwn.*."+ext); nil == err {
		defer fs.Close()
		var Nrp = map[string]bool{}
		for s := range i {
			if nil != s && "" != *s {
				if util.IsIp(*s) {
					WriteOne(&Nrp, *s, fs)
				} else if a := util.GetIps(*s); nil != a && 0 < len(a) {
					for _, y := range a {
						WriteOne(&Nrp, y, fs)
					}
				}
			}
		}
		return fs.Name()
	}
	return ""
}

var _GetCmd sync.Mutex

func GetCmd(szCmd string) chan *string {
	_GetCmd.Lock()
	defer _GetCmd.Unlock()
	return cmdMg[szCmd]
}

func RegCmd(szCmd string, cmd chan *string) {
	_GetCmd.Lock()
	defer _GetCmd.Unlock()
	if nil == cmd {
		cmdMg[szCmd] = nil
		delete(cmdMg, szCmd)
	} else {
		cmdMg[szCmd] = cmd
	}
}
