package goby

import (
	"embed"
	"io/ioutil"
	"log"
)

// 加载PoCs
func LoadPocs(Pocs embed.FS) chan<- string {
	var rst = make(chan string, 10000)
	var szPath string = "goby_pocs"
	entries, err := Pocs.ReadDir(szPath)
	if err == nil {
		go func() {
			defer close(rst)
			for _, v := range entries {
				szFl1 := szPath + "/" + v.Name()
				data, err := ioutil.ReadFile(szFl1)
				if nil == err {
					rst <- string(data)
				} else {
					log.Println("read ", szFl1, " is error ", err)
				}
			}
		}()
	} else {
		close(rst)
		log.Println("read ", szPath, " dir is error ", err)
	}
	return rst
}
