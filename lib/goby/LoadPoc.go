package goby

import (
	"archive/zip"
	"bytes"
	"fmt"
	"log"
	"strings"
)

// LoadPocs 从内嵌的 goby_pocs.zip 中按照扩展名过滤加载 PoC 内容
// exts 为空时加载全部文件
func LoadPocs(data []byte, exts ...string) chan string {
	var rst = make(chan string, 10000)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if nil != err {
		close(rst)
		log.Println("open goby_pocs.zip error ", err)
		return rst
	}
	allow := func(name string) bool {
		if 0 == len(exts) {
			return true
		}
		for _, e := range exts {
			if strings.HasSuffix(strings.ToLower(name), strings.ToLower(e)) {
				return true
			}
		}
		return false
	}
	go func() {
		defer close(rst)
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || 0 == f.UncompressedSize64 || !allow(f.Name) {
				continue
			}
			rc, err := f.Open()
			if nil != err {
				log.Println("open ", f.Name, " is error ", err)
				continue
			}
			func() {
				defer rc.Close()
				var buf bytes.Buffer
				if _, err = buf.ReadFrom(rc); nil != err {
					log.Println("read ", f.Name, " is error ", err)
					return
				}
				rst <- fmt.Sprintf("%s\n%s", f.Name, buf.String())
			}()
		}
	}()
	return rst
}
