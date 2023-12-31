package go_utils

import (
	"bytes"
	"io"
	"log"
	"strings"
)

// 读取流，逐行 cbk
// 为什么这样封装？因为基于buf的行受限长度
func ReadStream4Line(r1 io.Reader, cbk func(*string)) {
	var data []byte
	var td = make([]byte, 10240)
	var lSp = []byte("\n")
	var i int
	var err error
	for {
		if i, err = r1.Read(td); err == nil {
			if 0 < i {
				data = append(data, td[0:i]...)
				a11 := bytes.Split(data, lSp)
				if 1 < len(a11) {
					for y, x9 := range a11 {
						// 保留最后一个
						if y == len(a11)-1 && '\n' != data[len(data)-1] {
							data = x9
							break
						}
						line := string(x9)
						cbk(&line)
					}
				}
			}
		} else if err == io.EOF {
			break
		} else {
			if 0 < i {
				data = append(data, td[0:i]...)
			}
			log.Println(err)
			break
			//if strings.Contains(fmt.Sprintf("%v", err), "already closed") {
			//	break
			//}
		}
	}
	if nil != data && 0 < len(data) {
		for _, line := range strings.Split(string(data), "\n") {
			cbk(&line)
		}
	}
	cbk(nil)
}
