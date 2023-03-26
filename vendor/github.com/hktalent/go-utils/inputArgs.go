package go_utils

import (
	"bufio"
	"io"
	"log"
	"os"
	"strings"
)

func DoReadInputStream(r io.Reader, out chan *string) {
	buf := bufio.NewScanner(r)
	for buf.Scan() {
		if s := strings.TrimSpace(buf.Text()); s != "" {
			out <- &s
		}
	}
}

// 获取简单命令行输入
func GetSimpleInput() <-chan *string {
	var out = make(chan *string)
	go func() {
		defer close(out)
		if 1 < len(os.Args) {
			if FileExists(os.Args[1]) {
				if f, err := os.OpenFile(os.Args[1], os.O_RDONLY, os.ModePerm); nil == err {
					defer f.Close() //nolint
					DoReadInputStream(f, out)
				} else {
					log.Println("os.OpenFile ", os.Args[1], err)
				}
			} else {
				out <- &os.Args[1]
			}
		} else {
			DoReadInputStream(os.Stdin, out)
		}
	}()
	return out
}
