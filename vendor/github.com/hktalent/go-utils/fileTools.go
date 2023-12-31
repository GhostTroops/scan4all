package go_utils

import (
	"bufio"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	xj "github.com/hktalent/goxml2json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func Xml2Map(i io.Reader) *map[string]interface{} {
	if j1, err := xj.Convert(i); nil == err {
		var m1 = map[string]interface{}{}
		if err := Json.Unmarshal(j1.Bytes(), &m1); nil == err {
			return &m1
		}
	}
	return nil
}

// 处理目录遍历
func DoDirs(szDir string, doFile func(s string)) {
	filepath.WalkDir(szDir, func(s string, d os.DirEntry, e error) error {
		doFile(s)
		return nil
	})
}

// 读取多个文件，按行返回
func ReadFile4Line(a ...string) chan *string {
	var out = make(chan *string)
	go func() {
		defer close(out)
		for _, x := range a {
			if FileExists(x) {
				if fs, err := os.OpenFile(x, os.O_RDONLY, os.ModePerm); nil == err {
					scanner := bufio.NewScanner(fs)
					scanner.Buffer(make([]byte, MacLineSize), MacLineSize)
					for scanner.Scan() {
						value := strings.TrimSpace(scanner.Text())
						out <- &value
					}
				}
			}
		}
	}()
	return out
}

// 文件转 16进制字符串
func File2HexStr(s string) string {
	if data, err := os.ReadFile(s); nil == err {
		return fmt.Sprintf("%x", data)
	}
	return ""
}

// 16进制 字符串 转byte
func HexStr2Bytes(s string) []byte {
	if data, err := hex.DecodeString(s); nil == err {
		return data
	}
	return nil
}

// 追加到文件中
func AppendCsvFile(szFile string, a []string, f1 *os.File) *os.File {
	if nil == f1 {
		f, err := os.OpenFile(szFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
			return f
		}
		f1 = f
	}
	//defer f.Close()
	w := csv.NewWriter(f1)
	if err := w.Write(a); nil != err {
		log.Println(err)
	}
	w.Flush()
	return f1
}

func AppendFile(szFile string, data []byte, f1 *os.File) *os.File {
	if nil == f1 {
		f, err := os.OpenFile(szFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
			return f
		}
		f1 = f
	}
	//defer f.Close()
	buf := bufio.NewWriter(f1)
	if n, err := buf.Write(data); nil != err || n != len(data) {
		log.Println(err)
	}
	buf.Flush()

	return f1
}
