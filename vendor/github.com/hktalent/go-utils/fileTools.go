package go_utils

import (
	"bufio"
	"encoding/csv"
	"log"
	"os"
)

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
