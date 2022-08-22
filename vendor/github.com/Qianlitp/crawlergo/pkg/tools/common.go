package tools

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Qianlitp/crawlergo/pkg/logger"
)

func StrMd5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func ConvertHeaders(h map[string]interface{}) map[string]string {
	a := map[string]string{}
	for key, value := range h {
		a[key] = value.(string)
	}
	return a
}

func WriteFile(fileName string, content []byte) {
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		defer f.Close()
		_, err = f.Write(content)
		if err != nil {
			logger.Logger.Error("write to file error ", err)
		}
	}
}

func ReadFile(filePath string) []string {
	filePaths := []string{}
	f, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		defer f.Close()
		rd := bufio.NewReader(f)
		for {
			line, err := rd.ReadString('\n')
			if err != nil || io.EOF == err {
				break
			}
			filePaths = append(filePaths, line)
		}
	}
	return filePaths
}

func StringSliceContain(data []string, item string) bool {
	for _, value := range data {
		if value == item {
			return true
		}
	}
	return false
}

func MapStringFormat(data map[string]string) string {
	str := ""
	for key, value := range data {
		str += fmt.Sprintf("%s=%s,", key, value)
	}
	str = strings.Trim(str, ",")
	return str
}
