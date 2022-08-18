package Funcs

import (
	"bufio"
	"log"
	"os"
	"strings"
)

func GetUrlFile(filename string) (urllist []string) {
	fp, err := os.Open(filename)
	if err != nil {
		log.Println("无法打开url文件")
		os.Exit(0)

	}
	defer fp.Close()
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		str := scanner.Text()
		str = strings.Replace(str, " ", "", -1)
		if str != "" {
			urllist = append(urllist, str)
		}

	}
	return urllist
}
