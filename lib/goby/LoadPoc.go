package goby

import (
	"archive/zip"
	"bytes"
	"embed"
	"io"
	"log"
)

// 加载PoCs
func LoadPocs(Pocs embed.FS) <-chan string {
	var rst = make(chan string, 10000)
	data, err := Pocs.ReadFile("goby_pocs.zip")
	if err != nil {
		close(rst)
		log.Println("read goby_pocs.zip is error:", err)
		return rst
	}

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		close(rst)
		log.Println("open goby_pocs.zip is error:", err)
		return rst
	}

	go func() {
		defer close(rst)
		for _, file := range reader.File {
			if file.FileInfo().IsDir() {
				continue
			}
			rc, err := file.Open()
			if err != nil {
				log.Println("open", file.Name, "is error:", err)
				continue
			}
			content, err := io.ReadAll(rc)
			closeErr := rc.Close()
			if err != nil {
				log.Println("read", file.Name, "is error:", err)
				continue
			}
			if closeErr != nil {
				log.Println("close", file.Name, "is error:", closeErr)
				continue
			}
			rst <- string(content)
		}
	}()
	return rst
}
