package Funcs

import (
	Configs "github.com/GhostTroops/scan4all/webScan/config"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"strings"
)

func fuzzfile(name string, file string) [][]string {
	fuzzObj := regexp.MustCompile(`(?i).*?` + file + `.*.json`)
	if fuzzObj == nil {
		log.Println("failed to get regexp object")
		//os.Exit(1)
		return nil
	}
	result := fuzzObj.FindAllStringSubmatch(name, -1)
	return result
}
func FindFile(path, keyworld string) {
	if keyworld != "" {
		fileList, err := ioutil.ReadDir(path)
		if err != nil {
			log.Println("Failed to get the underlying directory results")
			return
		}
		for _, file := range fileList {
			if file.IsDir() {
				FindFile(path+file.Name()+"/", keyworld)
			} else {
				result := fuzzfile(file.Name(), keyworld)
				//.Println("result=", result)
				if len(result) > 0 {

					Configs.FindReslt = append(Configs.FindReslt, path+"/"+result[0][0])
				}
			}
		}
		PrintFindResult(Configs.FindReslt)
	}
	Configs.FindReslt = nil
}

// 搜索所有的json格式文件
func FindFileAllJson(pathname string, FindResltAllJson []string) ([]string, error) { //s用于存储临时环境

	fromSlash := filepath.FromSlash(pathname)
	rd, err := ioutil.ReadDir(pathname)

	if err != nil {
		return FindResltAllJson, err
	}

	for _, fi := range rd {
		if fi.IsDir() {
			fullDir := filepath.Join(fromSlash, fi.Name())
			FindResltAllJson, err = FindFileAllJson(fullDir, FindResltAllJson)
			if err != nil {
				return FindResltAllJson, err
			}
		} else {
			filename := filepath.Join(fromSlash, fi.Name())
			FindResltAllJson = append(FindResltAllJson, filename)
		}
	}

	return FindResltAllJson, nil
}

func PrintFindResult(Result []string) {
	for _, value := range Result {
		values := strings.ReplaceAll(value, "//", "/")
		log.Println("[+] " + values)
	}
}
