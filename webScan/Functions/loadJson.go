package Funcs

import (
	"encoding/json"
	"fmt"
	Configs "github.com/GhostTroops/scan4all/webScan/config"
	"io/ioutil"
	"log"
	"os"
)

func LoadExpJson(filepath string) {
	file, err := os.Open(filepath)
	if err != nil {
		log.Println("open " + filepath + " failed")
		os.Exit(1)
	}
	fileValue, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("read " + filepath + " body failed")
		os.Exit(1)
	}
	err = json.Unmarshal(fileValue, &Configs.ExpJsonMap)
	if err != nil {
		log.Println("Json file to load failed")
		os.Exit(1)
	}
}

func LoadExpJsonAll(filepath string) []byte {
	file, err := os.Open(filepath)
	if err != nil {
		log.Println("open " + filepath + " failed")
		os.Exit(1)
	}
	fileValue, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("read " + filepath + " body failed")
		os.Exit(1)
	}

	return fileValue
}

func LoadOneExpJson(filepath string, oneExpjson *Configs.ExpJson) {
	file, err := os.Open(filepath)
	if err != nil {
		log.Println(" LoadOneExpJson func open " + filepath + " failed")
		fmt.Println("LoadOneExpJson func open filepath err...")
	}
	fileValue, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println("LoadOneExpJson  read " + filepath + " body failed")
		fmt.Println("LoadOneExpJson func readAll err...")
	}
	err = json.Unmarshal(fileValue, oneExpjson)
	if err != nil {
		log.Println("LoadOneExpJson Json file to load failed")
		fmt.Println("LoadOneExpJson Json file to load failed")
	}
}
