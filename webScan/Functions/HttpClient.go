package Funcs

import (
	"bytes"
	"crypto/tls"
	"fmt"
	Configs "github.com/hktalent/scan4all/webScan/config"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"sync"
	"time"
)

var muxs sync.RWMutex

func Client(method string, url string, body io.Reader, Headers map[string]string, timeout time.Duration, redirects string, paras params) (resp *http.Response) {
	timeout_count := &Extra.timeout_count

	_, ok := (*timeout_count)[paras.Url]
	if ok {
		var resp *http.Response
		if (*timeout_count)[paras.Url] > 5 {
			return resp
		}
	}

	var client *http.Client
	//这里是转换为了使用https
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	if redirects == "true" {
		client = &http.Client{Timeout: time.Second * timeout, Transport: tr}
	} else {
		client = &http.Client{Timeout: time.Second * timeout, Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		fmt.Println("httpRequest err", err)
	}

	//遍历添加每个header 头
	muxs.Lock()
	for key, value := range Headers {
		key = re_replace(key, paras.Str_replace)
		value = re_replace(value, paras.Str_replace)
		req.Header.Add(key, value)
	}
	muxs.Unlock()
	//--------------------------------------
	//ExpJson := &Configs.ExpJson{}
	//fmt.Println(ExpJson)
	//------------------------------------
	resp, err2 := client.Do(req)

	if err2 != nil {
		muxs.Lock()
		(*timeout_count)[paras.Url] = (*timeout_count)[paras.Url] + 1
		muxs.Unlock()
		fmt.Println("Client.Do err", err2)

	}

	return resp
}

func UClient(method, url string, filestruct Configs.FileNameStruct, body io.Reader, Headers map[string]string, timeout time.Duration, redirects string, paras params) (resp *http.Response) {
	timeout_count := &Extra.timeout_count
	_, ok := (*timeout_count)[paras.Url]
	if ok {
		//var resp *http.Response
		if (*timeout_count)[paras.Url] > 5 {
			return resp
		}

	}

	var client *http.Client
	//这里是转换为了使用https
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	if redirects == "true" {
		client = &http.Client{Timeout: time.Second * timeout, Transport: tr}
	} else {
		client = &http.Client{Timeout: time.Second * timeout, Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}
	}
	//client := http.Client{} //原本就一句client
	bodyBuf := &bytes.Buffer{}
	bodyWrite := multipart.NewWriter(bodyBuf)
	file, err2 := os.Open(filestruct.FilePath)
	if err2 != nil {
		log.Println("Can't Open " + filestruct.FilePath + "file")
		return
	}
	defer file.Close()
	fileWrite, err := bodyWrite.CreateFormFile(filestruct.Name, filestruct.Filename)
	if err != nil {
		log.Println("CreateFormFile Failed,It will create HTTP Header")
		log.Println("form-Config;name=" + filestruct.Name + ";filename=" + filestruct.Filename)
		return
	}
	_, err = io.Copy(fileWrite, file)
	if err != nil {
		log.Println("Copy file body to buffer failed")
		return
	}
	bodyWrite.Close()
	// 创建请求
	contentType := bodyWrite.FormDataContentType()
	request, err := http.NewRequest(http.MethodPost, url, bodyBuf)
	if err != nil {
		log.Println("Create http Request failed")
		return
	}
	log.Println(url)
	request.Header.Set("Content-Type", contentType)
	muxs.Lock()
	for key, value := range Headers {
		key = re_replace(key, paras.Str_replace)
		value = re_replace(value, paras.Str_replace)
		request.Header.Add(key, value)
		//fmt.Println(key, value)
	}
	muxs.Unlock()
	resp, err4 := client.Do(request)

	if err4 != nil {
		log.Println("Http Client do Request failed")
		muxs.Lock()
		(*timeout_count)[paras.Url] = (*timeout_count)[paras.Url] + 1
		muxs.Unlock()
	}

	return resp
}
