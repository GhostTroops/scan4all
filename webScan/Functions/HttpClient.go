package Funcs

import (
	"bytes"
	"github.com/GhostTroops/scan4all/lib/util"
	Configs "github.com/GhostTroops/scan4all/webScan/config"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"sync"
	"time"
)

var muxs sync.RWMutex

func Client(method string, url string, body io.Reader, Headers map[string]string, timeout time.Duration, redirects string, paras params) (resp *[]byte, status_code int, head http.Header) {
	muxs.Lock()
	timeout_count := &Extra.timeout_count
	if _, ok := (*timeout_count)[paras.Url]; ok {
		if (*timeout_count)[paras.Url] > 5 {
			muxs.Unlock()
			return nil, 0, nil
		}
	}
	muxs.Unlock()
	client := util.GetClient(url)
	if nil == client.Client {
		client.Client = client.GetClient(nil)
	}

	if redirects == "true" {
		client.Client.CheckRedirect = nil
	}
	client.Client.Timeout = timeout
	client.DoGetWithClient4SetHd(client.Client, url, method, body, func(resp1 *http.Response, err error, szU string) {
		if nil != err {
			muxs.Lock()
			(*timeout_count)[paras.Url] = (*timeout_count)[paras.Url] + 1
			muxs.Unlock()
		} else if nil != resp1 {
			resp2, err1 := ioutil.ReadAll(resp1.Body)
			err = err1
			resp = &resp2
			status_code = resp1.StatusCode
			head = resp1.Header
		}
	}, func() map[string]string {
		mhd1 := map[string]string{}
		for key, value := range Headers {
			key = re_replace(key, paras.Str_replace)
			value = re_replace(value, paras.Str_replace)
			mhd1[key] = value
		}
		return mhd1
	}, true)
	return resp, status_code, head
}

func UClient(method, url string, filestruct Configs.FileNameStruct, body io.Reader, Headers map[string]string, timeout time.Duration, redirects string, paras params) (resp *[]byte, status_code int, head http.Header) {
	muxs.Lock()
	timeout_count := &Extra.timeout_count
	if _, ok := (*timeout_count)[paras.Url]; ok {
		if (*timeout_count)[paras.Url] > 5 {
			muxs.Unlock()
			return resp, 0, nil
		}
	}
	muxs.Unlock()
	client := util.GetClient(url)
	if redirects == "true" {
		client.Client.CheckRedirect = nil
	}
	client.Client.Timeout = timeout
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
	client.DoGetWithClient4SetHd(client.Client, url, http.MethodPost, bodyBuf, func(resp1 *http.Response, err error, szU string) {
		if nil != err {
			muxs.Lock()
			(*timeout_count)[paras.Url] = (*timeout_count)[paras.Url] + 1
			muxs.Unlock()
		} else {
			resp2, err1 := ioutil.ReadAll(resp1.Body)
			err = err1
			resp = &resp2
			status_code = resp1.StatusCode
			head = resp1.Header
		}
	}, func() map[string]string {
		mhd1 := map[string]string{}
		for key, value := range Headers {
			key = re_replace(key, paras.Str_replace)
			value = re_replace(value, paras.Str_replace)
			mhd1[key] = value
		}
		mhd1["Content-Type"] = contentType
		return mhd1
	}, true)
	return resp, status_code, head
}
