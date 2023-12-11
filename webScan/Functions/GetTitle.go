package Funcs

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	Configs "github.com/GhostTroops/scan4all/webScan/config"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Gettitle_result struct {
	rescode    int
	title_name string
	url        string
}

func url_handle(url []string) (urls []string) { //对原始url进行处理，判断是否http开头

	size := len(url)
	for i := 0; i < size; i++ {
		url[i] = strings.TrimSpace(url[i])
		url[i] = strings.TrimRight(url[i], "/")
		if !strings.HasPrefix(url[i], "http") {
			if strings.HasSuffix(url[i], "443") {
				url[i] = "https://" + url[i]
			} else {
				url[i] = "http://" + url[i]
			}

		}

		urls = append(urls, url[i])
	}
	return urls

}
func GetUrlTitle() {
	fp_succ, err := os.OpenFile("url_title.txt", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0660)
	fp_succ.WriteString("\n")
	fp_succ.WriteString("GetTitle is start........" + "\n")
	fp_succ.WriteString("\n")
	if err != nil {
		fmt.Println("GetUrlTitle open file err", err)
		return
	}
	var filename string
	if Configs.UserObject.File != "" {
		filename = Configs.UserObject.File
	}
	urllist := GetUrlFile(filename)
	title_urllist := url_handle(urllist) //已经修改过前缀的
	size := len(title_urllist)

	jobs_url := make(chan string, size+1)
	jobs_result := make(chan Gettitle_result, size+1)

	for i := 0; i < Configs.UserObject.ThreadNum; i++ {

		go GetUrlTitle_handle(jobs_url, jobs_result)

	}
	for i := 0; i < size; i++ {
		jobs_url <- title_urllist[i]
		fmt.Println(title_urllist[i])
	}
	for i := 0; i < size; i++ {

		res := <-jobs_result

		content := res.url + "\t" + res.title_name + "\t" + strconv.Itoa(res.rescode) + "\n"
		fmt.Println(content)
		fp_succ.WriteString(content)

	}

	defer fp_succ.Close()
}

// geg title
func GetUrlTitle_handle(urls <-chan string, Get_title_res chan<- Gettitle_result) {
	var res Gettitle_result
	var result_title string
	fnCbkGetTitle := func(Resp *http.Response, error_str string) {
		if error_str != "" {
			res.rescode = 999
			tmp_string := strings.Split(error_str, ":")
			res.title_name = tmp_string[len(tmp_string)-1]
		} else {
			if Resp == nil {
				res.rescode = 999
				res.title_name = "RespObject.Resp==nil"
			} else {
				body, err := ioutil.ReadAll(Resp.Body)
				if err != nil {
					fmt.Println("GetUrlTitle_handle func body is err..", err)
				} else {
					reg := regexp.MustCompile(`<title>(.+)?</title>`)
					if reg == nil {
						fmt.Println("MustCompile err")
					}
					res.rescode = Resp.StatusCode
					re_result := reg.FindAllStringSubmatch(string(body), -1)
					if re_result == nil {
						result_title = "未获取到标题"
					} else {
						result_title = re_result[0][1]
					}
					res.title_name = result_title
				}
			}
		}
	}
	for url := range urls {
		res.url = url
		GetTitleRequest(url, 5, fnCbkGetTitle)
		if strings.Contains(res.title_name, "400 The plain HTTP request was sent to HTTPS port") {
			tmp_url := url
			tmp_url = strings.Replace(tmp_url, "http://", "https://", 1)
			res.url = tmp_url
			GetTitleRequest(tmp_url, 5, fnCbkGetTitle)
		}
		Get_title_res <- res
	}
}

func GetTitleRequest(url string, timeout time.Duration, fnCbk func(resp *http.Response, str string)) {
	client := util.GetClient(url)
	var str string = ""
	client.Client.Timeout = time.Second * timeout
	client.DoGetWithClient4SetHd(client.Client, url, http.MethodPost, nil, func(resp *http.Response, err error, szU string) {
		if err != nil {
			str = err.Error()
		}
		fnCbk(resp, str)
	}, func() map[string]string {
		mhd1 := map[string]string{}
		mhd1["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36"
		return mhd1
	}, true)
}
