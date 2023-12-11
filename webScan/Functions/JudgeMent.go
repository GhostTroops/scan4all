package Funcs

import (
	"fmt"
	Configs "github.com/GhostTroops/scan4all/webScan/config"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

var mux sync.RWMutex

type params struct {
	Url         string //存放计数用的url
	Str_replace string //存放正则匹配后的结果
}

func regex_match(regex string, str string) string {

	re := regexp.MustCompile(regex)
	result := re.FindString(str)
	return result
}

func re_replace(str string, str_replace string) string {
	if str_replace == "" {
		return str
	}
	if strings.Contains(str, "{{replace{search}replace}}") {
		str = strings.ReplaceAll(str, "{{replace{search}replace}}", str_replace)
	}

	return str
}

func JudgeMent_OneUrl_OneJson(url string, oneExpjson Configs.ExpJson) bool {
	var paras params
	// 将Exp中的通配符替换为命令
	var str_replace string
	var RespObject Configs.HttpResult
	//判断是否多个url超时，如果是，则直接返回false，省的浪费时间
	ext_tmp := false //最外层判断是true还是false
	var JudgeStatus map[int]bool
	JudgeStatus = make(map[int]bool)
	final_true := false
	var filestruct Configs.FileNameStruct

	var ReqData *strings.Reader
	for key, value := range oneExpjson.Request {

		code_ststus := false
		//--------------正则替换
		value.Data = re_replace(value.Data, str_replace)
		//--------------替换结束
		ReqData = strings.NewReader(value.Data)
		whole_url := url + value.Uri //完整加路径的url
		filestruct.Name = value.Upload.Name
		filestruct.Filename = value.Upload.FileName
		filestruct.FilePath = value.Upload.FilePath
		//---正则替换
		whole_url = re_replace(whole_url, str_replace)
		filestruct.Name = re_replace(filestruct.Name, str_replace)
		filestruct.Filename = re_replace(filestruct.Filename, str_replace)
		filestruct.FilePath = re_replace(filestruct.FilePath, str_replace)
		//---正则替换结束

		paras.Url = url
		var head http.Header
		var status_code int
		if value.Upload.FilePath == "" {
			RespObject.Resp, status_code, head = Client(value.Method, whole_url, ReqData, value.Header, 5, value.Follow_redirects, paras) //最后一个url为原生url，用来统计是否不继续对该url发包
		} else {
			RespObject.Resp, status_code, head = UClient(value.Method, whole_url, filestruct, ReqData, value.Header, 5, value.Follow_redirects, paras)
		}

		if RespObject.Resp == nil {
			//log.Println("Http Do Request failed")
			return false
		} else {
			RespObject.Body = string(*RespObject.Resp)
			//fmt.Println(RespObject.Body)
			if value.Search != "" {
				if strings.HasPrefix("body:", value.Search) {
					value.Search = strings.TrimPrefix("body:", value.Search)
					paras.Str_replace = regex_match(value.Search, RespObject.Body)
				} else {
					if strings.HasPrefix("Set-Cookie:", value.Search) {
						str := head.Get("Set-Cookie")
						value.Search = strings.TrimPrefix("Set-Cookie:", value.Search)
						paras.Str_replace = regex_match(value.Search, str)
					}
					if strings.HasPrefix("Content-Type:", value.Search) {
						str := head.Get("Content-Type")
						value.Search = strings.TrimPrefix("Content-Type:", value.Search)
						paras.Str_replace = regex_match(value.Search, str)
					}
				}
			}
			CheckStatus := make([]map[string]interface{}, len(value.Response.Checks))

			if strings.ToLower(value.Response.Check_Steps) == `and` || strings.ToLower(value.Response.Check_Steps) == `or` {

				for id, chk_value := range value.Response.Checks {
					CheckStatus[id] = make(map[string]interface{})
					if chk_value.Operation == `contains` {
						if chk_value.Key != "" {

							CheckStatus[id][`contains`] = strings.Contains(head.Get(chk_value.Key), chk_value.Value)

						} else {
							CheckStatus[id][`contains`] = strings.Contains(RespObject.Body, chk_value.Value)
							// fmt.Print("id=", id)
							// fmt.Println("CheckStatus[id][`contains`]=", strings.Contains(RespObject.Body, chk_value.Value))
							if chk_value.Value == "renyizifumofamen" {
								CheckStatus[id][`contains`] = true
							}
						}

					}
					if chk_value.Operation == `code` {

						if fmt.Sprintf("%d", status_code) == chk_value.Value {
							code_ststus = true

						}
						if chk_value.Value == "" {
							code_ststus = true
						}
					}
				}

				length := len(CheckStatus)
				tmp := false

				for i := 0; i < length-1; i++ {

					if strings.ToLower(value.Response.Check_Steps) == `and` && code_ststus == true {

						if i == 0 {
							tmp = tmp || (CheckStatus[i][`contains`] == true)
						} else {
							tmp = tmp && (CheckStatus[i][`contains`] == true)
						}
					}

					if strings.ToLower(value.Response.Check_Steps) == `or` && code_ststus == true {
						tmp = tmp || (CheckStatus[i][`contains`] == true)
					}
				}
				ext_tmp = tmp
			}
		}
		if value.Next_decide == "" {
			if len(JudgeStatus) == 0 {
				return ext_tmp
			}
			JudgeStatus[key] = ext_tmp
		} else {
			JudgeStatus[key] = ext_tmp
		}

		// final_true = JudgeStatus[key]
		if key == 0 {
			final_true = JudgeStatus[key]
		}
	}

	for key, value := range oneExpjson.Request {
		if strings.ToLower(value.Next_decide) == "and" {
			final_true = final_true && JudgeStatus[key+1]
		}
		if strings.ToLower(value.Next_decide) == "or" {
			final_true = final_true || JudgeStatus[key+1]
		}
	}

	return final_true
}
