package Funcs

import (
	"encoding/json"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	Configs "github.com/GhostTroops/scan4all/webScan/config"
	"log"
)

type results struct {
	res bool
	url string
}

type all_result struct {
	res      []bool
	exp_name []string
	url      string
}

func GetAllJson() []Configs.ExpJson {
	FindResltAllJson := []string{}
	FindResltAllJson, _ = FindFileAllJson(Configs.ConfigJsonMap.Exploit.Path, FindResltAllJson)
	// 所有的json文件
	//for _, filename := range FindResltAllJson {
	//	fmt.Println(filename)
	//}
	size := len(FindResltAllJson)
	var AllExpJsonContent []Configs.ExpJson = make([]Configs.ExpJson, size)
	for i := 0; i < size; i++ {
		filevalue := LoadExpJsonAll(FindResltAllJson[i]) //获取每个输入json文件的内容

		var expjson Configs.ExpJson
		err := json.Unmarshal(filevalue, &expjson) //将每个json文件内容放到结构体数组中
		AllExpJsonContent[i] = expjson
		//	fmt.Println(AllExpJsonContent[i])  详细每个json的内容
		if err != nil {
			log.Println("Json file to load failed")
			continue
		}
	}
	return AllExpJsonContent //用于存放 返回的所有json内容
}

func All_url_one_Json(oneExpjson Configs.ExpJson, urls <-chan string, result chan<- results, timeout_count map[string]int) {
	for url := range urls {
		var res results
		res.url = url
		res.res = JudgeMent_OneUrl_OneJson(url, oneExpjson)
		result <- res
	}
}

func final_One_url_allJson(timeout_count map[string]int) {
	AllExpJsonContent := GetAllJson()
	size := len(AllExpJsonContent)
	result := false
	for i := 0; i < size; i++ {
		result = JudgeMent_OneUrl_OneJson(Configs.UserObject.OriAddr, AllExpJsonContent[i])
		if result == true {
			util.SendLog(Configs.UserObject.OriAddr, "webScan", AllExpJsonContent[i].Name, "")
		}
	}
}

func final_Oneurl_OneJson(timeout_count map[string]int) {
	var oneExpjson Configs.ExpJson
	LoadOneExpJson(Configs.UserObject.JsonFile, &oneExpjson)

	status := JudgeMent_OneUrl_OneJson(Configs.UserObject.OriAddr, oneExpjson)

	log.Println("status=", status)
	if status == true {
		util.SendLog(Configs.UserObject.OriAddr, "webScan", oneExpjson.Name, "")
		log.Println(Configs.UserObject.OriAddr + "\t" + oneExpjson.Name + "\t" + "Exploit Success !" + "\n")
	} else {
		fmt.Println(Configs.UserObject.OriAddr + "\t" + oneExpjson.Name + "\t" + "Exploit Failed !" + "\n")
	}
}

func final_ALLurl_OneJson(timeout_count map[string]int) {

	filename := Configs.UserObject.File

	urllist := GetUrlFile(filename)
	size := len(urllist)
	result := make(chan results, size+1)

	//results := make(chan bool, size+1)
	jobs_url := make(chan string, size+1)
	var oneExpjson Configs.ExpJson
	LoadOneExpJson(Configs.UserObject.JsonFile, &oneExpjson) //载入一个expjson
	for i := 0; i < Configs.UserObject.ThreadNum; i++ {
		go All_url_one_Json(oneExpjson, jobs_url, result, timeout_count)
	}

	for i := 0; i < size; i++ {
		jobs_url <- urllist[i]
	}

	for i := 0; i < size; i++ {

		res := <-result

		if res.res == true {
			util.SendLog(res.url, "webScan", oneExpjson.Name, "")
		}
	}

}

//---------------------------------------------------------------------------------

func All_url_ALLjson(urls <-chan string, allresult chan<- all_result) {
	tmp_result := false
	AllExpJsonContent := GetAllJson()
	for url := range urls {
		var res all_result
		res.url = url
		for _, expjsoncontent := range AllExpJsonContent {
			tmp_result = JudgeMent_OneUrl_OneJson(url, expjsoncontent)
			res.res = append(res.res, tmp_result)
			res.exp_name = append(res.exp_name, expjsoncontent.Name)
		}
		allresult <- res
	}
}

func final_ALLurl_ALLJson(urllist *[]string) {
	if Configs.UserObject.AllJson == true {
		size := len(*urllist)
		allresult := make(chan all_result)
		//results := make(chan bool, size+1)
		jobs_url := make(chan string)
		for i := 0; i < Configs.UserObject.ThreadNum; i++ {
			util.DoSyncFunc(func() {
				All_url_ALLjson(jobs_url, allresult)
			})
		}
		for i := 0; i < size; i++ {
			jobs_url <- (*urllist)[i]
		}
		close(jobs_url) // send over close
		i := 0
		for res := range allresult {
			i++
			for key, res_tmp := range res.res {
				if res_tmp == true {
					util.SendLog(res.url, "webScan", res.exp_name[key], "")
				}
			}
			if i >= size {
				close(allresult)
				break
			}
		}
	}
}
