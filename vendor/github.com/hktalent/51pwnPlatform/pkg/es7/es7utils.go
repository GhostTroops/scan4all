package es7

import (
	"bytes"
	"context"
	"encoding/json"
	elasticsearch7 "github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/hktalent/51pwnPlatform/pkg/util"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

type Es7Utils struct {
	Client *elasticsearch7.Client
}

var es7 *Es7Utils

func NewEs7() *Es7Utils {
	if nil != es7 {
		return es7
	}
	//time.Now()
	client, err := elasticsearch7.NewClient(elasticsearch7.Config{
		Addresses: []string{"http://localhost:9200"},
		//Username:  "username",
		//Password:  "password",
	})
	if err != nil {
		log.Println(err)
		return nil
	}
	es7 = &Es7Utils{Client: client}
	return es7
}

// get strutct name to index name
func (es7 *Es7Utils) GetIndexName(t1 any) string {
	return strings.ToLower(reflect.TypeOf(t1).Name() + "_index")
}

func GetCount(url, index, field string) (int, error) {
	req, err := http.NewRequest("POST", url+"/"+index+"/_search?size=0&track_total_hits=true", nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15")
		req.Header.Add("Cache-Control", "no-cache")
		req.Header.Add("Content-Type", "application/json; charset=UTF-8")
		szSendData := `{
  "aggs" : {
    "types_count" : { "value_count" : { "field" : "` + field + `" } }
  }
		}`

		req.Header.Add("Content-Length", strconv.Itoa(len([]byte(szSendData))))
		// keep-alive
		req.Header.Add("Connection", "close")
		req.Close = true
		req.Body = io.NopCloser(strings.NewReader(szSendData))

		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			defer resp.Body.Close() // resp 可能为 nil，不能读取 Body
		}
		if err != nil {
			return 0, err
		}
		s1, err := ioutil.ReadAll(resp.Body)
		if nil != err {
			return 0, err
		} else {
			var m1 map[string]interface{}
			json.Unmarshal(s1, &m1)
			n1 := util.GetJson4Query(m1, ".hits.total.value")
			if nil != n1 {
				x1 := n1.(float64)
				return int(x1), nil
			}
		}
	}
	return 0, err
}

func GetUrlInfo(url string, json string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15")
		req.Header.Add("Cache-Control", "no-cache")
		if "" != json {
			req.Header.Add("Content-Type", "application/json")
		}
		// keep-alive
		req.Header.Add("Connection", "close")
		req.Close = true
		req.Body = io.NopCloser(strings.NewReader(json))

		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			defer resp.Body.Close() // resp 可能为 nil，不能读取 Body
		}
		if err != nil {
			log.Println(err)
			return ""
		}
		s1, err := ioutil.ReadAll(resp.Body)
		if nil == err {
			return string(s1)
		}
	} else {
		log.Println(err)
	}
	return ""
}

// get Doc
func (es7 *Es7Utils) GetDoc(t1 any, id string) string {
	response, err := es7.Client.Get(es7.GetIndexName(t1), id)
	if nil != err {
		log.Println(err)
		return ""
	}
	defer response.Body.Close()
	return response.String()
}
func (es7 *Es7Utils) Update(t1 any, id string) string {
	body := &bytes.Buffer{}
	err := json.NewEncoder(body).Encode(&t1)
	if nil != err {
		log.Println(err)
		return ""
	}
	response, err := es7.Client.Update(es7.GetIndexName(t1), id, body)
	if nil != err {
		log.Println(err)
	} else {
		defer response.Body.Close()
	}
	return response.String()
}

// 创建索引
func (es7 *Es7Utils) Create(t1 any, id string) string {
	body := &bytes.Buffer{}
	//pubDate := time.Now()
	err := json.NewEncoder(body).Encode(&t1)
	if nil != err {
		return ""
	}
	indexName := es7.GetIndexName(t1)
	// 覆盖性更新文档，如果给定的文档ID不存在，将创建文档: bytes.NewReader(data),
	response, err := es7.Client.Index(indexName, body, es7.Client.Index.WithDocumentID(id), es7.Client.Index.WithRefresh("true"))
	if nil == err && nil != response {
		defer response.Body.Close()
		return response.String()
	}
	return ""
}

/*
{
	"_source":{
	  "excludes": ["author"]
	},
	"query": {
	  "match_phrase": {
		"author": "古龙"
	  }
	},
	"sort": [
	  {
		"pages": {
		  "order": "desc"
		}
	  }
	],
	"from": 0,
	"size": 5
}
*/
func (es7 *Es7Utils) Search(t1 any, query string) *esapi.Response {
	body := &bytes.Buffer{}
	body.WriteString(query)
	response, err := es7.Client.Search(es7.Client.Search.WithIndex(es7.GetIndexName(t1)), es7.Client.Search.WithBody(body))
	if nil == err {
		return response
	}
	return nil
}

// "select caseid,title from xc_cases where title like '%中国电信%'",
// 这里使用mysql的方式来请求，非常简单，符合开发习惯，简化es入门门槛，支持order，支持Limit，那么排序和分页就自己写好了
func (es7 *Es7Utils) QueryBySql(t1 any, query1 string) *esapi.Response {
	query := map[string]interface{}{
		"query": query1,
	}
	jsonBody, _ := json.Marshal(query)
	req := esapi.SQLQueryRequest{Body: bytes.NewReader(jsonBody)}
	res, _ := req.Do(context.Background(), es7.Client)
	return res
	// defer res.Body.Close()
}

//func main() {
//
//}
