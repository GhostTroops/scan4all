package pkg

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/Qianlitp/crawlergo/pkg/config"
	"github.com/Qianlitp/crawlergo/pkg/logger"
	model2 "github.com/Qianlitp/crawlergo/pkg/model"
	"github.com/Qianlitp/crawlergo/pkg/tools"
	"github.com/Qianlitp/crawlergo/pkg/tools/requests"

	mapset "github.com/deckarep/golang-set"
	"github.com/panjf2000/ants/v2"
)

const pathStr = "11/123/2017/2018/message/mis/model/abstract/account/act/action" +
	"/activity/ad/address/ajax/alarm/api/app/ar/attachment/auth/authority/award/back/backup/bak/base" +
	"/bbs/bbs1/cms/bd/gallery/game/gift/gold/bg/bin/blacklist/blog/bootstrap/brand/build/cache/caches" +
	"/caching/cacti/cake/captcha/category/cdn/ch/check/city/class/classes/classic/client/cluster" +
	"/collection/comment/commit/common/commons/components/conf/config/mysite/confs/console/consumer" +
	"/content/control/controllers/core/crontab/crud/css/daily/dashboard/data/database/db/default/demo" +
	"/dev/doc/download/duty/es/eva/examples/excel/export/ext/fe/feature/file/files/finance/flashchart" +
	"/follow/forum/frame/framework/ft/group/gss/hello/helper/helpers/history/home/hr/htdocs/html/hunter" +
	"/image/img11/import/improve/inc/include/includes/index/info/install/interface/item/jobconsume/jobs" +
	"/json/kindeditor/l/languages/lib/libraries/libs/link/lite/local/log/login/logs/mail/main" +
	"/maintenance/manage/manager/manufacturer/menus/models/modules/monitor/movie/mysql/n/nav/network" +
	"/news/notice/nw/oauth/other/page/pages/passport/pay/pcheck/people/person/php/phprpc" +
	"/phptest/picture/pl/platform/pm/portal/post/product/project/protected/proxy/ps/public/qq/question" +
	"/quote/redirect/redisclient/report/resource/resources/s/save/schedule/schema/script/scripts/search" +
	"/security/server/service/shell/show/simple/site/sites/skin/sms/soap/sola/sort/spider/sql/stat" +
	"/static/statistics/stats/submit/subways/survey/sv/syslog/system/tag/task/tasks/tcpdf/template" +
	"/templates/test/tests/ticket/tmp/token/tool/tools/top/tpl/txt/upload/uploadify/uploads/url/user" +
	"/util/v1/v2/vendor/view/views/web/weixin/widgets/wm/wordpress/workspace/ws/www/www2/wwwroot/zone" +
	"/admin/admin_bak/mobile/m/js"

var pathFuzzWG sync.WaitGroup
var validateUrl mapset.Set

/**
从robots.txt文件中获取路径信息
*/
func GetPathsFromRobots(navReq model2.Request) []*model2.Request {
	logger.Logger.Info("starting to get paths from robots.txt.")
	var result []*model2.Request
	var urlFindRegex = regexp.MustCompile(`(?:Disallow|Allow):.*?(/.+)`)
	var urlRegex = regexp.MustCompile(`(/.+)`)

	navReq.URL.Path = "/"
	url := navReq.URL.NoQueryUrl() + "robots.txt"

	resp, err := requests.Get(url, tools.ConvertHeaders(navReq.Headers),
		&requests.ReqOptions{AllowRedirect: false,
			Timeout: 5,
			Proxy:   navReq.Proxy})
	if err != nil {
		//for
		//logger.Logger.Error("request to robots.txt error ", err)
		return result
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result
	}
	urlList := urlFindRegex.FindAllString(resp.Text, -1)
	for _, _url := range urlList {
		_url = strings.TrimSpace(_url)
		_url = urlRegex.FindString(_url)
		url, err := model2.GetUrl(_url, *navReq.URL)
		if err != nil {
			continue
		}
		req := model2.GetRequest(config.GET, url)
		req.Source = config.FromRobots
		result = append(result, &req)
	}
	return result
}

/**
使用常见路径列表进行fuzz
*/
func GetPathsByFuzz(navReq model2.Request) []*model2.Request {
	logger.Logger.Info("starting to get paths by fuzzing.")
	pathList := strings.Split(pathStr, "/")
	return doFuzz(navReq, pathList)
}

/**
使用字典列表进行fuzz
*/
func GetPathsByFuzzDict(navReq model2.Request, dictPath string) []*model2.Request {
	logger.Logger.Infof("starting to get dict path by fuzzing: %s", dictPath)
	pathList := tools.ReadFile(dictPath)
	logger.Logger.Debugf("valid path count: %d", len(pathList))
	return doFuzz(navReq, pathList)
}

type singleFuzz struct {
	navReq model2.Request
	path   string
}

func doFuzz(navReq model2.Request, pathList []string) []*model2.Request {
	validateUrl = mapset.NewSet()
	var result []*model2.Request
	pool, _ := ants.NewPool(20)
	defer pool.Release()
	for _, path := range pathList {
		path = strings.TrimPrefix(path, "/")
		path = strings.TrimSuffix(path, "\n")
		task := singleFuzz{
			navReq: navReq,
			path:   path,
		}
		pathFuzzWG.Add(1)
		go func() {
			err := pool.Submit(task.doRequest)
			if err != nil {
				pathFuzzWG.Done()
			}
		}()
	}

	pathFuzzWG.Wait()
	for _, _url := range validateUrl.ToSlice() {
		_url := _url.(string)
		url, err := model2.GetUrl(_url)
		if err != nil {
			continue
		}
		req := model2.GetRequest(config.GET, url)
		req.Source = config.FromFuzz
		result = append(result, &req)
	}
	return result
}

/**

 */
func (s singleFuzz) doRequest() {
	defer pathFuzzWG.Done()

	url := fmt.Sprintf(`%s://%s/%s`, s.navReq.URL.Scheme, s.navReq.URL.Host, s.path)
	resp, errs := requests.Get(url, tools.ConvertHeaders(s.navReq.Headers),
		&requests.ReqOptions{Timeout: 2, AllowRedirect: false, Proxy: s.navReq.Proxy})
	if errs != nil {
		return
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		validateUrl.Add(url)
	} else if resp.StatusCode == 301 {
		locations := resp.Header["Location"]
		if len(locations) == 0 {
			return
		}
		location := locations[0]
		redirectUrl, err := model2.GetUrl(location)
		if err != nil {
			return
		}
		if redirectUrl.Host == s.navReq.URL.Host {
			validateUrl.Add(url)
		}
	}
}
