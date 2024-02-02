package test

import (
	"bufio"
	"fmt"
	"github.com/GhostTroops/scan4all/pkg/common"
	"github.com/GhostTroops/scan4all/pkg/tools"
	"github.com/GhostTroops/scan4all/pkg/utils"
	util "github.com/hktalent/go-utils"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var re1 = regexp.MustCompile(` +`)

func testCmd(s string, data string) {
	a := re1.Split(s, -1)
	//log.Println(strings.Join(a, "\n"))
	Cmd := exec.Command(a[0], a[1:]...)
	var err error
	var wt io.WriteCloser
	var wg sync.WaitGroup
	wg.Add(2)
	if wt, err = Cmd.StdinPipe(); nil == err {
		bufout := bufio.NewWriter(wt)
		go func() {
			defer wg.Done()
			bufout.Write([]byte(data + "\n"))
			/*
				I am not in a hurry to close wt here, there will be more uses in the future
				At this point I hope nuclei has started running and output the results
				But we found that if wt is not closed here, http will hang and will never start execution.
				In other words, it will not friendly process and execute the stream from time to time.
				When the stream becomes larger one by one, it will cause memory overflow, the same problem., tlsx does not have this problem. It can process the stream line by line in a friendly manner without waiting for the stream to be closed.
			*/
			bufout.Flush()
			//wt.Close()
		}()
	} else {
		fmt.Println(err)
	}
	if out, err1 := Cmd.StdoutPipe(); nil == err1 {
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096) // 设置适当的缓冲区大小
			for {
				n, err8 := out.Read(buf)
				if 0 < n {
					os.Stdout.Write(buf[:n])
				}
				if err8 == io.EOF {
					break
				}
				if err8 != nil {
					log.Println(err8)
					break
				}
			}
		}()
	} else {
		log.Println(err)
	}
	if err4 := Cmd.Start(); nil != err4 {
		log.Println("Cmd.Start", err4)
	}

	if err6 := Cmd.Wait(); nil != err6 {
		log.Println("Cmd.Wait", err6)
	}
	wg.Wait()
	wt.Close()
}

func TestMasscan(t *testing.T) {
	//fmt.Println(os.Getenv("PATH"))
	//if s, err := exec.LookPath("masscan"); nil == err {
	//	fmt.Println(s)
	//} else {
	//	cmd1 := exec.Command("where", "masscan")
	//	cmd1.Stdout = os.Stdout
	//	cmd1.Stderr = os.Stdout
	//	cmd1.Start()
	//	cmd1.Wait()
	//	log.Println(err)
	//}
	//testCmd("/usr/local/bin/masscan --rate=10000 -oX -p 443 -iL -", "125.64.129.171")
}

// cat $HOME/MyWork/bug-bounty/data/zq/韩国/url_200.txt|xargs -I % python ../WeblogicScan.py  -u %  -r -v --tags struts2
func TestKatana(t *testing.T) {
	testCmd("katana -nc -silent -j -hl -system-chrome -headless-options '--blink-settings=\"imagesEnabled=false\",--enable-quic=\"imagesEnabled=false\"' -jc -kf all", "https://51pwn.com")
}
func TestKsubdomain(t *testing.T) {
	testCmd(`ksubdomain e -b 100m --json -stdin`, "paypal.com")
}
func TestNuclei(t *testing.T) {
	//  -irt 30m0s
	testCmd(`nuclei -nc -silent -j -s info -no-stdin -stream`, "https://www.baidu.com")
}
func TestHttpx(t *testing.T) {
	a := re1.Split(`httpx -title -stream -websocket -method -server -location -ip  -pipeline -fr -csp-probe -http2 -p 443,80 -nc -silent -td -cname -t 64 -json`, -1)
	Cmd := exec.Command(a[0], a[1:]...)
	var err error
	var wt io.WriteCloser
	var wg sync.WaitGroup
	wg.Add(1)
	Cmd.Stdout = os.Stdout
	go func() {
		defer wg.Done()
		if wt, err = Cmd.StdinPipe(); nil == err {
			wt.Write([]byte("www.163.com\n"))
			/*
					I am not in a hurry to close wt here, there will be more uses in the future
					At this point I hope httpx has started running and output the results
					But we found that if wt is not closed here, http will hang and will never start execution.
				In other words, it will not friendly process and execute the stream from time to time.
				When the stream becomes larger one by one, it will cause memory overflow, the same problem. , tlsx does not have this problem. It can process the stream line by line in a friendly manner without waiting for the stream to be closed.
			*/
			//wt.Close()
		} else {
			fmt.Println(err)
		}
	}()
	wg.Wait()
	Cmd.Start()
	Cmd.Wait()
}
func TestDoCmdNode(t *testing.T) {
	util.InitConfigFile()
	var i = make(chan *string)
	s := "www.sina.com.cn"
	go func() {
		i <- &s
	}()
	var wg = util.NewSizedWaitGroup(0)
	common.DoCmd4Cbk("/usr/local/bin/ipgs -r", func(s *string) {
		if nil == s {
			return
		}
		var m = map[string]interface{}{}
		if err := util.Json.Unmarshal([]byte(*s), &m); nil == err {
			for _, x := range strings.Split("subject_an,subject_cn,subject_dn", ",") {
				tools.DoAorS(m[x], i, utils.TrimXx, "ipgs")
			}
		}
		log.Println(*s)
	}, i, &wg)
	wg.Wait()
}
