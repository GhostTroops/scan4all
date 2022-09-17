package main

import (
	"bytes"
	"github.com/hktalent/scan4all/projectdiscovery/nuclei_Yaml"
	runner2 "github.com/hktalent/scan4all/projectdiscovery/nuclei_Yaml/nclruner/runner"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	nucleiType "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	_ "net/http/pprof"
	"os"
	"sync"
)

/*
1、✓ POC 不落地验证、测试：黑盒模式，最小成本，不修改nuclei代码对情况下
思路：
1）、漏洞扫描管控平台 开启PoC http get服务
安全设计：/PoCs/[为每个节点特有的，具有实效性的key]/具体的pocid.yaml
2）、设置nuclei调用参数：options.Templates 对应命令行中的 -t,格式如下
nuclei -duc -u http://192.168.10.31:8888 -t "http://127.0.0.1:8088/goSwaggerAPI.yaml,http://127.0.0.1:8088/checkGoDebug.yaml"
2、多实例测试


*/

func DoNuclei(buf *bytes.Buffer, wg *sync.WaitGroup, oOpts *map[string]interface{}) {
	defer wg.Done()
	xx := make(chan bool)
	outNuclei := make(chan *runner2.Runner, 2)
	go nuclei_Yaml.RunNuclei(buf, xx, oOpts, outNuclei)
	<-xx
}

/*
1、排除gov
2、排除蜜罐
*/
func main() {
	os.Setenv("enableNuclei", "true")

	if true {
		//go func() {
		//	//szTip = "Since you started http://127.0.0.1:6060/debug/pprof/ with -debug, close the program with: control + C"
		//	fmt.Println("debug info: \nopen http://127.0.0.1:6060/debug/pprof/\n\ngo tool pprof -seconds=10 -http=:9999 http://localhost:6060/debug/pprof/heap")
		//	http.ListenAndServe(":6060", nil)
		//}()
		h01 := []severity.Severity{severity.Critical, severity.High, severity.Medium, 2, 1, 0}
		//data1, err := json.Marshal(h01)
		//if nil == err {
		//	log.Printf("%+v", string(data1))
		//}
		buf := bytes.Buffer{}
		var wg sync.WaitGroup
		wg.Add(1)
		buf.WriteString("http://192.168.10.31:8888\n")
		pwd, _ := os.Getwd()
		m1 := map[string]interface{}{"Severities": h01, "EnableProgressBar": false, "UpdateTemplates": false, "Templates": []string{pwd + "/config/nuclei-templates"}, "TemplatesDirectory": pwd + "/config/nuclei-templates", "NoUpdateTemplates": true}
		go DoNuclei(&buf, &wg, &m1)

		buf1 := bytes.Buffer{}
		buf1.WriteString("http://pms.yx4.me\nhttps://git.yx4.me/bugscan\n")
		wg.Add(1)
		m2 := map[string]interface{}{"Severities": h01, "EnableProgressBar": false, "Protocols": []nucleiType.ProtocolType{nucleiType.HTTPProtocol}, "UpdateTemplates": false, "Templates": []string{pwd + "/config/nuclei-templates"}, "TemplatesDirectory": pwd + "/config/nuclei-templates", "NoUpdateTemplates": true}
		go DoNuclei(&buf1, &wg, &m2)

		buf2 := bytes.Buffer{}
		buf2.WriteString("http://192.168.10.240\n")
		// "Protocols": []nucleiType.ProtocolType{nucleiType.HTTPProtocol},
		m3 := map[string]interface{}{"Severities": h01, "EnableProgressBar": true, "UpdateTemplates": false, "Templates": []string{pwd + "/config/nuclei-templates/51pwn"}, "TemplatesDirectory": pwd + "/config/nuclei-templates/51pwn", "NoUpdateTemplates": true}
		wg.Add(1)
		go DoNuclei(&buf2, &wg, &m3)
		wg.Wait()
	}

}
