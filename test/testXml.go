package main

import (
	"log"
	"net/url"
	"strings"
)

//var Naabubuffer bytes.Buffer = bytes.Buffer{}

func main9() {

	s := "http://www.ddd.com:990/xxp"
	if u, err := url.Parse(strings.TrimSpace(s)); err == nil {
		//s1 := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		log.Println(u.Hostname())
	}
	//fmt.Println(fmt.Sprintf("%v", 333))
	//var nucleiDone = make(chan bool)
	//Naabubuffer.Write([]byte("192.168.10.31\n"))
	//// 集成nuclei
	////log.Println("httpxrunner.Naabubuffer = ", httpxrunner.Naabubuffer.String())
	//nuclei_Yaml.RunNuclei(Naabubuffer, nucleiDone)
	//<-nucleiDone

	//x := "testnmanp/4ee58a18fc884edd74ff1ec077e8c90c6048a45b.xml"
	//b, err := ioutil.ReadFile(x)
	//if nil == err && 0 < len(b) {
	//	s := string(b)
	//	hydra.DoParseXml(s)
	//	//select {}
	//	//doc, err := xmlquery.Parse(strings.NewReader(s))
	//	//if err != nil {
	//	//	log.Println(err)
	//	//	return
	//	//}
	//	//
	//	//for _, n := range xmlquery.Find(doc, "//host") {
	//	//	x1 := n.SelectElement("address").Attr[0].Value
	//	//	ps := n.SelectElements("ports/port")
	//	//	for _, x := range ps {
	//	//		if "open" == x.SelectElement("state").Attr[0].Value {
	//	//			ip := x1
	//	//			port, _ := strconv.Atoi(GetAttr(x.Attr, "portid"))
	//	//			service := GetAttr(x.SelectElement("service").Attr, "name")
	//	//			fmt.Printf("%s\t%d\t%s\n", ip, port, service)
	//	//		}
	//	//	}
	//	//}
	//}

}
