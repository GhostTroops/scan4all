package main

import (
	"github.com/hktalent/scan4all/pkg/hydra"
	"io/ioutil"
)

func main() {

	x := "test/4ee58a18fc884edd74ff1ec077e8c90c6048a45b.xml"
	b, err := ioutil.ReadFile(x)
	if nil == err && 0 < len(b) {
		s := string(b)
		hydra.DoParseXml(s)
		//select {}
		//doc, err := xmlquery.Parse(strings.NewReader(s))
		//if err != nil {
		//	log.Println(err)
		//	return
		//}
		//
		//for _, n := range xmlquery.Find(doc, "//host") {
		//	x1 := n.SelectElement("address").Attr[0].Value
		//	ps := n.SelectElements("ports/port")
		//	for _, x := range ps {
		//		if "open" == x.SelectElement("state").Attr[0].Value {
		//			ip := x1
		//			port, _ := strconv.Atoi(GetAttr(x.Attr, "portid"))
		//			service := GetAttr(x.SelectElement("service").Attr, "name")
		//			fmt.Printf("%s\t%d\t%s\n", ip, port, service)
		//		}
		//	}
		//}
	}

}
