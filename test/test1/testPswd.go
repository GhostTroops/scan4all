package main

import (
	"github.com/hktalent/ProScan4all/lib/util"
	"log"
)

// //"github.com/hktalent/ProScan4all/pkg/hydra"
// import (
//
//	"github.com/hktalent/ProScan4all/pkg/hydra"
//
// )
func main() {
	var nucleiDone1, nucleiDone2 = make(chan bool), make(chan bool)
	util.DefaultPool.Submit(func() {
		//nucleiDone1 <- true
		//close(nucleiDone1)
		close(nucleiDone2)
	})

	//log.Printf("%v %v", <-nucleiDone1, <-nucleiDone2)
	for {
		select {
		case b, ok := <-nucleiDone1:
			log.Printf("%v %v", b, ok)
			break

		}
	}

	//hydra.Start("18.163.182.231", 22, "ssh")
	//"github.com/hktalent/ProScan4all/pkg/hydra"
	//tempInput, err := ioutil.TempFile("", "stdin-input-*")
	//if err != nil {
	//	log.Println(err)
	//	return
	//}
	//log.Println(tempInput.Name())
	//defer tempInput.Close()

}
