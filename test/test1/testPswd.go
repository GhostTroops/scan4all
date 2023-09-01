package main

import "log"

//
////"github.com/hktalent/scan4all/pkg/hydra"
//import (
//	"github.com/hktalent/scan4all/pkg/hydra"
//)
//
func main() {
	var nucleiDone1, nucleiDone2 = make(chan bool), make(chan bool)
	go func() {
		//nucleiDone1 <- true
		//close(nucleiDone1)
		close(nucleiDone2)
	}()

	//log.Printf("%v %v", <-nucleiDone1, <-nucleiDone2)
	for {
		select {
		case b, ok := <-nucleiDone1:
			log.Printf("%v %v", b, ok)
			break
		default:

		}
	}

	//hydra.Start("18.163.182.231", 22, "ssh")
	//"github.com/hktalent/scan4all/pkg/hydra"
	//tempInput, err := ioutil.TempFile("", "stdin-input-*")
	//if err != nil {
	//	log.Println(err)
	//	return
	//}
	//log.Println(tempInput.Name())
	//defer tempInput.Close()

}
