package main

import (
	"fmt"
	"regexp"
	"time"
)

var DeleteMe = regexp.MustCompile("rememberMe=deleteMe")

func IsChanClosed(ch chan interface{}) bool {
	if len(ch) == 0 {
		select {
		case _, ok := <-ch:
			return !ok
		}
	}
	return false
}
func CloseChan(c chan interface{}) {
	if !IsChanClosed(c) {
		close(c)
		//
	}
}

func main() {

	fmt.Printf("%+v\n\n\n\n", DeleteMe.FindAllStringIndex("lsjdfldsjfls;jflsd=jfxxxx;rememberMe=deleteMe", -1))
	fmt.Printf("%+v", DeleteMe.FindAllStringIndex("lsjdfld=sjfls;jflsd=jfxxxx;rememberMe=deleteMe;sdfdsfsf", -1))

	var CloseAll = make(chan interface{})
	go func() {
		for {
			select {
			case _, ok := <-CloseAll:
				fmt.Println("ok: ", ok)
				if !ok {
					return
				}
			}
		}
	}()
	CloseAll <- "ok"
	time.Sleep(3 * time.Second)
	close(CloseAll)
	k, ok := <-CloseAll
	fmt.Println("2ok: ", ok, " k = ", k)
	if _, ok2 := <-CloseAll; ok2 {
		close(CloseAll)
	}
	k, ok = <-CloseAll
	fmt.Println("2ok: ", ok, " k = ", k)
}
