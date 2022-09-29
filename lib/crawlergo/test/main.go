package main

import (
	"context"
	pkg "github.com/hktalent/scan4all/lib/crawlergo"
	"log"
)

func main() {
	ctx := context.Background()
	x1 := pkg.GetChromedpInstace(&ctx)
	//n1 := 15 * time.Second
	//x1.DoUrl("https://google.com", &map[string]interface{}{"cookie": "xxx"}, nil)
	if err := x1.DoUrl("https://www.baidu.com", &map[string]interface{}{}, nil); err != nil {
		log.Println(err)
	}
	defer x1.Close()
}
