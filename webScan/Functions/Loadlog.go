package Funcs

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	Configs "github.com/GhostTroops/scan4all/webScan/config"
	"log"
	"os"
	"time"
)

func init() {
	util.RegInitFunc(func() {
		fileValue := util.GetAsAny("Exploit")
		Configs.ConfigJsonMap.Exploit.Path = fmt.Sprintf("%v", util.GetJson4Query(fileValue, ".path"))

		//FileLog, err := os.OpenFile(Configs.ConfigJsonMap.Exploit.Logs, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		//if err != nil {
		//	fmt.Println("Can't to build " + Configs.ConfigJsonMap.Exploit.Logs)
		//	//os.Exit(1)
		//}
		Configs.ColorInfo = log.New(os.Stdout, "[INFO]", log.Ldate|log.Ltime)
		//Configs.ColorMistake = log.New(io.MultiWriter(FileLog, os.Stderr), "[ERROR]", log.Ldate|log.Ltime|log.Lshortfile)
		Configs.ColorSend = log.New(os.Stdout, "[MESSAGE-SEND]", log.Ldate|log.Ltime)
		Configs.ColorSuccess = log.New(os.Stdout, "[SUCCESS]", log.Ldate|log.Ltime)
	})
}

func Get_Time() string {
	year := time.Now().Year()
	month := time.Now().Month()
	day := time.Now().Day()
	hour := time.Now().Hour()
	minute := time.Now().Minute()
	now_time := fmt.Sprintf("%d年%d月%d日%d时%d分", year, month, day, hour, minute)
	return now_time
}
