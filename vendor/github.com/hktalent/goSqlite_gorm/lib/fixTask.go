package lib

import (
	"os"
	"os/signal"
	"time"
)

func fixTaskStatus() {
	//  SELECT  now(),updated_at,(UNIX_TIMESTAMP(now()) - UNIX_TIMESTAMP(updated_at)) tm FROM vuls.alipay_task_db_saves WHERE run_status =2;
	szSql := "UPDATE alipay_task_db_saves SET run_status=3 where (UNIX_TIMESTAMP(now()) - UNIX_TIMESTAMP(updated_at)) > 2400 and run_status=2"
	DoSql(szSql)
}

func initFix() {
	if GConfigServer.UseMysql {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			tick1 := time.NewTicker(time.Second * 60)
			// 自动清除 10 小时前数据,  3 小时执行一次
			tick2 := time.NewTicker(time.Second * 60 * 60 * 3)
			defer tick1.Stop()
			for {
				select {
				case <-c:
					os.Exit(1)
					return
				case <-tick2.C:
					if GConfigServer.AutoRmOldData {
						DoSql("DELETE from vuls.vul_results where updated_at < (CURRENT_TIMESTAMP()+INTERVAL - 600 MINUTE);")
					}
					continue
				case <-tick1.C:
					fixTaskStatus()
					continue
				default:
				}
			}
		}()
	}
}
