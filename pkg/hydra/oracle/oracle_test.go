package oracle

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestGetSID(t *testing.T) {
	// 需要真实 Oracle 实例，默认跳过
	if "" == os.Getenv("ORACLE_HOST") {
		t.Skip("设置 ORACLE_HOST=<host> 后再运行")
	}
	target := []string{os.Getenv("ORACLE_HOST")}
	for _, ip := range target {
		sid := GetSID(ip, 1521, ServiceName)
		if sid != "" {
			fmt.Println(ip, "\t", sid)
		}
	}

}

func TestConnect(t *testing.T) {
	if "" == os.Getenv("ORACLE_HOST") {
		t.Skip("设置 ORACLE_HOST=<host> 后再运行")
	}
	host := os.Getenv("ORACLE_HOST")
	dataSourceName := fmt.Sprintf("oracle://sid:sid@%s:%d/?SID=%s", host, 1521, "orcl")
	db, _ := sql.Open("oracle", dataSourceName)
	db.SetConnMaxLifetime(3 * time.Second)
	db.SetMaxIdleConns(0)
	fmt.Println(db.Ping())
}
