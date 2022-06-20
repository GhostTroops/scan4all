package oracle

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func TestGetSID(t *testing.T) {
	target := []string{""}
	for _, ip := range target {
		sid := GetSID(ip, 1521, ServiceName)
		if sid != "" {
			fmt.Println(ip, "\t", sid)
		}
	}

}

func TestConnect(t *testing.T) {
	dataSourceName := fmt.Sprintf("oracle://sid:sid@%s:%d/?SID=%s", "192.168.100.11", 1521, "orcl")
	db, _ := sql.Open("oracle", dataSourceName)
	db.SetConnMaxLifetime(3 * time.Second)
	db.SetMaxIdleConns(0)
	fmt.Println(db.Ping())
}
