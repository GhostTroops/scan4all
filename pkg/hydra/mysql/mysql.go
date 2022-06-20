package mysql

import (
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"log"
	"time"
)

func Check(Host, Username, Password string, Port int) (bool, error) {
	_ = mysql.SetLogger(log.New(io.Discard, "", log.Ldate|log.Ltime))
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/information_schema?charset=utf8&timeout=%v", Username, Password, Host, Port, 5*time.Second)
	db, err := sql.Open("mysql", dataSourceName)
	if err != nil {
		return false, err
	}
	db.SetConnMaxLifetime(5 * time.Second)
	db.SetMaxIdleConns(0)
	defer db.Close()
	err = db.Ping()
	if err != nil {
		return false, err
	}
	return true, nil
}
