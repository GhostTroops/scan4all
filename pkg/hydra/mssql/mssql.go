package mssql

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	mssql "github.com/denisenkom/go-mssqldb"
	"io"
	"log"
	"time"
)

func Check(Host, Username, Password string, Port int) (bool, error) {
	mssql.SetLogger(log.New(io.Discard, "", log.Ldate|log.Ltime))
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", Host, Username, Password, Port, 5*time.Second)
	db, err := sql.Open("mssql", dataSourceName)
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
