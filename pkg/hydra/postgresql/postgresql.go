package postgresql

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"time"
)

func Check(Host, Username, Password string, Port int) (bool, error) {
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", Username, Password, Host, Port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return false, err
	}
	db.SetConnMaxLifetime(5 * time.Second)
	defer db.Close()
	err = db.Ping()
	if err != nil {
		return false, err
	}
	return true, err
}
