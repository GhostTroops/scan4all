package util

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"strings"
	"time"
)

var dbCC *gorm.DB
var DbName = "config/scan4all_db"

// 关闭数据库连接
func Close() {
	if nil != dbCC {
		if db1, err := dbCC.DB(); nil == err {
			db1.Close()
		}
	}
}

// 初始化模型
func InitModle(x ...interface{}) {
	if nil == dbCC {
		InitDb()
	}
	dbCC.AutoMigrate(x...)
}

// go - 交叉编译go-sqlite3 https://www.modb.pro/db/329524
// ./tools/Check_CVE_2020_26134 -config="/Users/51pwn/MyWork/mybugbounty/allDomains.txt"
// 获取Gorm db连接、操作对象
func InitDb(dst ...interface{}) *gorm.DB {
	if nil != dbCC {
		log.Println("dbCC not is nil, DbName = ", DbName)
		return dbCC
	}
	szDf := DbName
	if 1 < len(dst) {
		szDf = dst[1].(string)
	}
	s1 := os.Getenv("DbName")
	if "" != s1 {
		szDf = s1
	}
	s1 = szDf[0:strings.LastIndex(szDf, "/")]
	if "" != s1 {
		Mkdirs(s1)
	}
	log.Println("DbName ", szDf)
	xx01 := sqlite.Open("file:" + szDf + ".db?cache=shared&mode=rwc&_journal_mode=WAL&Synchronous=Off&temp_store=memory&mmap_size=30000000000")
	db, err := gorm.Open(xx01, &gorm.Config{PrepareStmt: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err == nil { // no error
		db1, _ := db.DB()
		if err := db1.Ping(); nil == err {
			dbCC = db
			db1.SetConnMaxLifetime(time.Minute * 60)
			db1.SetMaxIdleConns(GetValAsInt("MaxIdleConns", 100))
			db1.SetMaxOpenConns(GetValAsInt("MaxOpenConns", 200))
			if nil != dst && 0 < len(dst) {
				db.AutoMigrate(dst[0])
			}
		} else {
			log.Println("sqlite db init Connection failed", err)
		}
	} else {
		log.Println(err)
	}
	return dbCC
}

// 通用
// 获取T类型mod表名
func GetTableName[T any](mod T) string {
	stmt := &gorm.Statement{DB: dbCC}
	stmt.Parse(GetPointVal(mod))
	return stmt.Schema.Table
}

// 通用,update
// 指定id更新T类型mod数据
func Update[T any](mod *T, query string, args ...interface{}) int64 {
	var t1 *T = mod
	xxxD := dbCC.Table(GetTableName(mod)).Model(t1)
	xxxD.AutoMigrate(t1)
	rst := xxxD.Where(query, args...).Updates(mod)
	xxxD.Commit()
	if 0 >= rst.RowsAffected {
		log.Println(rst.Error)
	}
	return rst.RowsAffected
}

// 更新失败再插入新数据，确保只有一条数据
func UpInsert[T any](mod *T, query string, args ...interface{}) int64 {
	if 1 >= Update[T](mod, query, args...) {
		return Create[T](mod)
	}
	return 0
}

// 通用,insert
func Create[T any](mod *T) int64 {
	xxxD := dbCC.Table(GetTableName(*mod)).Model(mod)
	xxxD.AutoMigrate(mod)
	rst := xxxD.Create(mod)
	rst.Commit()
	if 0 >= rst.RowsAffected {
		log.Println(rst.Error)
	}
	return rst.RowsAffected
}

// 通用
// 求T类型count，支持条件
// 对T表，mod类型表，args 的where求count
func GetCount[T any](mod T, args ...interface{}) int64 {
	var n int64
	x1 := dbCC.Model(&mod)
	if 0 < len(args) {
		x1.Where(args[0], args[1:]...).Count(&n)
	} else {
		x1.Count(&n)
	}
	return n
}

// 通用
// 查询返回T类型、表一条数据
func GetOne[T any](rst *T, args ...interface{}) *T {
	if nil == rst {
		rst = new(T)
	}
	xxxD := dbCC.Table(GetTableName(rst)).Model(rst)
	xxxD.AutoMigrate(rst)
	rst1 := xxxD.First(rst, args...)
	if 0 == rst1.RowsAffected && nil != rst1.Error {
		//log.Println(rst1.Error)
		return nil
	}
	return rst
}

// 通用
// 查询模型T1类型 mode，并关联T1类型对子类型T3 preLd
// 设置 nPageSize 和便宜Offset
// 以及其他查询条件conds
func GetSubQueryLists[T1, T2 any](mode T1, preLd string, aRst []T2, nPageSize int, Offset int, conds ...interface{}) *[]T2 {
	if "" != preLd {
		dbCC.Model(&mode).Preload(preLd).Limit(nPageSize).Offset(Offset*nPageSize).Order("updated_at DESC").Find(&aRst, conds...)
	} else {
		dbCC.Model(&mode).Limit(nPageSize).Offset(Offset*nPageSize).Order("updated_at DESC").Find(&aRst, conds...)
	}
	return &aRst
}

// 通用
// 查询模型T1类型 mode，并关联T1类型对子类型T3 preLd
// 设置 nPageSize 和便宜Offset
// 以及其他查询条件conds
func GetSubQueryList[T1, T2, T3 any](mode T1, preLd T3, aRst []T2, nPageSize int, Offset int, conds ...interface{}) *[]T2 {
	return GetSubQueryLists(mode, GetTableName(preLd), aRst, nPageSize, Offset, conds...)
}
