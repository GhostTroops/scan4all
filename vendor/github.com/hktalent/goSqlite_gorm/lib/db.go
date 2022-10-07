package lib

import (
	"context"
	"database/sql"
	"github.com/gin-gonic/gin"
	util "github.com/hktalent/go-utils"
	"gorm.io/gorm"
	"log"
	"net/http"
)

var DbCC *gorm.DB
var DbName = "db/mydbfile"

/*
恢复连接
mysqladmin flush-host -h 127.0.0.1 -u vuluser -pPassword123#@!
// 查询未正常结束的任务
SELECT  * FROM vuls.alipay_task_db_saves WHERE run_status=2 and updated_at < '2022-08-01 15:45:38';
修正任务:
n01 = 节点数 * 20 + 1
select * from (SELECT updated_at FROM vuls.alipay_task_db_saves WHERE run_status =2 ORDER by updated_at DESC limit 21,1) as x1  limit 21,22;
SELECT updated_at FROM vuls.alipay_task_db_saves WHERE run_status =2 ORDER by updated_at DESC limit 20,1;
UPDATE vuls.alipay_task_db_saves SET run_status=1 WHERE run_status =2 and updated_at <'2022-08-22 13:09:12.863';
UPDATE vuls.alipay_task_db_saves SET run_status=1 WHERE run_status =2 and updated_at <'2022-08-01 15:51:28.575000000';

删除任务，重来
DELETE FROM vuls.alipay_task_db_saves

// 删除所有结果，重来
DELETE FROM vuls.vul_results

查询已经完成的任务
SELECT  task_id, scan_web, run_status FROM vuls.alipay_task_db_saves WHERE run_status =3;
SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =3;
SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =2;
SELECT updated_at,task_id,run_status,id  FROM `alipay_task_db_saves` WHERE run_status=2 ORDER by updated_at LIMIT 2

所有未执行完的，重新执行一次
UPDATE vuls.alipay_task_db_saves SET run_status=1 WHERE run_status =2;

UPDATE vuls.alipay_task_db_saves SET run_status=1   WHERE scan_web like '%127.0.0.1%' and run_status =2;

重新计算效率
UPDATE vuls.alipay_task_db_saves SET created_at=NOW();
UPDATE vuls.alipay_task_db_saves SET updated_at=created_at;
UPDATE vuls.alipay_task_db_saves SET run_status=1;

修复状态重来
UPDATE vuls.alipay_task_db_saves SET created_at=NOW() where run_status=2;
UPDATE vuls.alipay_task_db_saves SET updated_at=created_at  where run_status=2;
UPDATE vuls.alipay_task_db_saves SET run_status=1  where run_status=2;


查询漏洞扫描结果
SELECT task_id, template_id, bug_level,scan_web,bug_summary,  bug_detail FROM vuls.vul_results;

查看特定id poc的结果
SELECT task_id, template_id, bug_level,scan_web,bug_summary,  bug_detail FROM vuls.vul_results WHERE template_id='S2-016';

查询特定目标的结果
SELECT bug_level,scan_web,bug_summary, bug_detail FROM vuls.vul_results WHERE scan_web like '%cq.meituan.com%';

统计可能误报的插件
SELECT template_id,count(1) as cnt FROM vul_results group by template_id ORDER BY  cnt DESC ;

计算任务的平均耗时（秒）
SELECT sum(UNIX_TIMESTAMP(updated_at) - UNIX_TIMESTAMP(created_at))/97 from alipay_task_db_saves atds WHERE run_status=3;

计算每个任务的完成时间（分钟）
SELECT  scan_web, created_at,updated_at,(UNIX_TIMESTAMP(updated_at) - UNIX_TIMESTAMP(created_at))/60 tm FROM vuls.alipay_task_db_saves WHERE run_status =3 ORDER by tm desc;

计算当前完成任务总耗时（分钟）
SELECT
((SELECT max(UNIX_TIMESTAMP(updated_at)) from alipay_task_db_saves atds WHERE run_status=3) -
(SELECT min(UNIX_TIMESTAMP(created_at)) from alipay_task_db_saves atds WHERE run_status=3) )/60 as zdtm,
(SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =3) as okTask ;

每分钟完成任务
SELECT
(SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =3)/
(((SELECT max(UNIX_TIMESTAMP(updated_at)) from alipay_task_db_saves atds WHERE run_status=3) -
(SELECT min(UNIX_TIMESTAMP(created_at)) from alipay_task_db_saves atds WHERE run_status=3) )/60)
 as okTask ;

每天完成任务
SELECT
 60/(((SELECT max(UNIX_TIMESTAMP(updated_at)) from alipay_task_db_saves atds WHERE run_status=3) -
(SELECT min(UNIX_TIMESTAMP(created_at)) from alipay_task_db_saves atds WHERE run_status=3) )/60)*
(SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =3) * 24 as okTask ;


// 最早创建时间、最后完成时间，总耗时分钟，当前完成任务数
SELECT
(SELECT max(updated_at) from vuls.alipay_task_db_saves atds WHERE run_status=3) as maxtm,
(SELECT min(created_at) from vuls.alipay_task_db_saves atds WHERE run_status=3) as mintm,
((SELECT max(UNIX_TIMESTAMP(updated_at)) from vuls.alipay_task_db_saves atds WHERE run_status=3) -
(SELECT min(UNIX_TIMESTAMP(created_at)) from vuls.alipay_task_db_saves atds WHERE run_status=3) )/60 as tm,
(SELECT count(1) FROM vuls.alipay_task_db_saves WHERE run_status =3) as okTask,
(SELECT count(1) from (SELECT template_id,count(1) cnt from vuls.vul_results  group by template_id) as xx) as plugNum,
(SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =3) as run_status3,
(SELECT  count(1) FROM vuls.alipay_task_db_saves WHERE run_status =2) as run_status2
;

命中率
SELECT template_id,count(1) cnt from vuls.vul_results  group by template_id order by cnt desc;
SELECT count(1) from (SELECT template_id,count(1) cnt from vul_results  group by template_id) plug_nums;
*/

// go - 交叉编译go-sqlite3 https://www.modb.pro/db/329524
// ./tools/Check_CVE_2020_26134 -config="/Users/51pwn/MyWork/mybugbounty/allDomains.txt"
// 获取Gorm db连接、操作对象
//func GetDb(dst ...interface{}) *gorm.DB {
//	if nil != DbCC {
//		log.Println("DbCC not is nil, DbName = ", DbName)
//		return DbCC
//	}
//	szDf := DbName
//	if 1 < len(dst) {
//		szDf = dst[1].(string)
//	}
//	s1 := os.Getenv("DbName")
//	//s1 = "db/.DbCache2"
//	if "" != s1 {
//		szDf = s1
//	}
//	log.Println("DbName ", szDf)
//	// mysql
//	var dbO gorm.Dialector
//	var dsn string
//	// https://gorm.io/docs/connecting_to_the_database.html
//	if GConfigServer.UseMysql {
//		dsn = GConfigServer.DbUrl
//		if GConfigServer.Debug {
//			dsn = GConfigServer.DebugDbUrl
//		}
//		dbO = mysql.Open(dsn)
//	} else {
//		dsn := "file:" + szDf + ".db?cache=shared&mode=rwc&_journal_mode=WAL&Synchronous=Off&temp_store=memory&mmap_size=30000000000"
//		dbO = sqlite.Open(dsn)
//	}
//
//	config1 := &gorm.Config{
//		PrepareStmt:            true,
//		SkipDefaultTransaction: false,
//	}
//	if util.GetVal("ProductMod") == gin.ReleaseMode {
//		config1.Logger = logger.Default.LogMode(logger.Silent)
//	} else {
//		config1.Logger = logger.Default.LogMode(logger.Info)
//	}
//
//	// logger.Silent
//	// PrepareStmt: true,打开预编译 提高效率
//	db, err := gorm.Open(dbO, config1)
//	if err == nil {
//		DbCC = db
//		// https://gorm.io/zh_CN/docs/connecting_to_the_database.html
//		db1, _ := DbCC.DB()
//		// Ping
//		db1.Ping()
//		//db1.SetConnMaxLifetime(time.Minute * 3)
//		db1.SetMaxIdleConns(GConfigServer.MaxOpenConns / 2)
//		db1.SetMaxOpenConns(GConfigServer.MaxOpenConns)
//		// SetMaxIdleConns 设置空闲连接池中连接的最大数量
//		//db1.SetMaxIdleConns(10)
//		// SetMaxOpenConns 设置打开数据库连接的最大数量。
//		//db1.SetMaxOpenConns(100)
//		//// SetConnMaxLifetime 设置了连接可复用的最大时间。
//		db1.SetConnMaxLifetime(time.Hour)
//		if nil != dst && 0 < len(dst) {
//			db.WithContext(context.Background()).AutoMigrate(dst[0])
//		}
//	} else {
//		log.Println(err)
//	}
//	return DbCC
//}

// 通用
// 获取T类型mod表名
func GetTableName[T any](mod T) string {
	stmt := &gorm.Statement{DB: DbCC.WithContext(context.Background())}
	stmt.Parse(&mod)
	return stmt.Schema.Table
}

// 通用,update
// 指定id更新T类型mod数据
func Update[T any](mod *T, id interface{}, idName string) int64 {
	xxxD := GetSession().Table(GetTableName(*mod)).Model(mod)
	AutoMigrate(mod)
	if "" == idName {
		idName = "id"
	}
	rst := xxxD.Where(idName+" = ?", id).Updates(mod)
	if 0 >= rst.RowsAffected && nil != rst.Error {
		log.Println(rst.Error)
	}
	defer CloseCur(rst)
	return rst.RowsAffected
}

var MD = make(map[string]bool)

func AutoMigrate[T any](mod *T) {
	s1 := GetTableName(*mod)
	if bDo, ok := MD[s1]; ok && bDo {
		return
	}
	MD[s1] = true
	DbCC.AutoMigrate(mod)
}

// go tool pprof -seconds=120 -http=:9999 http://65.49.202.211:8080/debug/pprof/heap
func CloseCur(xx1 *gorm.DB) {
	//if nil != xx1 {
	//	if r, err := xx1.Rows(); nil == err {
	//		r.Close()
	//	} else if nil != xx1.Statement {
	//		if r, err := xx1.Statement.Rows(); nil == err {
	//			r.Close()
	//		}
	//	}
	//}
}

func Update4Cust[T any](mod *T, szWhere string, args ...interface{}) int64 {
	xxxD := GetSession().Table(GetTableName(*mod)).Model(mod)
	AutoMigrate(mod)
	rst := xxxD.Where(szWhere, args...).Updates(mod)
	//rst.Commit() // 不能加，否则：invalid transaction
	nRs := rst.RowsAffected

	if 0 >= nRs && nil != rst.Error {
		log.Println("Update4Cust", rst.Error)
	}
	defer CloseCur(rst)
	return nRs
}

func DoSql(szSql string, args ...interface{}) int64 {
	xx1 := GetSession().Exec(szSql, args...)
	n1 := xx1.RowsAffected
	defer CloseCur(xx1)
	// 不能加，invalid transaction
	//xx1 = xx1.Commit()

	//nRst, err := xx1.RowsAffected()
	if nil != xx1.Error {
		log.Println("DoSql", xx1.Error)
		return n1
	}

	return n1
}

// 通用,insert
func Create[T any](mod *T) int64 {
	xxxD := DbCC.WithContext(context.Background()).Table(GetTableName(*mod)).Model(mod).Session(&gorm.Session{PrepareStmt: true})
	AutoMigrate(mod)
	rst := xxxD.Create(mod)
	if 0 >= rst.RowsAffected && nil != rst.Error {
		log.Println(rst.Error)
	}
	xxxD.Commit()
	defer CloseCur(xxxD)
	return rst.RowsAffected
}

// 通用
// 求T类型count，支持条件
// 对T表，mod类型表，args 的where求count
func GetCount[T any](mod T, args ...interface{}) int64 {
	var n int64
	x1 := DbCC.WithContext(context.Background()).Model(&mod).Session(&gorm.Session{PrepareStmt: true})
	if 0 < len(args) {
		x1.Where(args[0], args[1:]...).Count(&n)
	} else {
		x1.Count(&n)
	}
	defer CloseCur(x1)
	return n
}

// 通用
// 查询返回T类型、表一条数据
func GetOne[T any](rst *T, args ...interface{}) *T {
	xxxD := DbCC.Table(GetTableName(*rst)).Model(rst).WithContext(context.Background()).Session(&gorm.Session{PrepareStmt: true})
	//xxxD.AutoMigrate(rst)
	rst1 := xxxD.First(rst, args...)
	if 0 == rst1.RowsAffected && nil != rst1.Error {
		//log.Println("GetOne: ", rst1.Error)
		return nil
	}
	defer CloseCur(rst1)
	return rst
}

func GetSession() *gorm.DB {
	return DbCC.WithContext(context.Background()).Session(&gorm.Session{PrepareStmt: true})
}

// 通用
// https://gorm.io/docs/advanced_query.html
// 查询模型T1类型 mode，并关联T1类型对子类型T3 preLd
// 设置 nPageSize 和便宜Offset
// 以及其他查询条件conds
func GetSubQueryLists[T1, T2 any](mode T1, preLd string, aRst []T2, nPageSize int, Offset int, conds ...interface{}) []T2 {
	var x1 *gorm.DB
	var rows *sql.Rows

	if "" != preLd {
		x1 = GetSession().Model(&mode).Preload(preLd).Limit(nPageSize).Offset(Offset*nPageSize).Order("updated_at DESC").Find(&aRst, conds...)
	} else {
		x1 = GetSession().Model(&mode).Limit(nPageSize).Offset(Offset*nPageSize).Order("updated_at DESC").Find(&aRst, conds...)
	}
	//defer CloseCur(x1)
	defer func() {
		if nil != x1 {
			if nil == rows {
				rows, _ = x1.Rows()
			}
			if nil != rows {
				rows.Close()
				rows = nil
			} else if nil != x1.Statement {
				if r, err := x1.Statement.Rows(); nil == err {
					r.Close()
				}
			}
		}
	}()
	return aRst
}

// 通用
// 查询模型T1类型 mode，并关联T1类型对子类型T3 preLd
// 设置 nPageSize 和便宜Offset
// 以及其他查询条件conds
func GetSubQueryList[T1, T2, T3 any](mode T1, preLd T3, aRst []T2, nPageSize int, Offset int, conds ...interface{}) []T2 {
	return GetSubQueryLists(mode, GetTableName(preLd), aRst, nPageSize, Offset, conds...)
}

// 通用
// 通过泛型调用,支持多个模型调用
// T1 继承了T2，存在包含关系
func GetRmtsvLists[T1, T2 any](g *gin.Context, mode T1, aRst []T2, conds ...interface{}) {
	//rst := DbCC.Model(&mode).Limit(10000).Find(&aRst)
	aRst = GetSubQueryLists(mode, "", aRst, 1000, 0, conds...)
	if nil != aRst && 0 < len(aRst) {
		g.JSON(http.StatusOK, aRst)
		return
	}
	g.JSON(http.StatusBadRequest, gin.H{"msg": "not found", "code": -1})
}

/*
mysql -u vuluser -p vuls < task.sql

CREATE database vuls;
use vuls;

CREATE USER 'vuluser'@'%' IDENTIFIED BY 'XLK?*rSxQ4BX';
GRANT Alter ON vuls.* TO 'vuluser'@'%';
GRANT Create ON vuls.* TO 'vuluser'@'%';
GRANT Create view ON vuls.* TO 'vuluser'@'%';
GRANT Delete ON vuls.* TO 'vuluser'@'%';
GRANT Drop ON vuls.* TO 'vuluser'@'%';
GRANT Grant option ON vuls.* TO 'vuluser'@'%';
GRANT Index ON vuls.* TO 'vuluser'@'%';
GRANT Insert ON vuls.* TO 'vuluser'@'%';
GRANT References ON vuls.* TO 'vuluser'@'%';
GRANT Select ON vuls.* TO 'vuluser'@'%';
GRANT Show view ON vuls.* TO 'vuluser'@'%';
GRANT Trigger ON vuls.* TO 'vuluser'@'%';
GRANT Update ON vuls.* TO 'vuluser'@'%';
GRANT Alter routine ON vuls.* TO 'vuluser'@'%';
GRANT Create routine ON vuls.* TO 'vuluser'@'%';
GRANT Create temporary tables ON vuls.* TO 'vuluser'@'%';
GRANT Execute ON vuls.* TO 'vuluser'@'%';
GRANT Lock tables ON vuls.* TO 'vuluser'@'%';
GRANT Grant option ON vuls.* TO 'vuluser'@'%';

-- vuls.alipay_task_db_saves definition

CREATE TABLE `alipay_task_db_saves` (
  `scan_web` longtext,
  `data_sign` longtext,
  `task_id` longtext,
  `run_status` bigint DEFAULT NULL,
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_alipay_task_db_saves_deleted_at` (`deleted_at`)
) ENGINE=InnoDB AUTO_INCREMENT=486228 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `vul_results` (
	`id` bigint unsigned NOT NULL AUTO_INCREMENT,
	`created_at` datetime(3) DEFAULT NULL,
	`updated_at` datetime(3) DEFAULT NULL,
	`deleted_at` datetime(3) DEFAULT NULL,
	`vul_url` longtext,
	`bug_detail` longtext,
	`start_scan` longtext,
	`finish_time` longtext,
	`template_id` longtext,
	`bug_summary` longtext,
	`bug_description` longtext,
	`bug_level` longtext,
	`fix_detail` longtext,
	`risk_type` longtext,
	`bug_hazard` longtext,
	`scan_web` longtext,
	`data_sign` longtext,
	`task_id` longtext,
	PRIMARY KEY (`id`),
	KEY `idx_vul_results_deleted_at` (`deleted_at`)

) ENGINE=InnoDB AUTO_INCREMENT=224 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- vuls.mz_info_mods definition

CREATE TABLE `mz_info_mods` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  `scan_web` longtext,
  `data_sign` longtext,
  `task_id` longtext,
  `net_error` longtext,
  `fingerprint_info` longtext,
  `pocs` longtext,
  `poc_count` bigint DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_mz_info_mods_deleted_at` (`deleted_at`)
) ENGINE=InnoDB AUTO_INCREMENT=20285 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SHOW TABLES;
*/
// server端 api server时运行
func init2() {
	e := util.GetDb().Migrator().AutoMigrate(&AlipayTaskDbSave{}, &VulResults{}, &MzInfoMod{})
	if nil != e {
		log.Println(e)
	}
	// 商用时，修正状态
	//initFix()
}
