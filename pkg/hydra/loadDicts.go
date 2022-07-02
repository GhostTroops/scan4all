package hydra

import (
	_ "embed"
	"github.com/hktalent/scan4all/pkg"
	"strings"
)

//go:embed dicts/ssh_user.txt
var username string

//go:embed dicts/ssh_pswd.txt
var pswd string

//go:embed dicts/ssh_default.txt
var ssh_default string

//go:embed dicts/ftp_user.txt
var ftpusername string

//go:embed dicts/ftp_pswd.txt
var ftp_pswd string

//go:embed dicts/ftp_default.txt
var ftp_default string

//go:embed dicts/rdp_user.txt
var rdpusername string

//go:embed dicts/rdp_pswd.txt
var rdp_pswd string

//go:embed dicts/rdp_default.txt
var rdp_default string

//go:embed dicts/mongodb_user.txt
var mongodbusername string

//go:embed dicts/mongodb_pswd.txt
var mongodb_pswd string

//go:embed dicts/mongodb_default.txt
var mongodb_default string

//go:embed dicts/mssql_user.txt
var mssqlusername string

//go:embed dicts/mssql_pswd.txt
var mssql_pswd string

//go:embed dicts/mssql_default.txt
var mssql_default string

//go:embed dicts/mysql_user.txt
var mysqlusername string

//go:embed dicts/mysql_pswd.txt
var mysql_pswd string

//go:embed dicts/mysql_default.txt
var mysql_default string

//go:embed dicts/oracle_user.txt
var oracleusername string

//go:embed dicts/oracle_pswd.txt
var oracle_pswd string

//go:embed dicts/oracle_default.txt
var oracle_default string

//go:embed dicts/postgresql_user.txt
var postgresqlusername string

//go:embed dicts/postgresql_pswd.txt
var postgresql_pswd string

//go:embed dicts/postgresql_default.txt
var postgresql_default string

//go:embed dicts/redis_user.txt
var redisusername string

//go:embed dicts/redis_pswd.txt
var redis_pswd string

//go:embed dicts/redis_default.txt
var redis_default string

//go:embed dicts/smb_user.txt
var smbusername string

//go:embed dicts/smb_pswd.txt
var smb_pswd string

//go:embed dicts/smb_default.txt
var smb_default string

//go:embed dicts/telnet_user.txt
var telnetusername string

//go:embed dicts/telnet_pswd.txt
var telnet_pswd string

//go:embed dicts/telnet_default.txt
var telnet_default string

type PPDict struct {
	Username  string
	Paswd     string
	DefaultUp string
}

var md = map[string]PPDict{}

func init() {
	md["ftp"] = PPDict{
		Username:  pkg.GetVal4File("ftp_user", ftpusername),
		Paswd:     pkg.GetVal4File("ftp_pswd", ftp_pswd),
		DefaultUp: pkg.GetVal4Filedefault("ftp_default", ftp_default),
	}
	md["ssh"] = PPDict{
		Username:  pkg.GetVal4File("ssh_username", ftpusername),
		Paswd:     pkg.GetVal4File("ssh_pswd", ftp_pswd),
		DefaultUp: pkg.GetVal4Filedefault("ssh_default", ftp_default),
	}
	md["mongodb"] = PPDict{
		Username:  pkg.GetVal4File("mongodb_username", mongodbusername),
		Paswd:     pkg.GetVal4File("mongodb_pswd", mongodb_pswd),
		DefaultUp: pkg.GetVal4Filedefault("mongodb_default", mongodb_default),
	}
	md["mssql"] = PPDict{
		Username:  pkg.GetVal4File("mssql_username", mssqlusername),
		Paswd:     pkg.GetVal4File("mssql_pswd", mssql_pswd),
		DefaultUp: pkg.GetVal4Filedefault("mssql_default", mssql_default),
	}
	md["mysql"] = PPDict{
		Username:  pkg.GetVal4File("mysql_username", mysqlusername),
		Paswd:     pkg.GetVal4File("mysql_pswd", mysql_pswd),
		DefaultUp: pkg.GetVal4File("mysql_default", mysql_default),
	}
	md["oracle"] = PPDict{
		Username:  pkg.GetVal4File("oracle_username", oracleusername),
		Paswd:     pkg.GetVal4File("oracle_pswd", oracle_pswd),
		DefaultUp: pkg.GetVal4Filedefault("oracleh_default", oracle_default),
	}
	md["postgresql"] = PPDict{
		Username:  pkg.GetVal4File("postgresql_username", postgresqlusername),
		Paswd:     pkg.GetVal4File("postgresql_pswd", postgresql_pswd),
		DefaultUp: pkg.GetVal4Filedefault("postgresql_default", postgresql_default),
	}
	md["rdp"] = PPDict{
		Username:  pkg.GetVal4File("rdp_username", rdpusername),
		Paswd:     pkg.GetVal4File("rdp_pswd", rdp_pswd),
		DefaultUp: pkg.GetVal4Filedefault("rdp_default", rdp_default),
	}
	md["redis"] = PPDict{
		Username:  pkg.GetVal4File("redis_username", redisusername),
		Paswd:     pkg.GetVal4File("redis_pswd", redis_pswd),
		DefaultUp: pkg.GetVal4Filedefault("redis_default", redis_default),
	}
	md["smb"] = PPDict{
		Username:  pkg.GetVal4File("smb_username", smbusername),
		Paswd:     pkg.GetVal4File("smb_pswd", smb_pswd),
		DefaultUp: pkg.GetVal4Filedefault("smb_default", smb_default),
	}
	md["telnet"] = PPDict{
		Username:  pkg.GetVal4File("telnet_username", telnetusername),
		Paswd:     pkg.GetVal4File("telnet_pswd", telnet_pswd),
		DefaultUp: pkg.GetVal4Filedefault("telnet_default", telnet_default),
	}
}

func GetDefaultFtpList(t string) *AuthList {
	if x1, ok := md[t]; ok {
		return func(o PPDict) *AuthList {
			a := NewAuthList()
			a.Username = strings.Split(strings.TrimSpace(o.Username), "\n")
			a.Password = strings.Split(strings.TrimSpace(o.Paswd), "\n")
			a.Special = []Auth{}
			for _, x := range strings.Split(strings.TrimSpace(o.DefaultUp), "\n") {
				x2 := strings.Split(x, "\t")
				if 2 == len(x2) {
					a.Special = append(a.Special, NewSpecialAuth(x2[0], x2[1]))
				}
			}
			return a
		}(x1)
	}
	return NewAuthList()
}
