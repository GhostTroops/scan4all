package hydra

import (
	"fmt"
	"github.com/hktalent/scan4all/pkg/hydra/ftp"
	"github.com/hktalent/scan4all/pkg/hydra/mongodb"
	"github.com/hktalent/scan4all/pkg/hydra/mssql"
	"github.com/hktalent/scan4all/pkg/hydra/mysql"
	"github.com/hktalent/scan4all/pkg/hydra/oracle"
	"github.com/hktalent/scan4all/pkg/hydra/postgresql"
	"github.com/hktalent/scan4all/pkg/hydra/rdp"
	"github.com/hktalent/scan4all/pkg/hydra/redis"
	"github.com/hktalent/scan4all/pkg/hydra/smb"
	"github.com/hktalent/scan4all/pkg/hydra/ssh"
	"github.com/hktalent/scan4all/pkg/hydra/telnet"
	"github.com/hktalent/scan4all/pkg/kscan/core/slog"
	"github.com/hktalent/scan4all/pkg/kscan/lib/gotelnet"
	"github.com/hktalent/scan4all/pkg/kscan/lib/grdp"
)

func rdpCracker(IPAddr string, port int) func(interface{}) interface{} {
	target := fmt.Sprintf("%s:%d", IPAddr, port)
	protocol := grdp.VerifyProtocol(target)
	//slog.Println(slog.DEBUG, "rdp protocol is :", protocol)
	return func(i interface{}) interface{} {
		info := i.(AuthInfo)
		info.Auth.MakePassword()
		domain := ""
		if ok, err := rdp.Check(info.IPAddr, domain, info.Auth.Username, info.Auth.Password, info.Port, protocol); ok {
			if err != nil {
				slog.Printf(slog.DEBUG, "rdp://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
				return nil
			}
			info.Status = true
			return info
		}
		return nil
	}
}

func smbCracker(i interface{}) interface{} {
	info := i.(AuthInfo)
	info.Auth.MakePassword()
	domain := ""
	if ok, err := smb.Check(info.IPAddr, domain, info.Auth.Username, info.Auth.Password, info.Port); ok {
		if err != nil {
			slog.Printf(slog.DEBUG, "smb://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
			return nil
		}
		info.Status = true
		return info
	}
	return nil
}

func sshCracker(i interface{}) interface{} {
	info := i.(AuthInfo)
	info.Auth.MakePassword()
	if ok, err := ssh.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port); ok {
		if err != nil {
			slog.Printf(slog.DEBUG, "ssh://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
			return nil
		}
		info.Status = true
		return info
	}
	return nil
}

func telnetCracker(serverType int) func(interface{}) interface{} {
	return func(i interface{}) interface{} {
		info := i.(AuthInfo)
		info.Auth.MakePassword()
		if ok, err := telnet.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port, serverType); ok {
			if err != nil {
				slog.Printf(slog.DEBUG, "telnet://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
				return nil
			}
			info.Status = true
			return info
		}
		return nil
	}
}

func getTelnetServerType(ip string, port int) int {
	client := gotelnet.New(ip, port)
	err := client.Connect()
	if err != nil {
		return gotelnet.Closed
	}
	defer client.Close()
	return client.MakeServerType()
}

func mysqlCracker(i interface{}) interface{} {
	info := i.(AuthInfo)
	info.Auth.MakePassword()
	if ok, err := mysql.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port); ok {
		if err != nil {
			slog.Printf(slog.DEBUG, "mysql://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
			return nil
		}
		info.Status = true
		return info
	}
	return nil
}

func mssqlCracker(i interface{}) interface{} {
	info := i.(AuthInfo)
	info.Auth.MakePassword()
	if ok, err := mssql.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port); ok {
		if err != nil {
			slog.Printf(slog.DEBUG, "mssql://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
			return nil
		}
		info.Status = true
		return info
	}
	return nil
}

func redisCracker(i interface{}) interface{} {
	info := i.(AuthInfo)
	info.Auth.MakePassword()
	if ok, err := redis.Check(info.IPAddr, info.Auth.Password, info.Port); ok {
		if err != nil {
			slog.Printf(slog.DEBUG, "redis://%s:%s/auth:%s,%s", info.IPAddr, info.Port, info.Auth.Password, err)
			return nil
		}
		info.Status = true
		return info
	}
	return nil
}

func ftpCracker(i interface{}) interface{} {
	info := i.(AuthInfo)
	info.Auth.MakePassword()
	if ok, err := ftp.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port); ok {
		if err != nil {
			slog.Printf(slog.DEBUG, "ftp://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
		}
		info.Status = true
		return info
	}
	return nil
}

func postgresqlCracker(i interface{}) interface{} {
	info := i.(AuthInfo)
	info.Auth.MakePassword()
	if ok, err := postgresql.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port); ok {
		if err != nil {
			slog.Printf(slog.DEBUG, "postgres://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
			return nil
		}
		info.Status = true
		return info
	}
	return nil
}

func oracleCracker(IPAddr string, port int) func(interface{}) interface{} {
	sid := oracle.GetSID(IPAddr, port, oracle.ServiceName)
	if sid == "" {
		return nil
	}
	return func(i interface{}) interface{} {
		info := i.(AuthInfo)
		info.Auth.MakePassword()
		info.Auth.Other["SID"] = sid
		if ok, err := oracle.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port, sid); ok {
			if err != nil {
				slog.Printf(slog.DEBUG, "oracle://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
				return nil
			}
			info.Status = true
			return info
		}
		return nil
	}
}

func mongodbCracker(i interface{}) interface{} {
	info := i.(AuthInfo)
	info.Auth.MakePassword()
	if ok, err := mongodb.Check(info.IPAddr, info.Auth.Username, info.Auth.Password, info.Port); ok {
		if err != nil {
			slog.Printf(slog.DEBUG, "mongodb://%s:%s@%s:%d:%s", info.Auth.Username, info.Auth.Password, info.IPAddr, info.Port, err)
			return nil
		}
		info.Status = true
		return info
	}
	return nil
}
